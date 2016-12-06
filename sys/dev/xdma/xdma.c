/*-
 * Copyright (c) 2016 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/kobj.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/sx.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

#include <xdma_if.h>

MALLOC_DEFINE(M_XDMA, "xdma", "xDMA framework");

static struct mtx xdma_mtx;
#define	XDMA_LOCK()	mtx_lock(&xdma_mtx)
#define	XDMA_UNLOCK()	mtx_unlock(&xdma_mtx)

/*
 * Allocate virtual xDMA channel.
 */
xdma_channel_t *
xdma_channel_alloc(xdma_controller_t xdma)
{
	xdma_channel_t *xchan;
	int ret;

	xchan = malloc(sizeof(xdma_channel_t), M_XDMA, M_WAITOK | M_ZERO);
	if (xchan == NULL) {
		printf("Cant alloc channel\n");
		return (NULL);
	}
	xchan->xdma = xdma;

	XDMA_LOCK();

	/* Request a real channel from hardware driver. */
	ret = XDMA_CHANNEL_ALLOC(xdma->dev, xchan);
	if (ret != 0) {
		XDMA_UNLOCK();
		free(xchan, M_XDMA);
		return (NULL);
	}

	TAILQ_INIT(&xchan->ie_handlers);

	XDMA_UNLOCK();

	return (xchan);
}

int
xdma_channel_free(xdma_channel_t *xchan)
{
	xdma_controller_t xdma;
	int ret;

	xdma = xchan->xdma;

	XDMA_LOCK();

	xdma_teardown_all_intr(xchan);

	ret = XDMA_CHANNEL_FREE(xdma->dev, xchan);
	if (ret != 0) {
		XDMA_UNLOCK();
		return (-1);
	}

	contigfree(xchan->descs, xchan->descs_size, M_XDMA);
	free(xchan, M_XDMA);

	XDMA_UNLOCK();

	return (ret);
}

int
xdma_setup_intr(xdma_channel_t *xchan, int (*cb)(void *), void *arg,
    void **ihandler)
{
	struct xdma_intr_handler *ih;
	xdma_controller_t xdma;

	xdma = xchan->xdma;

	ih = malloc(sizeof(struct xdma_intr_handler), M_XDMA, M_WAITOK | M_ZERO);
	if (ih == NULL) {
		return (-1);
	}

	ih->cb = cb;
	ih->cb_user = arg;

	TAILQ_INSERT_TAIL(&xchan->ie_handlers, ih, ih_next);

	*ihandler = ih;

	return (0);
}

int
xdma_teardown_all_intr(xdma_channel_t *xchan)
{
	struct xdma_intr_handler *ih;

	TAILQ_FOREACH(ih, &xchan->ie_handlers, ih_next) {
		TAILQ_REMOVE(&xchan->ie_handlers, ih, ih_next);
	}

	return (0);
}

int
xdma_teardown_intr(xdma_channel_t *xchan, struct xdma_intr_handler *ih)
{

	/* Sanity check. */
	if (ih == NULL) {
		return (-1);
	}

	TAILQ_REMOVE(&xchan->ie_handlers, ih, ih_next);

	return (0);
}

static void *
xdma_desc_alloc_contig(uint32_t sz, uint32_t align)
{
	void *ret;

	ret = contigmalloc(sz,
		M_DEVBUF,
		(M_WAITOK | M_ZERO),
		0UL,	/* low address */
		-1UL,	/* high address */
		align,	/* alignment */
		0UL);	/* boundary */

	return (ret);
}

int
xdma_desc_alloc(xdma_channel_t *xchan, uint32_t alloc_type,
    uint32_t desc_sz, uint32_t align)
{
	xdma_controller_t xdma;
	xdma_config_t *conf;
	void *ret;

	xdma = xchan->xdma;
	if (xdma == NULL) {
		return (-1);
	}

	if ((xchan->flags & XCHAN_FLAG_CONFIGURED) == 0) {
		return (-1);
	}

	conf = &xchan->conf;

	xchan->descs_size = (conf->block_num * desc_sz);

	if (alloc_type == XDMA_ALLOC_CONTIG) {
		ret = xdma_desc_alloc_contig(xchan->descs_size, align);
	} else {
		/* Don't know how to allocate descriptors */
		return (-1);
	}

	if (ret == NULL) {
		printf("Can't allocate memory for descriptors");
		return (-1);
	}

	xchan->descs = ret;
	xchan->descs_phys = vtophys(ret);

	return (0);
}

int
xdma_prep_cyclic(xdma_channel_t *xchan, enum xdma_direction dir,
    uintptr_t src_addr, uintptr_t dst_addr, int block_len,
    int block_num, int src_width, int dst_width)
{
	xdma_controller_t xdma;
	xdma_config_t *conf;
	int ret;

	xdma = xchan->xdma;

	conf = &xchan->conf;
	conf->direction = dir;
	conf->src_addr = src_addr;
	conf->dst_addr = dst_addr;
	conf->block_len = block_len;
	conf->block_num = block_num;
	conf->src_width = src_width;
	conf->dst_width = dst_width;

	xchan->flags |= XCHAN_FLAG_CONFIGURED;

	XDMA_LOCK();

	ret = XDMA_CHANNEL_CONFIGURE(xdma->dev, xchan);
	if (ret != 0) {
		XDMA_UNLOCK();
		return (-1);
	}

	XDMA_UNLOCK();

	return (0);
}

int
xdma_begin(xdma_channel_t *xchan)
{
	xdma_controller_t xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dev, xchan, XDMA_CMD_BEGIN);

	return (ret);
}

int
xdma_terminate(xdma_channel_t *xchan)
{
	xdma_controller_t xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dev, xchan, XDMA_CMD_TERMINATE);

	return (ret);
}

int
xdma_pause(xdma_channel_t *xchan)
{
	xdma_controller_t xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dev, xchan, XDMA_CMD_PAUSE);

	return (ret);
}

int
xdma_callback(xdma_channel_t *xchan)
{
	struct xdma_intr_handler *entry;

	//printf("%s: xchan %x\n", __func__, (uint32_t)xchan);
	//if (xchan->cb != NULL) {
	//	xchan->cb(xchan->cb_user);
	//}

	TAILQ_FOREACH(entry, &xchan->ie_handlers, ih_next) {
		entry->cb(entry->cb_user);
	}

	return (0);
}

static int
xdma_md_data(xdma_controller_t xdma, phandle_t *cells, int ncells)
{
	uint32_t ret;

	ret = XDMA_MD_DATA(xdma->dev, cells, ncells, &xdma->data);

	return (ret);
}

#ifdef FDT
xdma_controller_t
xdma_fdt_get(device_t dev, const char *prop)
{
	phandle_t parent, *cells;
	xdma_controller_t xdma;
	phandle_t node;
	int ncells;
	int error;
	int ndmas;
	int idx;

	node = ofw_bus_get_node(dev);

	error = ofw_bus_parse_xref_list_get_length(node, "dmas", "#dma-cells", &ndmas);
	if (error) {
		printf("Failed\n");
		return (NULL);
	}

	printf("ndmas %d\n", ndmas);
	if (ndmas == 0) {
		printf("Failed\n");
		return (NULL);
	}

	error = ofw_bus_find_string_index(node, "dma-names", prop, &idx);
	if (error != 0) {
		printf("Failed\n");
		return (NULL);
	}

	printf("dma idx %d\n", idx);
	printf("get dmas \n");

	error = ofw_bus_parse_xref_list_alloc(node, "dmas", "#dma-cells", idx,
	    &parent, &ncells, &cells);
	if (error != 0) {
		printf("Cant get dma\n");
		return (NULL);
	}

	printf("get dev \n");
	dev = OF_device_from_xref(parent);
	if (dev == NULL) {
		printf("failed to get dma dev\n");
		return (NULL);
	}

	xdma = malloc(sizeof(xdma_controller_t), M_XDMA, M_WAITOK | M_ZERO);
	xdma->dev = dev;

	xdma_md_data(xdma, cells, ncells);

	return (xdma);
}
#endif

#if 0
static void
xdma_init(void)
{

	printf("%s\n", __func__);

	mtx_init(&xdma_mtx, "xDMA", NULL, MTX_DEF);
}

SYSINIT(xdma, SI_SUB_DRIVERS, SI_ORDER_FIRST, xdma_init, NULL);
#endif

MTX_SYSINIT(xdma_lock, &xdma_mtx, "xDMA", MTX_DEF);
