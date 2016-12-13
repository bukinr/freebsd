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
#include <sys/bus_dma.h>

#include <machine/bus.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

#include <xdma_if.h>

MALLOC_DEFINE(M_XDMA, "xdma", "xDMA framework");

static struct mtx xdma_mtx;
#define	XDMA_LOCK()		mtx_lock(&xdma_mtx)
#define	XDMA_UNLOCK()		mtx_unlock(&xdma_mtx)
#define	XDMA_ASSERT_LOCKED()	mtx_assert(&xdma_mtx, MA_OWNED)

/*
 * Allocate virtual xDMA channel.
 */
xdma_channel_t *
xdma_channel_alloc(xdma_controller_t *xdma)
{
	xdma_channel_t *xchan;
	int ret;

	xchan = malloc(sizeof(xdma_channel_t), M_XDMA, M_WAITOK | M_ZERO);
	if (xchan == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for channel.\n", __func__);
		return (NULL);
	}
	xchan->xdma = xdma;

	XDMA_LOCK();

	/* Request a real channel from hardware driver. */
	ret = XDMA_CHANNEL_ALLOC(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't request real hardware channel.\n", __func__);
		XDMA_UNLOCK();
		free(xchan, M_XDMA);

		return (NULL);
	}

	TAILQ_INIT(&xchan->ie_handlers);

	TAILQ_INSERT_TAIL(&xdma->channels, xchan, xchan_next);

	XDMA_UNLOCK();

	return (xchan);
}

int
xdma_channel_free(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int err;

	xdma = xchan->xdma;

	XDMA_LOCK();

	/* Free the real DMA channel. */
	err = XDMA_CHANNEL_FREE(xdma->dma_dev, xchan);
	if (err != 0) {
		device_printf(xdma->dev,
		    "%s: Can't free real hw channel.\n", __func__);
		XDMA_UNLOCK();
		return (-1);
	}

	xdma_teardown_all_intr(xchan);

	/* Deallocate descriptors, if any. */
	xdma_desc_free(xchan);

	TAILQ_REMOVE(&xdma->channels, xchan, xchan_next);

	free(xchan, M_XDMA);

	XDMA_UNLOCK();

	return (0);
}

int
xdma_setup_intr(xdma_channel_t *xchan, int (*cb)(void *), void *arg,
    void **ihandler)
{
	struct xdma_intr_handler *ih;
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("Panic."));

	/* Sanity check. */
	if (cb == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't setup interrupt handler.\n",
		    __func__);

		return (-1);
	}

	ih = malloc(sizeof(struct xdma_intr_handler),
	    M_XDMA, M_WAITOK | M_ZERO);
	if (ih == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for interrupt handler.\n",
		    __func__);

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
	xdma_controller_t *xdma;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("Panic."));

	/* Sanity check. */
	if (ih == NULL) {
		device_printf(xdma->dev,
		    "%s: Can't teardown interrupt.\n", __func__);
		return (-1);
	}

	TAILQ_REMOVE(&xchan->ie_handlers, ih, ih_next);

	return (0);
}

static void
xdma_dmamap_cb(void *arg, bus_dma_segment_t *segs, int nseg, int err)
{
	xdma_channel_t *xchan;
	int i;

	xchan = (xdma_channel_t *)arg;

	/* TODO: handle error. */
	if (err) {
		panic("error %d\n", err);
		return;
	}

	for (i = 0; i < nseg; i++) {
		//printf("seg %d: %x (%d bytes)\n", i, segs[i].ds_addr, segs[i].ds_len);
		xchan->descs_phys[i] = segs[i].ds_addr;
	}
}

static int
xdma_desc_alloc_bus_dma(xdma_channel_t *xchan, uint32_t desc_size,
    uint32_t align)
{
	xdma_controller_t *xdma;
	bus_size_t all_desc_sz;
	xdma_config_t *conf;
	int nsegments;
	int err;

	xdma = xchan->xdma;
	conf = &xchan->conf;

	XDMA_ASSERT_LOCKED();

	nsegments = conf->block_num;
	all_desc_sz = (conf->block_num * desc_size);

	err = bus_dma_tag_create(
	    bus_get_dma_tag(xdma->dev),
	    align, desc_size,		/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    all_desc_sz, nsegments,	/* maxsize, nsegments*/
	    desc_size, 0,		/* maxsegsize, flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &xchan->dma_tag);
	if (err) {
		device_printf(xdma->dev,
		    "%s: Can't create bus_dma tag.\n", __func__);
		return (-1);
	}

	err = bus_dmamem_alloc(xchan->dma_tag, (void **)&xchan->descs,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT, &xchan->dma_map);
	if (err) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for descriptors.\n", __func__);
		return (-1);
	}

	xchan->descs_phys = malloc(nsegments * sizeof(uintptr_t), M_XDMA,
	    (M_WAITOK | M_ZERO));

	err = bus_dmamap_load(xchan->dma_tag, xchan->dma_map, xchan->descs,
	    all_desc_sz, xdma_dmamap_cb, xchan, BUS_DMA_WAITOK);
	if (err) {
		device_printf(xdma->dev,
		    "%s: Can't load DMA map.\n", __func__);
		return (-1);
	}

	return (0);
}

int
xdma_desc_alloc(xdma_channel_t *xchan, uint32_t desc_size, uint32_t align)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

	XDMA_ASSERT_LOCKED();

	xdma = xchan->xdma;
	if (xdma == NULL) {
		device_printf(xdma->dev,
		    "%s: Channel was not allocated properly.\n", __func__);
		return (-1);
	}

	if (xchan->flags & XCHAN_FLAG_DESC_ALLOCATED) {
		device_printf(xdma->dev,
		    "%s: Descriptors already allocated.\n", __func__);
		return (-1);
	}

	if ((xchan->flags & XCHAN_FLAG_CONFIGURED) == 0) {
		device_printf(xdma->dev,
		    "%s: Channel has no configuration.\n", __func__);
		return (-1);
	}

	conf = &xchan->conf;

	ret = xdma_desc_alloc_bus_dma(xchan, desc_size, align);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't allocate memory for descriptors.\n",
		    __func__);
		return (-1);
	}

	xchan->flags |= XCHAN_FLAG_DESC_ALLOCATED;

	/* We are going to write to descriptors. */
	bus_dmamap_sync(xchan->dma_tag, xchan->dma_map, BUS_DMASYNC_PREWRITE);

	return (0);
}

int
xdma_desc_free(xdma_channel_t *xchan)
{

	if (xchan->flags & XCHAN_FLAG_DESC_ALLOCATED) {
		bus_dmamap_unload(xchan->dma_tag, xchan->dma_map);
		bus_dmamem_free(xchan->dma_tag, xchan->descs, xchan->dma_map);
		free(xchan->descs_phys, M_XDMA);
		xchan->flags &= ~(XCHAN_FLAG_DESC_ALLOCATED);

		return (0);
	}

	return (-1);
}

int
xdma_prep_memcpy(xdma_channel_t *xchan, uintptr_t src_addr,
    uintptr_t dst_addr, size_t len)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

#if 0
	if (xchan->flags & XCHAN_FLAG_CONFIGURED) {
		device_printf(xdma->dev,
		    "%s: Channel is already configured.\n", __func__);
		return (-1);
	}
#endif

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("Panic."));

	conf = &xchan->conf;
	conf->direction = XDMA_MEM_TO_MEM;
	conf->src_addr = src_addr;
	conf->dst_addr = dst_addr;
	conf->block_len = len;
	conf->block_num = 1;

	xchan->flags |= XCHAN_FLAG_CONFIGURED | XCHAN_FLAG_MEMCPY;

	XDMA_LOCK();

	/* Deallocate old descriptors, if any. */
	xdma_desc_free(xchan);

	ret = XDMA_CHANNEL_PREP_MEMCPY(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't prepare memcpy transfer.\n", __func__);
		XDMA_UNLOCK();

		return (-1);
	}

	if (xchan->flags & XCHAN_FLAG_DESC_ALLOCATED) {
		/* Driver created xDMA decsriptors. */
		bus_dmamap_sync(xchan->dma_tag, xchan->dma_map,
		    BUS_DMASYNC_POSTWRITE);
	}

	XDMA_UNLOCK();

	return (0);
}

int
xdma_prep_cyclic(xdma_channel_t *xchan, enum xdma_direction dir,
    uintptr_t src_addr, uintptr_t dst_addr, int block_len,
    int block_num, int src_width, int dst_width)
{
	xdma_controller_t *xdma;
	xdma_config_t *conf;
	int ret;

	xdma = xchan->xdma;
	KASSERT(xdma != NULL, ("Panic."));

#if 0
	if (xchan->flags & XCHAN_FLAG_CONFIGURED) {
		device_printf(xdma->dev,
		    "%s: Channel is already configured.\n", __func__);
		return (-1);
	}
#endif

	conf = &xchan->conf;
	conf->direction = dir;
	conf->src_addr = src_addr;
	conf->dst_addr = dst_addr;
	conf->block_len = block_len;
	conf->block_num = block_num;
	conf->src_width = src_width;
	conf->dst_width = dst_width;

	xchan->flags |= XCHAN_FLAG_CONFIGURED | XCHAN_FLAG_CYCLIC;

	XDMA_LOCK();

	/* Deallocate old descriptors, if any. */
	xdma_desc_free(xchan);

	ret = XDMA_CHANNEL_PREP_CYCLIC(xdma->dma_dev, xchan);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't prepare cyclic transfer.\n", __func__);
		XDMA_UNLOCK();
		return (-1);
	}

	if (xchan->flags & XCHAN_FLAG_DESC_ALLOCATED) {
		/* Driver created xDMA decsriptors. */
		bus_dmamap_sync(xchan->dma_tag, xchan->dma_map,
		    BUS_DMASYNC_POSTWRITE);
	}

	XDMA_UNLOCK();

	return (0);
}

int
xdma_begin(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, XDMA_CMD_BEGIN);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't begin the channel operation.\n", __func__);
		return (-1);
	}

	return (0);
}

int
xdma_terminate(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, XDMA_CMD_TERMINATE);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't terminate the channel operation.\n", __func__);
		return (-1);
	}

	return (0);
}

int
xdma_pause(xdma_channel_t *xchan)
{
	xdma_controller_t *xdma;
	int ret;

	xdma = xchan->xdma;

	ret = XDMA_CHANNEL_CONTROL(xdma->dma_dev, xchan, XDMA_CMD_PAUSE);
	if (ret != 0) {
		device_printf(xdma->dev,
		    "%s: Can't pause the channel operation.\n", __func__);
		return (-1);
	}

	return (ret);
}

int
xdma_callback(xdma_channel_t *xchan)
{
	struct xdma_intr_handler *entry;

	TAILQ_FOREACH(entry, &xchan->ie_handlers, ih_next) {
		if (entry->cb != NULL) {
			entry->cb(entry->cb_user);
		}
	}

	return (0);
}

#ifdef FDT
/*
 * Notify the DMA driver we have machine-dependent data in FDT.
 */
static int
xdma_ofw_md_data(xdma_controller_t *xdma, phandle_t *cells, int ncells)
{
	uint32_t ret;

	ret = XDMA_OFW_MD_DATA(xdma->dma_dev, cells, ncells, (void **)&xdma->data);

	return (ret);
}

/*
 * Allocate xdma controller.
 */
xdma_controller_t *
xdma_ofw_get(device_t dev, const char *prop)
{
	phandle_t parent, *cells;
	xdma_controller_t *xdma;
	device_t dma_dev;
	phandle_t node;
	int ncells;
	int error;
	int ndmas;
	int idx;

	node = ofw_bus_get_node(dev);
	if (node <= 0) {
		device_printf(dev,
		    "%s called on not ofw based device.\n", __func__);
	}

	error = ofw_bus_parse_xref_list_get_length(node,
	    "dmas", "#dma-cells", &ndmas);
	if (error) {
		device_printf(dev,
		    "%s can't get dmas list.\n", __func__);
		return (NULL);
	}

	if (ndmas == 0) {
		device_printf(dev,
		    "%s dmas list is empty.\n", __func__);
		return (NULL);
	}

	error = ofw_bus_find_string_index(node, "dma-names", prop, &idx);
	if (error != 0) {
		device_printf(dev,
		    "%s can't find string index.\n", __func__);
		return (NULL);
	}

	error = ofw_bus_parse_xref_list_alloc(node, "dmas", "#dma-cells",
	    idx, &parent, &ncells, &cells);
	if (error != 0) {
		device_printf(dev,
		    "%s can't get dma device xref.\n", __func__);
		return (NULL);
	}

	dma_dev = OF_device_from_xref(parent);
	if (dma_dev == NULL) {
		device_printf(dev,
		    "%s can't get dma device.\n", __func__);
		return (NULL);
	}

	XDMA_LOCK();

	xdma = malloc(sizeof(struct xdma_controller), M_XDMA, M_WAITOK | M_ZERO);
	if (xdma == NULL) {
		device_printf(dev,
		    "%s can't allocate memory for xdma.\n", __func__);
		return (NULL);
	}
	xdma->dev = dev;
	xdma->dma_dev = dma_dev;

	TAILQ_INIT(&xdma->channels);

	xdma_ofw_md_data(xdma, cells, ncells);

	XDMA_UNLOCK();

	return (xdma);
}
#endif

/*
 * Free xDMA controller object.
 */
int
xdma_put(xdma_controller_t *xdma)
{

	/* Ensure no channels allocated. */
	if (!TAILQ_EMPTY(&xdma->channels)) {
		device_printf(xdma->dev, "%s: Can't free xDMA\n", __func__);
		return (-1);
	}

	free(xdma, M_XDMA);

	return (0);
}

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
