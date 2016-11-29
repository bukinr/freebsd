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

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

#include <xdma_if.h>

MALLOC_DEFINE(M_XDMA, "xdma", "xDMA framework");

#define	XDMA_NCHANNELS	32
struct xdma_channel xdma_channels[XDMA_NCHANNELS];

struct xdma_channel *
xdma_channel_alloc(xdma_device_t xdma_dev)
{
	struct xdma_channel *xchan;
	int ret;
	int i;

	for (i = 0; i < XDMA_NCHANNELS; i++) {
		xchan = &xdma_channels[i];
		if (xchan->used == 0) {
			ret = XDMA_CHANNEL_ALLOC(xdma_dev->dma_dev, xchan);
			if (ret == 0) {
				xchan->xdev = xdma_dev;
				xchan->used = 1;
				return (xchan);
			}
		}
	}

	return (NULL);
}

int
xdma_prepare(struct xdma_channel *xchan, struct xdma_channel_config *conf)
{
	xdma_device_t xdev;
	int ret;

	xdev = xchan->xdev;

	ret = XDMA_CHANNEL_CONFIGURE(xdev->dma_dev, conf);
	if (ret == 0) {

		return (0);
	}

	return (-1);
}

int
xdma_callback(struct xdma_channel *xchan)
{

	printf("%s\n", __func__);

	return (0);
}

int
xdma_test(device_t dev)
{
	phandle_t node;
	int error;
	int ndmas;
	int idx;

	node = ofw_bus_get_node(dev);
	error = ofw_bus_parse_xref_list_get_length(node, "dmas", "#dma-cells", &ndmas);
	printf("ndmas %d\n", ndmas);

	error = ofw_bus_find_string_index(node, "dma-names", "tx", &idx);
	printf("tx dma idx %d\n", idx);

	error = ofw_bus_find_string_index(node, "dma-names", "rx", &idx);
	printf("rx dma idx %d\n", idx);

	phandle_t parent, *cells;
	device_t dma_dev;
	int ncells;

	printf("get dmas \n");

	error = ofw_bus_parse_xref_list_alloc(node, "dmas", "#dma-cells", idx,
	    &parent, &ncells, &cells);
	if (error != 0) {
		printf("Cant get dma\n");
		return (-1);
	}

	printf("get dev \n");
	dma_dev = OF_device_from_xref(parent);
	if (dma_dev == NULL) {
		printf("failed to get dma dev\n");
		return (-1);
	}

	struct xdma_channel_config conf;
	printf("call xdma_chan_conf\n");

	XDMA_CHANNEL_CONFIGURE(dma_dev, &conf);

	return (0);
}

static int
xdma_fill_data(xdma_device_t xdma_dev, phandle_t *cells, int ncells)
{
	uint32_t ret;

	ret = XDMA_DATA(xdma_dev->dma_dev, cells, ncells, &xdma_dev->data);

	return (ret);
}

xdma_device_t
xdma_get(device_t dev, const char *prop)
{
	phandle_t parent, *cells;
	device_t dma_dev;
	xdma_device_t xdma_dev;
	phandle_t node;
	int ncells;
	int error;
	int ndmas;
	int idx;

	xdma_dev = malloc(sizeof(xdma_device_t), M_XDMA, M_WAITOK | M_ZERO);

	node = ofw_bus_get_node(dev);
	error = ofw_bus_parse_xref_list_get_length(node, "dmas", "#dma-cells", &ndmas);
	if (error) {
		printf("failed\n");
		return (NULL);
	}
	printf("ndmas %d\n", ndmas);
	if (ndmas == 0) {
		printf("failed\n");
		return (NULL);
	}

	error = ofw_bus_find_string_index(node, "dma-names", prop, &idx);
	if (error != 0) {
		printf("failed\n");
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
	dma_dev = OF_device_from_xref(parent);
	if (dma_dev == NULL) {
		printf("failed to get dma dev\n");
		return (NULL);
	}

	xdma_dev->dma_dev = dma_dev;

	xdma_fill_data(xdma_dev, cells, ncells);

	return (xdma_dev);
}

int
xdma_control(xdma_device_t xdma_dev, int command)
{

	switch(command) {
	case XDMA_CMD_START:
		break;
	default:
		break;
	}

	return (0);
}
