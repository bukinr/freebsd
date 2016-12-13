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

/* xDMA test driver. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <machine/bus.h>

#include <dev/xdma/xdma.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

struct xdmatest_softc {
	device_t		dev;
	xdma_controller_t	*xdma;
	xdma_channel_t		*xchan;
	void			*ih;
	struct intr_config_hook test_intrhook;
	char			*src;
	char			*dst;
	uint32_t		len;
	uintptr_t		src_phys;
	uintptr_t		dst_phys;
	bus_dma_tag_t		dma_tag;
	bus_dmamap_t		dma_map;
};

static int xdmatest_probe(device_t dev);
static int xdmatest_attach(device_t dev);
static int xdmatest_detach(device_t dev);

static int
xdmatest_intr(void *arg)
{
	struct xdmatest_softc *sc;
	int err;
	int i;

	sc = arg;

	/* We have memory updated by DMA controller. */
	bus_dmamap_sync(sc->dma_tag, sc->dma_map, BUS_DMASYNC_POSTWRITE);

	for (i = 0; i < sc->len; i++) {
		if (sc->dst[i] != sc->src[i]) {
			device_printf(sc->dev, "%s: Test failed.\n", __func__);
			return (0);
		}
	}

	err = xdma_channel_free(sc->xchan);
	if (err != 0) {
		device_printf(sc->dev,
		    "%s: Test failed: can't deallocate channel.\n", __func__);
		return (0);
	}

	err = xdma_put(sc->xdma);
	if (err != 0) {
		device_printf(sc->dev,
		    "%s: Test failed: can't deallocate xDMA.\n", __func__);
		return (0);
	}

	device_printf(sc->dev, "Test succeded.\n");

	return (0);
}

static void
xdmatest_dmamap_cb(void *arg, bus_dma_segment_t *segs, int nseg, int err)
{
	bus_addr_t *addr;

	if (err)
		return;

	addr = (bus_addr_t*)arg;
	*addr = segs[0].ds_addr;
}

static int
xdmatest_alloc_test_memory(struct xdmatest_softc *sc)
{
	int err;

	sc->len = (3 * PAGE_SIZE);

	err = bus_dma_tag_create(
	    bus_get_dma_tag(sc->dev),
	    1024, 0,			/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    sc->len, 1,			/* maxsize, nsegments*/
	    sc->len, 0,			/* maxsegsize, flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->dma_tag);
	if (err) {
		device_printf(sc->dev,
		    "%s: Can't create bus_dma tag.\n", __func__);
		return (-1);
	}

	/* Source memory. */
	err = bus_dmamem_alloc(sc->dma_tag, (void **)&sc->src,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT, &sc->dma_map);
	if (err) {
		device_printf(sc->dev,
		    "%s: Can't allocate memory.\n", __func__);
		return (-1);
	}

	err = bus_dmamap_load(sc->dma_tag, sc->dma_map, sc->src,
	    sc->len, xdmatest_dmamap_cb, &sc->src_phys, BUS_DMA_WAITOK);
	if (err) {
		device_printf(sc->dev,
		    "%s: Can't load DMA map.\n", __func__);
		return (-1);
	}

	/* Destination memory. */
	err = bus_dmamem_alloc(sc->dma_tag, (void **)&sc->dst,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT, &sc->dma_map);
	if (err) {
		device_printf(sc->dev,
		    "%s: Can't allocate memory.\n", __func__);
		return (-1);
	}

	err = bus_dmamap_load(sc->dma_tag, sc->dma_map, sc->dst,
	    sc->len, xdmatest_dmamap_cb, &sc->dst_phys, BUS_DMA_WAITOK);
	if (err) {
		device_printf(sc->dev,
		    "%s: Can't load DMA map.\n", __func__);
		return (-1);
	}

	return (0);
}

static int
xdmatest_test(struct xdmatest_softc *sc)
{
	int err;
	int i;

	/* Get xDMA controller. */
	sc->xdma = xdma_ofw_get(sc->dev, "test");
	if (sc->xdma == NULL) {
		device_printf(sc->dev, "Can't find xDMA controller.\n");
		return (-1);
	}

	/* Alloc xDMA virtual channel. */
	sc->xchan = xdma_channel_alloc(sc->xdma);
	if (sc->xchan == NULL) {
		device_printf(sc->dev, "Can't alloc virtual DMA channel.\n");
		return (-1);
	}

	/* Setup callback. */
	err = xdma_setup_intr(sc->xchan, xdmatest_intr, sc, &sc->ih);
	if (err) {
		device_printf(sc->dev, "Can't setup xDMA interrupt handler.\n");
		return (-1);
	}

	/* Allocate test memory */
	err = xdmatest_alloc_test_memory(sc);
	if (err != 0) {
		device_printf(sc->dev, "Can't allocate test memory.\n");
		return (-1);
	}

	/* We are going to fill memory. */
	bus_dmamap_sync(sc->dma_tag, sc->dma_map, BUS_DMASYNC_PREWRITE);

	/* Fill memory. */
	for (i = 0; i < sc->len; i++) {
		sc->src[i] = (i & 0xff);
		sc->dst[i] = 0;
	}

	/* Configure channel for memcpy transfer. */
	err = xdma_prep_memcpy(sc->xchan, sc->src_phys, sc->dst_phys, sc->len);
	if (err != 0) {
		device_printf(sc->dev, "Can't configure virtual channel.\n");
		return (-1);
	}

	/* Start operation. */
	xdma_begin(sc->xchan);

	return (0);
}

static void
delayed_attach(void *arg)
{
	struct xdmatest_softc *sc;

	sc = arg;

	xdmatest_test(sc);

	config_intrhook_disestablish(&sc->test_intrhook);
}

static int
xdmatest_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "freebsd,xdma-test"))
		return (ENXIO);

	device_set_desc(dev, "FreeBSD Project xDMA test driver");

	return (BUS_PROBE_DEFAULT);
}

static int
xdmatest_attach(device_t dev)
{
	struct xdmatest_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	/* We'll run test later, but before / mount. */
	sc->test_intrhook.ich_func = delayed_attach;
	sc->test_intrhook.ich_arg = sc;
	if (config_intrhook_establish(&sc->test_intrhook) != 0)
		device_printf(dev, "test_intrhook_establish failed\n");

	return (0);
}

static int
xdmatest_detach(device_t dev)
{
	struct xdmatest_softc *sc;

	sc = device_get_softc(dev);

	return (0);
}

static device_method_t xdmatest_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			xdmatest_probe),
	DEVMETHOD(device_attach,		xdmatest_attach),
	DEVMETHOD(device_detach,		xdmatest_detach),

	DEVMETHOD_END
};

static driver_t xdmatest_driver = {
	"xdmatest",
	xdmatest_methods,
	sizeof(struct xdmatest_softc),
};

static devclass_t xdmatest_devclass;

DRIVER_MODULE(xdmatest, simplebus, xdmatest_driver, xdmatest_devclass, 0, 0);
