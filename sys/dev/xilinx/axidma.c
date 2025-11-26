/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019-2025 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

/*
 * Xilinx AXI DMA controller driver.
 */

#include <sys/cdefs.h>
#include "opt_platform.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xilinx/axidma.h>

#include "axidma_if.h"

#define	AXIDMA_RD4(_sc, _reg)	\
	bus_space_read_4(_sc->bst, _sc->bsh, _reg)
#define	AXIDMA_WR4(_sc, _reg, _val)	\
	bus_space_write_4(_sc->bst, _sc->bsh, _reg, _val)
#define	AXIDMA_RD8(_sc, _reg)	\
	bus_space_read_8(_sc->bst, _sc->bsh, _reg)
#define	AXIDMA_WR8(_sc, _reg, _val)	\
	bus_space_write_8(_sc->bst, _sc->bsh, _reg, _val)

#define dprintf(fmt, ...)

#define	AXIDMA_MAX_CHANNELS	2

struct axidma_softc {
	device_t		dev;
	struct resource		*res[1 + AXIDMA_MAX_CHANNELS];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	void			*ih[AXIDMA_MAX_CHANNELS];
};

static struct resource_spec axidma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		1,	RF_ACTIVE },
	{ -1, 0 }
};

static struct ofw_compat_data compat_data[] = {
	{ "xlnx,eth-dma",	1 },
	{ NULL,			0 },
};

static int
axidma_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_search_compatible(dev, compat_data)->ocd_data)
		return (ENXIO);

	device_set_desc(dev, "Xilinx AXI DMA");

	return (BUS_PROBE_DEFAULT);
}

static int
axidma_attach(device_t dev)
{
	struct axidma_softc *sc;
	phandle_t xref, node;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, axidma_spec, sc->res)) {
		device_printf(dev, "could not allocate resources.\n");
		return (ENXIO);
	}

	/* CSR memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	return (0);
}

static int
axidma_detach(device_t dev)
{
	struct axidma_softc *sc;

	sc = device_get_softc(dev);

	bus_teardown_intr(dev, sc->res[1], sc->ih[0]);
	bus_teardown_intr(dev, sc->res[2], sc->ih[1]);
	bus_release_resources(dev, axidma_spec, sc->res);

	return (0);
}

static int
axidma_reset(device_t dev, int chan_id)
{
	struct axidma_softc *sc;
	int timeout;

	sc = device_get_softc(dev);

	AXIDMA_WR4(sc, AXI_DMACR(chan_id), DMACR_RESET);

	timeout = 100;

	do {
		if ((AXIDMA_RD4(sc, AXI_DMACR(chan_id)) & DMACR_RESET) == 0)
			break;
	} while (timeout--);

	dprintf("timeout %d\n", timeout);

	if (timeout == 0)
		return (-1);

	dprintf("%s: read control after reset: %x\n",
	    __func__, AXIDMA_RD4(sc, AXI_DMACR(chan_id)));

	return (0);
}

static int
axidma_read4(device_t dev, bus_addr_t reg)
{
	struct axidma_softc *sc;

	sc = device_get_softc(dev);

	return (AXIDMA_RD4(sc, reg));
}

static void
axidma_write4(device_t dev, bus_addr_t reg, uint32_t val)
{
	struct axidma_softc *sc;

	sc = device_get_softc(dev);

	AXIDMA_WR4(sc, reg, val);
}

static void
axidma_write8(device_t dev, bus_addr_t reg, uint64_t val)
{
	struct axidma_softc *sc;

	sc = device_get_softc(dev);

	AXIDMA_WR8(sc, reg, val);
}

static int
axidma_setup_cb(device_t dev, int chan_id, void (*cb)(void *), void *arg)
{
	struct axidma_softc *sc;
	int error;

	sc = device_get_softc(dev);

	error = bus_setup_intr(dev, sc->res[chan_id + 1],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, cb, arg,
	    &sc->ih[chan_id]);
	if (error)
		device_printf(dev, "Unable to alloc interrupt resource.\n");

	return (error);
}

static device_method_t axidma_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			axidma_probe),
	DEVMETHOD(device_attach,		axidma_attach),
	DEVMETHOD(device_detach,		axidma_detach),

	DEVMETHOD(axidma_setup_cb,		axidma_setup_cb),
	DEVMETHOD(axidma_reset,			axidma_reset),
	DEVMETHOD(axidma_read4,			axidma_read4),
	DEVMETHOD(axidma_write4,		axidma_write4),
	DEVMETHOD(axidma_write8,		axidma_write8),

	DEVMETHOD_END
};

static driver_t axidma_driver = {
	"axidma",
	axidma_methods,
	sizeof(struct axidma_softc),
};

EARLY_DRIVER_MODULE(axidma, simplebus, axidma_driver, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
