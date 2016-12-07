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

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

struct xdmatest_softc {
	device_t		dev;
};

static int xdmatest_probe(device_t dev);
static int xdmatest_attach(device_t dev);
static int xdmatest_detach(device_t dev);

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
