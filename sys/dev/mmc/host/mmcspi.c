/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/resource.h>
#include <sys/rman.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/mmc/bridge.h>
#include <dev/mmc/mmcbrvar.h>
#include <dev/mmc/mmc_fdt_helpers.h>

#include <dev/clk/clk.h>
#include <dev/hwreset/hwreset.h>
#include <dev/regulator/regulator.h>

#include "opt_mmccam.h"

#include <dev/spibus/spi.h>
#include "spibus_if.h"

#include "mmc_pwrseq_if.h"

struct mmcspi_conf {
	int	dma_xferlen;
};

static const struct mmcspi_conf standard_conf = {
	.dma_xferlen = MMC_SECTOR_SIZE,
};

static struct ofw_compat_data compat_data[] = {
	{ "mmc-spi-slot",	(uintptr_t)&standard_conf },
	{ NULL,			0 }
};

struct mmcspi_softc {
	device_t		dev;
	struct mmc_request *	req;
	struct mtx		mtx;
	struct mmcspi_conf *	mmcspi_conf;
	device_t		child;
	struct mmc_host		mmcspi_host;
	int			bus_busy;
};

#define	MMCSPI_LOCK(_sc)	mtx_lock(&(_sc)->mtx)
#define	MMCSPI_UNLOCK(_sc)	mtx_unlock(&(_sc)->mtx)

static int
mmcspi_reset(struct mmcspi_softc *sc)
{

	return (0);
}

static int
mmcspi_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "MMC SPI mode controller");

	return (BUS_PROBE_DEFAULT);
}

static int
mmcspi_attach(device_t dev)
{
	struct mmcspi_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	sc->mmcspi_conf = (struct mmcspi_conf *)
	    ofw_bus_search_compatible(dev, compat_data)->ocd_data;

	sc->req = NULL;
	mtx_init(&sc->mtx, device_get_nameunit(sc->dev), "mmcspi", MTX_DEF);

	/* Soft Reset controller. */
	if (mmcspi_reset(sc) != 0) {
		device_printf(dev, "cannot reset the controller\n");
		mtx_destroy(&sc->mtx);
		return (ENXIO);
	}

	/* Set some defaults for freq and supported mode */
	sc->mmcspi_host.f_min = 400000;
	sc->mmcspi_host.f_max = 52000000;
	sc->mmcspi_host.host_ocr = MMC_OCR_320_330 | MMC_OCR_330_340;
	sc->mmcspi_host.caps |= MMC_CAP_HSPEED | MMC_CAP_SIGNALING_330;

	return (0);
}

static int
mmcspi_detach(device_t dev)
{
	struct mmcspi_softc *sc;

	sc = device_get_softc(dev);

	mtx_destroy(&sc->mtx);

	return (0);
}

static void
mmcspi_intr(void *arg)
{
	struct mmcspi_softc *sc;

	sc = (struct mmcspi_softc *)arg;
	MMCSPI_LOCK(sc);
	MMCSPI_UNLOCK(sc);
}

static int
mmcspi_request(device_t bus, device_t child, struct mmc_request *req)
{

	printf("%s\n", __func__);

	return (0);
}

static int
mmcspi_read_ivar(device_t bus, device_t child, int which, uintptr_t *result)
{
	struct mmcspi_softc *sc;

	sc = device_get_softc(bus);
	switch (which) {
	default:
		return (EINVAL);
	case MMCBR_IVAR_BUS_MODE:
		*(int *)result = sc->mmcspi_host.ios.bus_mode;
		break;
	case MMCBR_IVAR_BUS_WIDTH:
		*(int *)result = sc->mmcspi_host.ios.bus_width;
		break;
	case MMCBR_IVAR_CHIP_SELECT:
		*(int *)result = sc->mmcspi_host.ios.chip_select;
		break;
	case MMCBR_IVAR_CLOCK:
		*(int *)result = sc->mmcspi_host.ios.clock;
		break;
	case MMCBR_IVAR_F_MIN:
		*(int *)result = sc->mmcspi_host.f_min;
		break;
	case MMCBR_IVAR_F_MAX:
		*(int *)result = sc->mmcspi_host.f_max;
		break;
	case MMCBR_IVAR_HOST_OCR:
		*(int *)result = sc->mmcspi_host.host_ocr;
		break;
	case MMCBR_IVAR_MODE:
		*(int *)result = sc->mmcspi_host.mode;
		break;
	case MMCBR_IVAR_OCR:
		*(int *)result = sc->mmcspi_host.ocr;
		break;
	case MMCBR_IVAR_POWER_MODE:
		*(int *)result = sc->mmcspi_host.ios.power_mode;
		break;
	case MMCBR_IVAR_VDD:
		*(int *)result = sc->mmcspi_host.ios.vdd;
		break;
	case MMCBR_IVAR_VCCQ:
		*(int *)result = sc->mmcspi_host.ios.vccq;
		break;
	case MMCBR_IVAR_CAPS:
		*(int *)result = sc->mmcspi_host.caps;
		break;
	case MMCBR_IVAR_TIMING:
		*(int *)result = sc->mmcspi_host.ios.timing;
		break;
	case MMCBR_IVAR_MAX_DATA:
		*(int *)result = sc->mmcspi_conf->dma_xferlen / MMC_SECTOR_SIZE;
		break;
	case MMCBR_IVAR_RETUNE_REQ:
		*(int *)result = retune_req_none;
		break;
	}

	return (0);
}

static int
mmcspi_write_ivar(device_t bus, device_t child, int which, uintptr_t value)
{
	struct mmcspi_softc *sc;

	sc = device_get_softc(bus);
	switch (which) {
	default:
		return (EINVAL);
	case MMCBR_IVAR_BUS_MODE:
		sc->mmcspi_host.ios.bus_mode = value;
		break;
	case MMCBR_IVAR_BUS_WIDTH:
		sc->mmcspi_host.ios.bus_width = value;
		break;
	case MMCBR_IVAR_CHIP_SELECT:
		sc->mmcspi_host.ios.chip_select = value;
		break;
	case MMCBR_IVAR_CLOCK:
		sc->mmcspi_host.ios.clock = value;
		break;
	case MMCBR_IVAR_MODE:
		sc->mmcspi_host.mode = value;
		break;
	case MMCBR_IVAR_OCR:
		sc->mmcspi_host.ocr = value;
		break;
	case MMCBR_IVAR_POWER_MODE:
		sc->mmcspi_host.ios.power_mode = value;
		break;
	case MMCBR_IVAR_VDD:
		sc->mmcspi_host.ios.vdd = value;
		break;
	case MMCBR_IVAR_VCCQ:
		sc->mmcspi_host.ios.vccq = value;
		break;
	case MMCBR_IVAR_TIMING:
		sc->mmcspi_host.ios.timing = value;
		break;
	/* These are read-only */
	case MMCBR_IVAR_CAPS:
	case MMCBR_IVAR_HOST_OCR:
	case MMCBR_IVAR_F_MIN:
	case MMCBR_IVAR_F_MAX:
	case MMCBR_IVAR_MAX_DATA:
		return (EINVAL);
	}

	return (0);
}

static int
mmcspi_update_clock(struct mmcspi_softc *sc, uint32_t clkon)
{

	return (0);
}

static int
mmcspi_switch_vccq(device_t bus, device_t child)
{
	struct mmcspi_softc *sc;

	sc = device_get_softc(bus);

	switch (sc->mmcspi_host.ios.vccq) {
	case vccq_180:
		break;
	case vccq_330:
		break;
	default:
		return EINVAL;
	}

	return (0);
}

static int
mmcspi_update_ios(device_t bus, device_t child)
{
	struct mmcspi_softc *sc;
	struct mmc_ios *ios;

	sc = device_get_softc(bus);
	ios = &sc->mmcspi_host.ios;

	/* Set the bus width. */
	switch (ios->bus_width) {
	case bus_width_1:
		break;
	case bus_width_4:
		break;
	case bus_width_8:
		break;
	}

	switch (ios->power_mode) {
	case power_on:
		break;
	case power_off:
		//mmcspi_reset(sc);
		break;
	case power_up:
		//mmcspi_init(sc);
		break;
	};

	return (0);
}

static int
mmcspi_get_ro(device_t bus, device_t child)
{

	return (false);
}

static int
mmcspi_acquire_host(device_t bus, device_t child)
{
	struct mmcspi_softc *sc;
	int error;

	sc = device_get_softc(bus);
	MMCSPI_LOCK(sc);
	while (sc->bus_busy) {
		error = msleep(sc, &sc->mtx, PCATCH, "mmchw", 0);
		if (error != 0) {
			MMCSPI_UNLOCK(sc);
			return (error);
		}
	}
	sc->bus_busy++;
	MMCSPI_UNLOCK(sc);

	return (0);
}

static int
mmcspi_release_host(device_t bus, device_t child)
{
	struct mmcspi_softc *sc;

	sc = device_get_softc(bus);
	MMCSPI_LOCK(sc);
	sc->bus_busy--;
	wakeup(sc);
	MMCSPI_UNLOCK(sc);

	return (0);
}

static device_method_t mmcspi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		mmcspi_probe),
	DEVMETHOD(device_attach,	mmcspi_attach),
	DEVMETHOD(device_detach,	mmcspi_detach),

	/* Bus interface */
	DEVMETHOD(bus_read_ivar,	mmcspi_read_ivar),
	DEVMETHOD(bus_write_ivar,	mmcspi_write_ivar),
	DEVMETHOD(bus_add_child,        bus_generic_add_child),

	/* MMC bridge interface */
	DEVMETHOD(mmcbr_update_ios,	mmcspi_update_ios),
	DEVMETHOD(mmcbr_request,	mmcspi_request),
	DEVMETHOD(mmcbr_get_ro,		mmcspi_get_ro),
	DEVMETHOD(mmcbr_switch_vccq,	mmcspi_switch_vccq),
	DEVMETHOD(mmcbr_acquire_host,	mmcspi_acquire_host),
	DEVMETHOD(mmcbr_release_host,	mmcspi_release_host),

	DEVMETHOD_END
};

static driver_t mmcspi_driver = {
	"mmcspi",
	mmcspi_methods,
	sizeof(struct mmcspi_softc),
};

DRIVER_MODULE(mmcspi, spibus, mmcspi_driver, NULL, NULL);
MODULE_DEPEND(mmcspi, spibus, 1, 1, 1);
MMC_DECLARE_BRIDGE(mmcspi);
#ifdef FDT
SPIBUS_FDT_PNP_INFO(compat_data);
#endif
