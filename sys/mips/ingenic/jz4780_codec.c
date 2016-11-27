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

/* Ingenic JZ4780 CODEC. */

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

#include <mips/ingenic/jz4780_common.h>
#include <mips/ingenic/jz4780_codec.h>

#define ARRAY_SIZE(x)		(sizeof(x)/sizeof(x[0]))

struct codec_softc {
	device_t		dev;
	struct resource		*res[1];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	void			*ih;
};

static struct resource_spec codec_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

struct reg_default {
	uint32_t reg;
	uint32_t val;
};
static struct reg_default jz4780_codec_reg_defaults[] = {
	//{ AICR_DAC,		0xd3 },
	//{ AICR_ADC,		0xd3 },
	{ AICR_DAC,		0x03 },
	{ AICR_ADC,		0x03 },

	{ FCR_DAC,		10 },

	{ CR_LO,		0x90 },
	{ CR_HP,		0x90 },
	{ CR_MIC1,		0xb0 },
	{ CR_MIC2,		0x30 },
	{ CR_LI1,		0x10 },
	{ CR_LI2,		0x10 },
	{ CR_DAC,		0x90 },
	{ CR_ADC,		0x90 },
	{ CR_VIC,		0x03 },
	{ IMR,			0xff },
	{ IMR2,			0xff },
	{ GCR_HPL,		0x06 },
	{ GCR_HPR,		0x06 },
	{ GCR_LIBYL,		0x06 },
	{ GCR_LIBYR,		0x06 },
};

static int codec_probe(device_t dev);
static int codec_attach(device_t dev);
static int codec_detach(device_t dev);

static int
codec_write(struct codec_softc *sc, uint32_t reg, uint32_t val)
{
	uint32_t tmp;

	tmp = (reg << RGADW_RGADDR_S);
	tmp |= (val << RGADW_RGDIN_S);
	tmp |= RGADW_RGWR;

	WRITE4(sc, CODEC_RGADW, tmp);

	while(READ4(sc, CODEC_RGADW) & RGADW_RGWR)
		;

	return (0);
}

static int
codec_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "ingenic,jz4780-codec"))
		return (ENXIO);

	device_set_desc(dev, "Ingenic JZ4780 CODEC");

	return (BUS_PROBE_DEFAULT);
}

static int
codec_attach(device_t dev)
{
	struct codec_softc *sc;
	int i;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, codec_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	printf("sizeof %d\n", ARRAY_SIZE(jz4780_codec_reg_defaults));

	if (1 == 1) {
	for (i = 0; i < 18; i++) {
		printf("write reg %x val %x\n", jz4780_codec_reg_defaults[i].reg, jz4780_codec_reg_defaults[i].val);
		codec_write(sc, jz4780_codec_reg_defaults[i].reg, jz4780_codec_reg_defaults[i].val);
	}
	}

	return (0);
}

static int
codec_detach(device_t dev)
{
	struct codec_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, codec_spec, sc->res);

	return (0);
}

static device_method_t codec_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			codec_probe),
	DEVMETHOD(device_attach,		codec_attach),
	DEVMETHOD(device_detach,		codec_detach),

	DEVMETHOD_END
};

static driver_t codec_driver = {
	"codec",
	codec_methods,
	sizeof(struct codec_softc),
};

static devclass_t codec_devclass;

DRIVER_MODULE(codec, simplebus, codec_driver, codec_devclass, 0, 0);
