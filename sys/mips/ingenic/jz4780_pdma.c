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

/* Ingenic JZ4780 PDMA Controller. */

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

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/bus.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/xdma/xdma.h>

#include <mips/ingenic/jz4780_common.h>
#include <mips/ingenic/jz4780_pdma.h>

#include "xdma_if.h"

struct dma_device {
	device_t		dev;
};

struct pdma_softc {
	device_t		dev;
	struct resource		*res[2];
	struct dma_device	dd;
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	void			*ih;
};

struct pdma_data {
	int tx;
	int rx;
	int chan;
};

struct pdma_channel {
	struct xdma_channel	*xchan;
	struct pdma_data	data;
	int			cur_desc;
	int			used;
	int			index;
	struct xdma_channel_config *conf;
};

#define	PDMA_NCHANNELS	32
struct pdma_channel pdma_channels[PDMA_NCHANNELS];

static struct resource_spec pdma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

struct pdma_hwdesc descs[128] __aligned(32*1024);

static int pdma_probe(device_t dev);
static int pdma_attach(device_t dev);
static int pdma_detach(device_t dev);
static int chan_start(struct pdma_softc *sc, struct pdma_channel *chan);

static void
pdma_intr(void *arg)
{
	struct xdma_channel_config *conf;
	struct pdma_channel *chan;
	struct pdma_softc *sc;
	int pending;
	int i;

	sc = arg;

	pending = READ4(sc, PDMA_DIRQP);

	//printf("%s: DIRQP %x\n", __func__, pending);

	for (i = 0; i < PDMA_NCHANNELS; i++) {
		if (pending & (1 << i)) {
			chan = &pdma_channels[i];
			conf = chan->conf;
			chan->cur_desc = (chan->cur_desc + 1) % conf->hwdesc_num;
			xdma_callback(chan->xchan);

			chan_start(sc, chan);

			/* Disable channel */
			//WRITE4(sc, PDMA_DCS(i), 0);
		}
	}

	/* Ack all the channels */
	WRITE4(sc, PDMA_DIRQP, 0);
}

static int
pdma_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "ingenic,jz4780-dma"))
		return (ENXIO);

	device_set_desc(dev, "Ingenic JZ4780 PDMA Controller");

	return (BUS_PROBE_DEFAULT);
}

static int
pdma_attach(device_t dev)
{
	struct pdma_softc *sc;
	struct dma_device *dd;
	int err;
	int reg;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, pdma_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	/* Setup interrupt handler */
	err = bus_setup_intr(dev, sc->res[1], INTR_TYPE_MISC | INTR_MPSAFE,
	    NULL, pdma_intr, sc, &sc->ih);
	if (err) {
		device_printf(dev, "Unable to alloc interrupt resource.\n");
		return (ENXIO);
	}

	phandle_t xref, node;

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	/* Configure DMA device */
	dd = &sc->dd;
	dd->dev = dev;

	reg = READ4(sc, PDMA_DMAC);
	reg &= ~(DMAC_HLT | DMAC_AR);
	reg |= (DMAC_DMAE);
	reg |= (DMAC_FMSC);
	WRITE4(sc, PDMA_DMAC, reg);

	WRITE4(sc, PDMA_DMACP, 0);

	return (0);
}

static int
pdma_detach(device_t dev)
{
	struct pdma_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, pdma_spec, sc->res);

	return (0);
}

static int
pdma_channel_alloc(device_t dev, struct xdma_channel *xchan)
{
	struct pdma_channel *chan;
	struct pdma_softc *sc;
	int i;

	sc = device_get_softc(dev);

	for (i = 0; i < PDMA_NCHANNELS; i++) {
		chan = &pdma_channels[i];
		if (chan->used == 0) {
			chan->xchan = xchan;
			xchan->chan = (void *)chan;
			chan->used = 1;
			chan->index = i;

			return (0);
		}
	}

	return (-1);
}

static int
chan_start(struct pdma_softc *sc, struct pdma_channel *chan)
{
	struct pdma_hwdesc *desc;

	desc = &descs[0];

	/* 8 byte descriptor */
	WRITE4(sc, PDMA_DCS(chan->index), DCS_DES8);

	//printf("descriptor address %x phys %x\n",
	//    (uint32_t)desc, (uint32_t)vtophys(&desc[chan->cur_desc]));

	WRITE4(sc, PDMA_DDA(chan->index), vtophys(&desc[chan->cur_desc]));

	/* Set Doorbell */
	WRITE4(sc, PDMA_DDS, (1 << chan->index));

#if 0
	int i;
	for (i = 0; i < 1; i++) {
		printf("PDMA_DSA(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DSA(chan->index)));
		printf("PDMA_DTA(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DTA(chan->index)));
		printf("PDMA_DTC(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DTC(chan->index)));
		printf("PDMA_DRT(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DRT(chan->index)));
		printf("PDMA_DCS(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DCS(chan->index)));
		printf("PDMA_DCM(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DCM(chan->index)));
		printf("PDMA_DDA(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DDA(chan->index)));
		printf("PDMA_DSD(%d) 0x%x\n", chan->index, READ4(sc, PDMA_DSD(chan->index)));
	}
#endif

	/* Channel transfer enable */
	WRITE4(sc, PDMA_DCS(chan->index), (DCS_DES8 | DCS_CTE));

	mb();

	return (0);
}

static int
pdma_channel_configure(device_t dev, struct xdma_channel *xchan, struct xdma_channel_config *conf)
{
	struct pdma_channel *chan;
	struct pdma_hwdesc *desc;
	struct pdma_data *data;
	struct pdma_softc *sc;
	//int reg;
	int i;

	sc = device_get_softc(dev);

	printf("%s: desc num %d, period_len %d\n", __func__,
	    conf->hwdesc_num, conf->period_len);

	chan = (struct pdma_channel *)xchan->chan;
	chan->conf = conf;
	data = &chan->data;

	WRITE4(sc, PDMA_DCS(chan->index), 0);
	WRITE4(sc, PDMA_DTC(chan->index), 0);
	WRITE4(sc, PDMA_DRT(chan->index), 0);
	WRITE4(sc, PDMA_DSA(chan->index), 0);
	WRITE4(sc, PDMA_DTA(chan->index), 0);
	WRITE4(sc, PDMA_DSD(chan->index), 0);
	WRITE4(sc, PDMA_DCM(chan->index), 0);

	//desc = malloc(conf->hwdesc_num * sizeof(struct pdma_hwdesc), M_DEVBUF, M_WAITOK | M_ZERO);
	desc = &descs[0];

#if 0
	desc = contigmalloc(conf->hwdesc_num * sizeof(struct pdma_hwdesc),
		M_DEVBUF,
		(M_WAITOK | M_ZERO),
		0UL /* low address */,
		-1UL /* high address */,
		1024 /* alignment */,
		0UL /* boundary */);
#endif

	data->tx = 0x6;

	for (i = 0; i < conf->hwdesc_num; i++) {
		if (conf->direction == XDMA_MEM_TO_DEV) {
			desc[i].dsa = conf->src_start + (i * conf->period_len);
			desc[i].dta = conf->dst_start;
			desc[i].drt = data->tx;
			desc[i].dcm = DCM_TIE | DCM_SAI;

			/* TODO: dehardcode */
			desc[i].dtc = (conf->period_len / 16);
			desc[i].dcm |= DCM_TSZ_16 | DCM_DP_2 | DCM_SP_2;

			printf("mem to dev: %x -> %x, data->tx %d, dtc %d\n",
			    desc[i].dsa, desc[i].dta, data->tx, desc[i].dtc);

		} else if (conf->direction == XDMA_MEM_TO_MEM) {
			desc[i].dsa = conf->src_start + (i * conf->period_len);
			desc[i].dta = vtophys(conf->dst_start) + (i * conf->period_len);
			desc[i].drt = DRT_AUTO;
			desc[i].dcm = DCM_TIE | DCM_SAI | DCM_DAI;

			printf("mem to mem: %x -> %x\n", desc[i].dsa, desc[i].dta);

			/* TODO: dehardcode */
			desc[i].dtc = conf->period_len / 32;
			desc[i].dcm |= DCM_TSZ_32;
		}
		
#if 0
		if (i != (conf->hwdesc_num - 1)) {
			desc[i].dcm |= DCM_LINK;
			desc[i].dtc |= (((i + 1) * sizeof(struct pdma_hwdesc)) >> 4) << 24;
		}
#endif

		mb();
	}

	chan_start(sc, chan);

	return (0);
}

static int
pdma_data(device_t dev, phandle_t *cells, int ncells, void *ptr)
{
	struct pdma_channel *chan;
	struct pdma_data *data;

	chan = &pdma_channels[2];
	data = &chan->data;

	printf("%s: ncells is %d\n", __func__, ncells);
	if (ncells >= 1)
		printf("cells[0] %d, cells[1] %d, cells[2] %d\n",
		    cells[0], cells[1], cells[2]);

	data->rx = cells[0];
	data->rx = cells[1];
	data->chan = cells[2];

	return (0);
}

static device_method_t pdma_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			pdma_probe),
	DEVMETHOD(device_attach,		pdma_attach),
	DEVMETHOD(device_detach,		pdma_detach),

	/* xDMA Interface */
	DEVMETHOD(xdma_channel_alloc,		pdma_channel_alloc),
	DEVMETHOD(xdma_channel_configure,	pdma_channel_configure),
	DEVMETHOD(xdma_data,			pdma_data),

	DEVMETHOD_END
};

static driver_t pdma_driver = {
	"pdma",
	pdma_methods,
	sizeof(struct pdma_softc),
};

static devclass_t pdma_devclass;

EARLY_DRIVER_MODULE(pdma, simplebus, pdma_driver, pdma_devclass, 0, 0, BUS_PASS_INTERRUPT+BUS_PASS_ORDER_LAST);
