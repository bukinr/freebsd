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

/* Ingenic JZ4780 Audio Interface Controller (AIC). */

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

#include <dev/sound/pcm/sound.h>
#include <dev/sound/chip.h>
#include <mixer_if.h>

#include <dev/xdma/xdma.h>

#include <mips/ingenic/jz4780_common.h>
#include <mips/ingenic/jz4780_aic.h>

#define	AIC_NCHANNELS		1

struct aic_softc {
	device_t		dev;
	struct resource		*res[1];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	struct mtx		*lock;
	int			pos;
	bus_dma_tag_t		dma_tag;
	bus_dmamap_t		dma_map;
	bus_addr_t		buf_base_phys;
	uint32_t		*buf_base;
	uintptr_t		aic_paddr;
	int			dma_size;
	struct aic_rate		*sr;
	struct xdma_channel_config conf;
};

/* Channel registers */
struct sc_chinfo {
	struct snd_dbuf		*buffer;
	struct pcm_channel	*channel;
	struct sc_pcminfo	*parent;

	/* Channel information */
	uint32_t	dir;
	uint32_t	format;

	/* Flags */
	uint32_t	run;
};

/* PCM device private data */
struct sc_pcminfo {
	device_t		dev;
	uint32_t		(*ih)(struct sc_pcminfo *scp);
	uint32_t		chnum;
	struct sc_chinfo	chan[AIC_NCHANNELS];
	struct aic_softc	*sc;
};

static struct resource_spec aic_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int aic_probe(device_t dev);
static int aic_attach(device_t dev);
static int aic_detach(device_t dev);
static int setup_dma(struct sc_pcminfo *scp);

struct aic_rate {
        uint32_t speed;
        uint32_t mfi; /* PLL4 Multiplication Factor Integer */
        uint32_t mfn; /* PLL4 Multiplication Factor Numerator */
        uint32_t mfd; /* PLL4 Multiplication Factor Denominator */
        /* More dividers to configure can be added here */
};

static struct aic_rate rate_map[] = {
	{ 192000, 49, 152, 1000 }, /* PLL4 49.152 Mhz */
	/* TODO: add more frequences */
	{ 0, 0 },
};

/*
 * Mixer interface.
 */
static int
aicmixer_init(struct snd_mixer *m)
{
	struct sc_pcminfo *scp;
	struct aic_softc *sc;
	int mask;

	printf("%s\n", __func__);

	scp = mix_getdevinfo(m);
	sc = scp->sc;

	if (sc == NULL)
		return -1;

	mask = SOUND_MASK_PCM;
	mask |= SOUND_MASK_VOLUME;

	snd_mtxlock(sc->lock);
	pcm_setflags(scp->dev, pcm_getflags(scp->dev) | SD_F_SOFTPCMVOL);
	mix_setdevs(m, mask);
	snd_mtxunlock(sc->lock);

	return (0);
}

static int
aicmixer_set(struct snd_mixer *m, unsigned dev,
    unsigned left, unsigned right)
{
	struct sc_pcminfo *scp;

	scp = mix_getdevinfo(m);

	/* Here we can configure hardware volume on our DAC */
#if 1
	device_printf(scp->dev, "aicmixer_set() %d %d\n",
	    left, right);
#endif

	return (0);
}

static kobj_method_t aicmixer_methods[] = {
	KOBJMETHOD(mixer_init,      aicmixer_init),
	KOBJMETHOD(mixer_set,       aicmixer_set),
	KOBJMETHOD_END
};
MIXER_DECLARE(aicmixer);

/*
 * Channel interface.
 */
static void *
aicchan_init(kobj_t obj, void *devinfo, struct snd_dbuf *b,
    struct pcm_channel *c, int dir)
{
	struct sc_pcminfo *scp;
	struct sc_chinfo *ch;
	struct aic_softc *sc;

	printf("%s\n", __func__);

	scp = (struct sc_pcminfo *)devinfo;
	sc = scp->sc;

	snd_mtxlock(sc->lock);
	ch = &scp->chan[0];
	ch->dir = dir;
	ch->run = 0;
	ch->buffer = b;
	ch->channel = c;
	ch->parent = scp;
	snd_mtxunlock(sc->lock);

	if (sndbuf_setup(ch->buffer, sc->buf_base, sc->dma_size) != 0) {
		device_printf(scp->dev, "Can't setup sndbuf.\n");
		return NULL;
	}

	return (ch);
}

static int
aicchan_free(kobj_t obj, void *data)
{
	struct sc_chinfo *ch = data;
	struct sc_pcminfo *scp = ch->parent;
	struct aic_softc *sc = scp->sc;

#if 1
	device_printf(scp->dev, "aicchan_free()\n");
#endif

	snd_mtxlock(sc->lock);
	/* TODO: free channel buffer */
	snd_mtxunlock(sc->lock);

	return (0);
}

static int
aicchan_setformat(kobj_t obj, void *data, uint32_t format)
{
	struct sc_pcminfo *scp;
	struct sc_chinfo *ch;

	ch = data;
	scp = ch->parent;

	device_printf(scp->dev, "%s\n", __func__);

	ch->format = format;

	return (0);
}

static uint32_t
aicchan_setspeed(kobj_t obj, void *data, uint32_t speed)
{
	struct sc_pcminfo *scp;
	struct sc_chinfo *ch;
	struct aic_rate *sr;
	struct aic_softc *sc;
	int threshold;
	int i;

	ch = data;
	scp = ch->parent;
	sc = scp->sc;

	device_printf(scp->dev, "%s\n", __func__);

	sr = NULL;

	/* First look for equal frequency. */
	for (i = 0; rate_map[i].speed != 0; i++) {
		if (rate_map[i].speed == speed)
			sr = &rate_map[i];
	}

	/* If no match, just find nearest. */
	if (sr == NULL) {
		for (i = 0; rate_map[i].speed != 0; i++) {
			sr = &rate_map[i];
			threshold = sr->speed + ((rate_map[i + 1].speed != 0) ?
			    ((rate_map[i + 1].speed - sr->speed) >> 1) : 0);
			if (speed < threshold)
				break;
		}
	}

	sc->sr = sr;

#if 0
	aic_configure_clock(sc);
#endif

	return (sr->speed);
}

#if 0
static void
aic_configure_clock(struct aic_softc *sc)
{
	struct aic_rate *sr;

	sr = sc->sr;

	pll4_configure_output(sr->mfi, sr->mfn, sr->mfd);

	/* Configure other dividers here, if any */
}
#endif

static uint32_t
aicchan_setblocksize(kobj_t obj, void *data, uint32_t blocksize)
{
	struct sc_pcminfo *scp;
	struct sc_chinfo *ch;
	struct aic_softc *sc;

	ch = data;
	scp = ch->parent;
	sc = scp->sc;

	device_printf(scp->dev, "%s\n", __func__);

	sndbuf_resize(ch->buffer, sc->dma_size / blocksize, blocksize);

	setup_dma(scp);

	return (sndbuf_getblksz(ch->buffer));
}

#if 0
uint32_t
aic_dma_intr(void *arg, int chn)
{
	struct sc_pcminfo *scp;
	struct sdma_conf *conf;
	struct sc_chinfo *ch;
	struct aic_softc *sc;
	int bufsize;

	scp = arg;
	ch = &scp->chan[0];
	sc = scp->sc;
	conf = &sc->conf;

	bufsize = sndbuf_getsize(ch->buffer);

	sc->pos += conf->period;
	if (sc->pos >= bufsize)
		sc->pos -= bufsize;

	if (ch->run)
		chn_intr(ch->channel);

	return (0);
}

static int
find_sdma_controller(struct aic_softc *sc)
{
	struct sdma_softc *sdma_sc;
	phandle_t node, sdma_node;
	device_t sdma_dev;
	int dts_value[8];
	int len;

	if ((node = ofw_bus_get_node(sc->dev)) == -1)
		return (ENXIO);

	if ((len = OF_getproplen(node, "dmas")) <= 0)
		return (ENXIO);

	OF_getencprop(node, "dmas", &dts_value, len);

	sc->sdma_ev_rx = dts_value[1];
	sc->sdma_ev_tx = dts_value[5];

	sdma_node = OF_node_from_xref(dts_value[0]);

	sdma_sc = NULL;

	sdma_dev = devclass_get_device(devclass_find("sdma"), 0);
	if (sdma_dev)
		sdma_sc = device_get_softc(sdma_dev);

	if (sdma_sc == NULL) {
		device_printf(sc->dev, "No sDMA found. Can't operate\n");
		return (ENXIO);
	}

	sc->sdma_sc = sdma_sc;

	return (0);
};
#endif

static int
setup_dma(struct sc_pcminfo *scp)
{
	struct xdma_channel_config *conf;
	struct aic_softc *sc;
	struct sc_chinfo *ch;
	device_t dma_dev_tx;
	device_t dma_dev_rx;
	int fmt;

	ch = &scp->chan[0];
	sc = scp->sc;
	conf =  &sc->conf;

	fmt = sndbuf_getfmt(ch->buffer);

	conf->dst_incr = 0;
	conf->src_incr = 0;
	conf->direction = DMA_MEM_TO_DEV;
	conf->src_start = sc->buf_base_phys;
	conf->dst_start = (sc->aic_paddr + AICDR);

	printf("dst_start is %x\n", conf->dst_start);

	//xdma_channel_configure(conf);
	dma_dev_tx = xdma_get(sc->dev, "tx");
	dma_dev_rx = xdma_get(sc->dev, "rx");

#if 0
	conf->ih = aic_dma_intr;
	conf->ih_user = scp;
	conf->saddr = sc->buf_base_phys;
	conf->daddr = rman_get_start(sc->res[0]) + SSI_STX0;
	conf->event = sc->sdma_ev_tx; /* SDMA TX event */
	conf->period = sndbuf_getblksz(ch->buffer);
	conf->num_bd = sndbuf_getblkcnt(ch->buffer);

	/*
	 * Word Length
	 * Can be 32, 24, 16 or 8 for sDMA.
	 *
	 * SSI supports 24 at max.
	 */

	fmt = sndbuf_getfmt(ch->buffer);

	if (fmt & AFMT_16BIT) {
		conf->word_length = 16;
		conf->command = CMD_2BYTES;
	} else if (fmt & AFMT_24BIT) {
		conf->word_length = 24;
		conf->command = CMD_3BYTES;
	} else {
		device_printf(sc->dev, "Unknown format\n");
		return (-1);
	}
#endif

	return (0);
}

static int
aic_start(struct sc_pcminfo *scp)
{
	struct aic_softc *sc;
	int reg;

	sc = scp->sc;

	device_printf(scp->dev, "%s\n", __func__);

	reg = READ4(sc, AICCR);
	//reg |= (AICCR_CHANNEL_2);
	reg |= (AICCR_TDMS);
	reg |= (AICCR_ERPL);
	WRITE4(sc, AICCR, reg);

#if 0
	if (sdma_configure(sc->sdma_channel, sc->conf) != 0) {
		device_printf(sc->dev, "Can't configure sDMA\n");
		return (-1);
	}

	/* Enable DMA interrupt */
	reg = (SIER_TDMAE);
	WRITE4(sc, SSI_SIER, reg);

	sdma_start(sc->sdma_channel);
#endif

	return (0);
}

static int
aic_stop(struct sc_pcminfo *scp)
{
	struct aic_softc *sc;
	//int reg;

	sc = scp->sc;

	device_printf(scp->dev, "%s\n", __func__);

#if 0
	reg = READ4(sc, SSI_SIER);
	reg &= ~(SIER_TDMAE);
	WRITE4(sc, SSI_SIER, reg);

	sdma_stop(sc->sdma_channel);
#endif

	bzero(sc->buf_base, sc->dma_size);

	return (0);
}

static int
aicchan_trigger(kobj_t obj, void *data, int go)
{
	struct sc_pcminfo *scp;
	struct sc_chinfo *ch;
	struct aic_softc *sc;

	ch = data;
	scp = ch->parent;
	sc = scp->sc;

	device_printf(scp->dev, "%s\n", __func__);

	snd_mtxlock(sc->lock);

	switch (go) {
	case PCMTRIG_START:
#if 1
		device_printf(scp->dev, "trigger start\n");
#endif
		ch->run = 1;

		aic_start(scp);

		break;

	case PCMTRIG_STOP:
	case PCMTRIG_ABORT:
#if 1
		device_printf(scp->dev, "trigger stop or abort\n");
#endif
		ch->run = 0;

		aic_stop(scp);

		break;
	}

	snd_mtxunlock(sc->lock);

	return (0);
}

static uint32_t
aicchan_getptr(kobj_t obj, void *data)
{
	struct sc_pcminfo *scp;
	struct sc_chinfo *ch;
	struct aic_softc *sc;

	ch = data;
	scp = ch->parent;
	sc = scp->sc;

	device_printf(scp->dev, "%s\n", __func__);

	return (sc->pos);
}

static uint32_t aic_pfmt[] = {
	SND_FORMAT(AFMT_S24_LE, 2, 0),
	0
};

static struct pcmchan_caps aic_pcaps = {44100, 192000, aic_pfmt, 0};

static struct pcmchan_caps *
aicchan_getcaps(kobj_t obj, void *data)
{

	return (&aic_pcaps);
}

static kobj_method_t aicchan_methods[] = {
	KOBJMETHOD(channel_init,         aicchan_init),
	KOBJMETHOD(channel_free,         aicchan_free),
	KOBJMETHOD(channel_setformat,    aicchan_setformat),
	KOBJMETHOD(channel_setspeed,     aicchan_setspeed),
	KOBJMETHOD(channel_setblocksize, aicchan_setblocksize),
	KOBJMETHOD(channel_trigger,      aicchan_trigger),
	KOBJMETHOD(channel_getptr,       aicchan_getptr),
	KOBJMETHOD(channel_getcaps,      aicchan_getcaps),
	KOBJMETHOD_END
};
CHANNEL_DECLARE(aicchan);

static void
aic_dmamap_cb(void *arg, bus_dma_segment_t *segs, int nseg, int err)
{
	bus_addr_t *addr;

	if (err)
		return;

	addr = (bus_addr_t*)arg;
	*addr = segs[0].ds_addr;
}

static int
aic_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "ingenic,jz4780-i2s"))
		return (ENXIO);

	device_set_desc(dev, "Ingenic JZ4780 Audio Interface Controller");

	return (BUS_PROBE_DEFAULT);
}

static int
aic_attach(device_t dev)
{
	char status[SND_STATUSLEN];
	struct sc_pcminfo *scp;
	struct aic_softc *sc;
	uint32_t reg;
	int err;

	//sc = device_get_softc(dev);
	//sc->dev = dev;

	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK | M_ZERO);  
	sc->dev = dev;
	//sc->sr = &rate_map[0];
	sc->pos = 0;
	//sc->conf = malloc(sizeof(struct sdma_conf), M_DEVBUF, M_WAITOK | M_ZERO);

	printf("%s cl\n", __func__);
	sc->lock = snd_mtxcreate(device_get_nameunit(dev), "aic softc");
	if (sc->lock == NULL) {
		device_printf(dev, "Can't create mtx.\n");
		return (ENXIO);
	}
	printf("%s lc\n", __func__);

	if (bus_alloc_resources(dev, aic_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);
	sc->aic_paddr = rman_get_start(sc->res[0]);

	/* Setup PCM */
	scp = malloc(sizeof(struct sc_pcminfo), M_DEVBUF, M_NOWAIT | M_ZERO);
	scp->sc = sc;
	scp->dev = dev;

	/*
	 * Maximum possible DMA buffer.
	 * Will be used partially to match 24 bit word.
	 */
	sc->dma_size = 131072;

	/*
	 * Must use dma_size boundary as modulo feature required.
	 * Modulo feature allows setup circular buffer.
	 */
	err = bus_dma_tag_create(
	    bus_get_dma_tag(sc->dev),
	    4, sc->dma_size,		/* alignment, boundary */
	    BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    sc->dma_size, 1,		/* maxsize, nsegments */
	    sc->dma_size, 0,		/* maxsegsize, flags */
	    NULL, NULL,			/* lockfunc, lockarg */
	    &sc->dma_tag);

	err = bus_dmamem_alloc(sc->dma_tag, (void **)&sc->buf_base,
	    BUS_DMA_NOWAIT | BUS_DMA_COHERENT, &sc->dma_map);
	if (err) {
		device_printf(dev, "cannot allocate framebuffer\n");
		return (ENXIO);
	}

	err = bus_dmamap_load(sc->dma_tag, sc->dma_map, sc->buf_base,
	    sc->dma_size, aic_dmamap_cb, &sc->buf_base_phys, BUS_DMA_NOWAIT);
	if (err) {
		device_printf(dev, "cannot load DMA map\n");
		return (ENXIO);
	}

	bzero(sc->buf_base, sc->dma_size);

	/* Configure AIC */
	reg = READ4(sc, AICFR);
	reg |= (AICFR_BCKD);	/* BIT_CLK is generated internally and
				   driven out to the CODEC. */
	reg |= (AICFR_ENB);	/* Enable the controller. */
	reg |= (AICFR_AUSEL);	/* Select I2S/MSB-justified format. */
	reg |= (AICFR_ICDC);	/* Internal CODEC. */
	WRITE4(sc, AICFR, reg);

	reg = READ4(sc, AICCR);
	reg |= (AICCR_CHANNEL_2);
	reg |= (AICCR_TFLUSH | AICCR_RFLUSH);
	//reg |= (AICCR_TDMS);
	//reg |= (AICCR_ERPL);
	WRITE4(sc, AICCR, reg);

	pcm_setflags(dev, pcm_getflags(dev) | SD_F_MPSAFE);

	err = pcm_register(dev, scp, 1, 0);
	if (err) {
		device_printf(dev, "Can't register pcm.\n");
		return (ENXIO);
	}

	scp->chnum = 0;
	pcm_addchan(dev, PCMDIR_PLAY, &aicchan_class, scp);
	scp->chnum++;

	snprintf(status, SND_STATUSLEN, "at simplebus");
	pcm_setstatus(dev, status);

	mixer_init(dev, &aicmixer_class, scp);

	return (0);
}

static int
aic_detach(device_t dev)
{
	struct aic_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, aic_spec, sc->res);

	return (0);
}

static device_method_t aic_pcm_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		aic_probe),
	DEVMETHOD(device_attach,	aic_attach),
	DEVMETHOD(device_detach,	aic_detach),
	DEVMETHOD_END
};

static driver_t aic_pcm_driver = {
	"pcm",
	aic_pcm_methods,
	PCM_SOFTC_SIZE,
};

DRIVER_MODULE(aic, simplebus, aic_pcm_driver, pcm_devclass, 0, 0);
MODULE_DEPEND(aic, sound, SOUND_MINVER, SOUND_PREFVER, SOUND_MAXVER);
MODULE_VERSION(aic, 1);
