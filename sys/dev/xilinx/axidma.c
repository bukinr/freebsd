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
 * This is part of Xilinx AXI Ethernet (xae) driver.
 */

#include <sys/cdefs.h>
#include "opt_platform.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/socket.h>

#include <machine/bus.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_var.h>

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

#define	READ4(_sc, _reg)	\
	bus_space_read_4(_sc->bst, _sc->bsh, _reg)
#define	WRITE4(_sc, _reg, _val)	\
	bus_space_write_4(_sc->bst, _sc->bsh, _reg, _val)
#define	READ8(_sc, _reg)	\
	bus_space_read_8(_sc->bst, _sc->bsh, _reg)
#define	WRITE8(_sc, _reg, _val)	\
	bus_space_write_8(_sc->bst, _sc->bsh, _reg, _val)

#define	AXIDMA_LOCK(sc)			mtx_lock(&(sc)->mtx)
#define	AXIDMA_UNLOCK(sc)		mtx_unlock(&(sc)->mtx)
#define	AXIDMA_ASSERT_LOCKED(sc)	mtx_assert(&(sc)->mtx, MA_OWNED)
#define	AXIDMA_ASSERT_UNLOCKED(sc)	mtx_assert(&(sc)->mtx, MA_NOTOWNED)

#define AXIDMA_DEBUG
#undef AXIDMA_DEBUG

#ifdef AXIDMA_DEBUG
#define dprintf(fmt, ...)  printf(fmt, ##__VA_ARGS__)
#else
#define dprintf(fmt, ...)
#endif

#define	AXI_DESC_RING_ALIGN		64

/*
 * Driver data and defines.
 */
#define	RX_DESC_COUNT	64
#define	RX_DESC_SIZE	(sizeof(struct axidma_desc) * RX_DESC_COUNT)
#define	TX_DESC_COUNT	64
#define	TX_DESC_SIZE	(sizeof(struct axidma_desc) * TX_DESC_COUNT)

extern struct bus_space memmap_bus;

struct axidma_bufmap {
	struct mbuf	*mbuf;
	bus_dmamap_t	map;
};

struct axidma_softc {
	device_t		dev;
	struct resource		*res[3];
	bus_space_tag_t		bst;
	bus_space_handle_t	bsh;
	void			*ih[2];

	struct mtx		mtx;
	if_t			ifp;

	int			rxbuf_align;
	int			txbuf_align;

	bus_dma_tag_t		rxdesc_tag;
	bus_dmamap_t		rxdesc_map;
	struct axidma_desc	*rxdesc_ring;
	bus_addr_t		rxdesc_ring_paddr;
	bus_dma_tag_t		rxbuf_tag;
	struct axidma_bufmap	rxbuf_map[RX_DESC_COUNT];
	uint32_t		rx_idx;

	bus_dma_tag_t		txdesc_tag;
	bus_dmamap_t		txdesc_map;
	struct axidma_desc	*txdesc_ring;
	bus_addr_t		txdesc_ring_paddr;
	bus_dma_tag_t		txbuf_tag;
	struct axidma_bufmap	txbuf_map[TX_DESC_COUNT];
	uint32_t		tx_idx_head;
	uint32_t		tx_idx_tail;
	int			txcount;
};

static struct resource_spec axidma_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		1,	RF_ACTIVE },
	{ -1, 0 }
};

#define	HWTYPE_NONE	0
#define	HWTYPE_STD	1

static struct ofw_compat_data compat_data[] = {
	{ "xlnx,eth-dma",	HWTYPE_STD },
	{ NULL,			HWTYPE_NONE },
};

static inline uint32_t
next_rxidx(struct axidma_softc *sc, uint32_t curidx)
{

	return ((curidx == RX_DESC_COUNT - 1) ? 0 : curidx + 1);
}

static inline uint32_t
next_txidx(struct axidma_softc *sc, uint32_t curidx)
{

	return ((curidx == TX_DESC_COUNT - 1) ? 0 : curidx + 1);
}

static void
axidma_get1paddr(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{

	if (error != 0)
		return;
	*(bus_addr_t *)arg = segs[0].ds_addr;
}

inline static uint32_t
axidma_setup_txdesc(struct axidma_softc *sc, int idx, bus_addr_t paddr, 
    uint32_t len)
{
	struct axidma_desc *desc;
	uint32_t nidx;
	uint32_t flags;

	nidx = next_txidx(sc, idx);

	desc = &sc->txdesc_ring[idx];

	/* Addr/len 0 means we're clearing the descriptor after xmit done. */
	if (paddr == 0 || len == 0) {
		flags = 0;
		--sc->txcount;
	} else {
		flags = BD_CONTROL_TXSOF | BD_CONTROL_TXEOF;
		++sc->txcount;
	}

	desc->next = sc->txdesc_ring_paddr + sizeof(struct axidma_desc) * nidx;
	desc->phys = paddr;
	desc->status = 0;
	desc->control = len | flags;

	return (nidx);
}

static int
axidma_setup_txbuf(struct axidma_softc *sc, int idx, struct mbuf **mp)
{
	struct bus_dma_segment seg;
	struct mbuf *m;
	int error;
	int nsegs;

dprintf("%s\n", __func__);

	if ((m = m_defrag(*mp, M_NOWAIT)) == NULL)
		return (ENOMEM);

	*mp = m;

	error = bus_dmamap_load_mbuf_sg(sc->txbuf_tag, sc->txbuf_map[idx].map,
	    m, &seg, &nsegs, 0);
	if (error != 0)
		return (ENOMEM);

	bus_dmamap_sync(sc->txbuf_tag, sc->txbuf_map[idx].map,
	    BUS_DMASYNC_PREWRITE);

	sc->txbuf_map[idx].mbuf = m;
	axidma_setup_txdesc(sc, idx, seg.ds_addr, seg.ds_len);

	return (0);
}

static void
axidma_txstart_locked(struct axidma_softc *sc)
{
	struct mbuf *m;
	int enqueued;
	uint32_t addr;
	int tmp;
	if_t ifp;

dprintf("%s\n", __func__);

	AXIDMA_ASSERT_LOCKED(sc);

#if 0
	if (!sc->link_is_up)
		return;
#endif

	ifp = sc->ifp;

	if (if_getdrvflags(ifp) & IFF_DRV_OACTIVE)
		return;

	enqueued = 0;

	for (;;) {
		if (sc->txcount == (TX_DESC_COUNT - 1)) {
			if_setdrvflagbits(ifp, IFF_DRV_OACTIVE, 0);
			break;
		}
		m = if_dequeue(ifp);
		if (m == NULL)
			break;
		if (axidma_setup_txbuf(sc, sc->tx_idx_head, &m) != 0) {
			if_sendq_prepend(ifp, m);
			break;
		}
		BPF_MTAP(ifp, m);
		tmp = sc->tx_idx_head;
		sc->tx_idx_head = next_txidx(sc, sc->tx_idx_head);
		++enqueued;
	}

	if (enqueued != 0) {
		bus_dmamap_sync(sc->txdesc_tag, sc->txdesc_map,
		    BUS_DMASYNC_PREWRITE);

		addr = sc->txdesc_ring_paddr + tmp * sizeof(struct axidma_desc);
		dprintf("%s: new tail desc %x\n", __func__, addr);
		WRITE8(sc, AXI_TAILDESC(AXIDMA_TX_CHAN), addr);
	}
}

static void
axidma_txfinish_locked(struct axidma_softc *sc)
{
	struct axidma_desc *desc;
	struct axidma_bufmap *bmap;
	boolean_t retired_buffer;
	if_t ifp;

	AXIDMA_ASSERT_LOCKED(sc);

	/* XXX Can't set PRE|POST right now, but we need both. */
	bus_dmamap_sync(sc->txdesc_tag, sc->txdesc_map, BUS_DMASYNC_PREREAD);
	bus_dmamap_sync(sc->txdesc_tag, sc->txdesc_map, BUS_DMASYNC_POSTREAD);
	ifp = sc->ifp;
	retired_buffer = false;
	while (sc->tx_idx_tail != sc->tx_idx_head) {
		desc = &sc->txdesc_ring[sc->tx_idx_tail];
		if ((desc->status & BD_STATUS_CMPLT) == 0)
			break;
		retired_buffer = true;
		bmap = &sc->txbuf_map[sc->tx_idx_tail];
		bus_dmamap_sync(sc->txbuf_tag, bmap->map, 
		   BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->txbuf_tag, bmap->map);
		m_freem(bmap->mbuf);
		bmap->mbuf = NULL;
		axidma_setup_txdesc(sc, sc->tx_idx_tail, 0, 0);
		sc->tx_idx_tail = next_txidx(sc, sc->tx_idx_tail);
	}

	/*
	* If we retired any buffers, there will be open tx slots available in
	* the descriptor ring, go try to start some new output.
	*/
	if (retired_buffer) {
		if_setdrvflagbits(ifp, 0, IFF_DRV_OACTIVE);
		axidma_txstart_locked(sc);
	}

	/* If there are no buffers outstanding, muzzle the watchdog. */
	if (sc->tx_idx_tail == sc->tx_idx_head) {
		//sc->tx_watchdog_count = 0;
	}
}

inline static uint32_t
axidma_setup_rxdesc(struct axidma_softc *sc, int idx, bus_addr_t paddr)
{
	struct axidma_desc *desc;
	uint32_t nidx;

	/*
	 * The hardware requires 32-bit physical addresses.  We set up the dma
	 * tag to indicate that, so the cast to uint32_t should never lose
	 * significant bits.
	 */
	nidx = next_rxidx(sc, idx);

	desc = &sc->rxdesc_ring[idx];
	desc->next = sc->rxdesc_ring_paddr + sizeof(struct axidma_desc) * nidx;
	desc->phys = paddr;
	desc->status = 0;
	desc->control = MCLBYTES | BD_CONTROL_TXSOF | BD_CONTROL_TXEOF;

	return (nidx);
}

static struct mbuf *
axidma_alloc_mbufcl(struct axidma_softc *sc)
{
	struct mbuf *m;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m != NULL)
		m->m_pkthdr.len = m->m_len = m->m_ext.ext_size;

	return (m);
}

static int
axidma_setup_rxbuf(struct axidma_softc *sc, int idx, struct mbuf * m)
{
	int error, nsegs;
	struct bus_dma_segment seg;

	error = bus_dmamap_load_mbuf_sg(sc->rxbuf_tag, sc->rxbuf_map[idx].map,
	   m, &seg, &nsegs, 0);
	if (error != 0) {
		return (error);
	}

	bus_dmamap_sync(sc->rxbuf_tag, sc->rxbuf_map[idx].map,
	   BUS_DMASYNC_PREREAD);

	sc->rxbuf_map[idx].mbuf = m;
	axidma_setup_rxdesc(sc, idx, seg.ds_addr);
	
	return (0);
}

static void
axidma_rxfinish_onebuf(struct axidma_softc *sc, int len)
{
	struct mbuf *m, *newmbuf;
	struct axidma_bufmap *bmap;
	int error;

dprintf("%s\n", __func__);
	/*
	*  First try to get a new mbuf to plug into this slot in the rx ring.
	*  If that fails, drop the current packet and recycle the current
	*  mbuf, which is still mapped and loaded.
	*/
	if ((newmbuf = axidma_alloc_mbufcl(sc)) == NULL) {
		if_inc_counter(sc->ifp, IFCOUNTER_IQDROPS, 1);
		axidma_setup_rxdesc(sc, sc->rx_idx, 
		    sc->rxdesc_ring[sc->rx_idx].phys);
		return;
	}

	AXIDMA_UNLOCK(sc);

	bmap = &sc->rxbuf_map[sc->rx_idx];
	bus_dmamap_sync(sc->rxbuf_tag, bmap->map, BUS_DMASYNC_POSTREAD);
	bus_dmamap_unload(sc->rxbuf_tag, bmap->map);
	m = bmap->mbuf;
	bmap->mbuf = NULL;
	m->m_len = len;
	m->m_pkthdr.len = len;
	m->m_pkthdr.rcvif = sc->ifp;

	if_input(sc->ifp, m);

	AXIDMA_LOCK(sc);

	if ((error = axidma_setup_rxbuf(sc, sc->rx_idx, newmbuf)) != 0) {
		device_printf(sc->dev, "axidma_setup_rxbuf error %d\n", error);
		/* XXX Now what?  We've got a hole in the rx ring. */
	}
}

static void
axidma_rxfinish_locked(struct axidma_softc *sc)
{
	boolean_t produced_empty_buffer;
	struct axidma_desc *desc;
	uint32_t addr;
	int len;
	int tmp;

dprintf("%s\n", __func__);

	AXIDMA_ASSERT_LOCKED(sc);

	/* XXX Can't set PRE|POST right now, but we need both. */
	//bus_dmamap_sync(sc->rxdesc_tag, sc->rxdesc_map, BUS_DMASYNC_PREREAD);
	bus_dmamap_sync(sc->rxdesc_tag, sc->rxdesc_map, BUS_DMASYNC_POSTREAD);
	produced_empty_buffer = false;
	for (;;) {
		desc = &sc->rxdesc_ring[sc->rx_idx];
		if ((desc->status & BD_STATUS_CMPLT) == 0)
			break;
		produced_empty_buffer = true;
		len = desc->status & BD_CONTROL_LEN_M;
		axidma_rxfinish_onebuf(sc, len);
		tmp = sc->rx_idx;
		sc->rx_idx = next_rxidx(sc, sc->rx_idx);
	}

	if (produced_empty_buffer) {
		bus_dmamap_sync(sc->rxdesc_tag, sc->rxdesc_map,
		    BUS_DMASYNC_PREWRITE);

		addr = sc->rxdesc_ring_paddr + tmp * sizeof(struct axidma_desc);
		dprintf("%s: new tail desc %x\n", __func__, addr);
		WRITE8(sc, AXI_TAILDESC(AXIDMA_RX_CHAN), addr);
	}
}

static void
axidma_intr_rx(void *arg)
{
	struct axidma_softc *sc;
	uint32_t pending;

	sc = arg;

	AXIDMA_LOCK(sc);
	pending = READ4(sc, AXI_DMASR(AXIDMA_RX_CHAN));
dprintf("%s: pending %x\n", __func__, pending);
	WRITE4(sc, AXI_DMASR(AXIDMA_RX_CHAN), pending);
	axidma_rxfinish_locked(sc);
	AXIDMA_UNLOCK(sc);
}

static void
axidma_intr_tx(void *arg)
{
	struct axidma_softc *sc;
	uint32_t pending;

	sc = arg;

	AXIDMA_LOCK(sc);
	pending = READ4(sc, AXI_DMASR(AXIDMA_TX_CHAN));
dprintf("%s: pending %x\n", __func__, pending);
	WRITE4(sc, AXI_DMASR(AXIDMA_TX_CHAN), pending);
	axidma_txfinish_locked(sc);
	AXIDMA_UNLOCK(sc);
}

static int
axidma_reset(struct axidma_softc *sc, int chan_id)
{
	int timeout;

	WRITE4(sc, AXI_DMACR(chan_id), DMACR_RESET);

	timeout = 100;
	do {
		if ((READ4(sc, AXI_DMACR(chan_id)) & DMACR_RESET) == 0)
			break;
	} while (timeout--);

	dprintf("timeout %d\n", timeout);

	if (timeout == 0)
		return (-1);

	dprintf("%s: read control after reset: %x\n",
	    __func__, READ4(sc, AXI_DMACR(chan_id)));

	return (0);
}

static int
axidma_probe(device_t dev)
{
	int hwtype;

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	hwtype = ofw_bus_search_compatible(dev, compat_data)->ocd_data;
	if (hwtype == HWTYPE_NONE)
		return (ENXIO);

	device_set_desc(dev, "Xilinx AXI DMA");

	return (BUS_PROBE_DEFAULT);
}

static int
axidma_attach(device_t dev)
{
	struct axidma_softc *sc;
	phandle_t xref, node;
	struct mbuf *m;
	int error;
	int err;
	int idx;

	sc = device_get_softc(dev);
	sc->dev = dev;

	mtx_init(&sc->mtx, device_get_nameunit(sc->dev),
	    MTX_NETWORK_LOCK, MTX_DEF);
	sc->rx_idx = 0;
	sc->tx_idx_head = sc->tx_idx_tail = 0;
	sc->txcount = 0;

	if (bus_alloc_resources(dev, axidma_spec, sc->res)) {
		device_printf(dev, "could not allocate resources.\n");
		return (ENXIO);
	}

	/* CSR memory interface */
	sc->bst = rman_get_bustag(sc->res[0]);
	sc->bsh = rman_get_bushandle(sc->res[0]);

	/* Setup interrupt handler */
	err = bus_setup_intr(dev, sc->res[1], INTR_TYPE_MISC | INTR_MPSAFE,
	    NULL, axidma_intr_tx, sc, &sc->ih[0]);
	if (err) {
		device_printf(dev, "Unable to alloc interrupt resource.\n");
		return (ENXIO);
	}

	/* Setup interrupt handler */
	err = bus_setup_intr(dev, sc->res[2], INTR_TYPE_MISC | INTR_MPSAFE,
	    NULL, axidma_intr_rx, sc, &sc->ih[1]);
	if (err) {
		device_printf(dev, "Unable to alloc interrupt resource.\n");
		return (ENXIO);
	}

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	sc->rxbuf_align = PAGE_SIZE;
	sc->txbuf_align = PAGE_SIZE;

	/*
	* Set up TX descriptor ring, descriptors, and dma maps.
	*/
	error = bus_dma_tag_create(
	   bus_get_dma_tag(dev),	/* Parent tag. */
	   AXI_DESC_RING_ALIGN, 0,	/* alignment, boundary */
	   BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	   BUS_SPACE_MAXADDR,		/* highaddr */
	   NULL, NULL,			/* filter, filterarg */
	   TX_DESC_SIZE, 1, 		/* maxsize, nsegments */
	   TX_DESC_SIZE,		/* maxsegsize */
	   0,				/* flags */
	   NULL, NULL,			/* lockfunc, lockarg */
	   &sc->txdesc_tag);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not create TX ring DMA tag.\n");
		goto out;
	}

	error = bus_dmamem_alloc(sc->txdesc_tag, (void**)&sc->txdesc_ring,
	   BUS_DMA_COHERENT | BUS_DMA_WAITOK | BUS_DMA_ZERO, &sc->txdesc_map);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not allocate TX descriptor ring.\n");
		goto out;
	}

	error = bus_dmamap_load(sc->txdesc_tag, sc->txdesc_map, sc->txdesc_ring,
	   TX_DESC_SIZE, axidma_get1paddr, &sc->txdesc_ring_paddr, 0);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not load TX descriptor ring map.\n");
		goto out;
	}

	error = bus_dma_tag_create(
	   bus_get_dma_tag(dev),	/* Parent tag. */
	   sc->txbuf_align, 0,		/* alignment, boundary */
	   BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	   BUS_SPACE_MAXADDR,		/* highaddr */
	   NULL, NULL,			/* filter, filterarg */
	   MCLBYTES, 1, 		/* maxsize, nsegments */
	   MCLBYTES,			/* maxsegsize */
	   0,				/* flags */
	   NULL, NULL,			/* lockfunc, lockarg */
	   &sc->txbuf_tag);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not create TX ring DMA tag.\n");
		goto out;
	}

	struct axidma_desc *desc;
	for (idx = 0; idx < TX_DESC_COUNT; ++idx) {
		desc = &sc->txdesc_ring[idx];
		bzero(desc, sizeof(struct axidma_desc));
	}

	for (idx = 0; idx < TX_DESC_COUNT; ++idx) {
		error = bus_dmamap_create(sc->txbuf_tag, 0,
		   &sc->txbuf_map[idx].map);
		if (error != 0) {
			device_printf(sc->dev,
			   "could not create TX buffer DMA map.\n");
			goto out;
		}
		axidma_setup_txdesc(sc, idx, 0, 0);
	}

	/*
	* Set up RX descriptor ring, descriptors, dma maps, and mbufs.
	*/
	error = bus_dma_tag_create(
	   bus_get_dma_tag(dev),	/* Parent tag. */
	   AXI_DESC_RING_ALIGN, 0,	/* alignment, boundary */
	   BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	   BUS_SPACE_MAXADDR,		/* highaddr */
	   NULL, NULL,			/* filter, filterarg */
	   RX_DESC_SIZE, 1, 		/* maxsize, nsegments */
	   RX_DESC_SIZE,		/* maxsegsize */
	   0,				/* flags */
	   NULL, NULL,			/* lockfunc, lockarg */
	   &sc->rxdesc_tag);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not create RX ring DMA tag.\n");
		goto out;
	}

	error = bus_dmamem_alloc(sc->rxdesc_tag, (void **)&sc->rxdesc_ring, 
	   BUS_DMA_COHERENT | BUS_DMA_WAITOK | BUS_DMA_ZERO, &sc->rxdesc_map);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not allocate RX descriptor ring.\n");
		goto out;
	}

	error = bus_dmamap_load(sc->rxdesc_tag, sc->rxdesc_map, sc->rxdesc_ring,
	   RX_DESC_SIZE, axidma_get1paddr, &sc->rxdesc_ring_paddr, 0);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not load RX descriptor ring map.\n");
		goto out;
	}

	error = bus_dma_tag_create(
	   bus_get_dma_tag(dev),	/* Parent tag. */
	   1, 0,			/* alignment, boundary */
	   BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
	   BUS_SPACE_MAXADDR,		/* highaddr */
	   NULL, NULL,			/* filter, filterarg */
	   MCLBYTES, 1, 		/* maxsize, nsegments */
	   MCLBYTES,			/* maxsegsize */
	   0,				/* flags */
	   NULL, NULL,			/* lockfunc, lockarg */
	   &sc->rxbuf_tag);
	if (error != 0) {
		device_printf(sc->dev,
		   "could not create RX buf DMA tag.\n");
		goto out;
	}

	for (idx = 0; idx < RX_DESC_COUNT; ++idx) {
		desc = &sc->rxdesc_ring[idx];
		bzero(desc, sizeof(struct axidma_desc));
	}

	for (idx = 0; idx < RX_DESC_COUNT; ++idx) {
		error = bus_dmamap_create(sc->rxbuf_tag, 0,
		   &sc->rxbuf_map[idx].map);
		if (error != 0) {
			device_printf(sc->dev,
			   "could not create RX buffer DMA map.\n");
			goto out;
		}
		if ((m = axidma_alloc_mbufcl(sc)) == NULL) {
			device_printf(dev, "Could not alloc mbuf\n");
			error = ENOMEM;
			goto out;
		}
		if ((error = axidma_setup_rxbuf(sc, idx, m)) != 0) {
			device_printf(sc->dev,
			   "could not create new RX buffer.\n");
			goto out;
		}
	}

	uint32_t reg;

	if (axidma_reset(sc, AXIDMA_TX_CHAN) != 0)
		return (-1);
	if (axidma_reset(sc, AXIDMA_RX_CHAN) != 0)
		return (-1);

dprintf("%s: tx desc base %lx\n", __func__, sc->txdesc_ring_paddr);
	WRITE8(sc, AXI_CURDESC(AXIDMA_TX_CHAN), sc->txdesc_ring_paddr);
	reg = READ4(sc, AXI_DMACR(AXIDMA_TX_CHAN));
	reg |= DMACR_IOC_IRQEN | DMACR_DLY_IRQEN | DMACR_ERR_IRQEN;
	WRITE4(sc, AXI_DMACR(AXIDMA_TX_CHAN), reg);
	reg |= DMACR_RS;
	//WRITE4(sc, AXI_DMACR(AXIDMA_TX_CHAN), reg);

	WRITE8(sc, AXI_CURDESC(AXIDMA_RX_CHAN), sc->rxdesc_ring_paddr);
	reg = READ4(sc, AXI_DMACR(AXIDMA_RX_CHAN));
	reg |= DMACR_IOC_IRQEN | DMACR_DLY_IRQEN | DMACR_ERR_IRQEN;
	WRITE4(sc, AXI_DMACR(AXIDMA_RX_CHAN), reg);
	reg |= DMACR_RS;
	//WRITE4(sc, AXI_DMACR(AXIDMA_RX_CHAN), reg);

	return (0);

	uint32_t addr;
	addr = sc->rxdesc_ring_paddr +
	    (RX_DESC_COUNT - 1) * sizeof(struct axidma_desc);
dprintf("%s: new RX tail desc %x\n", __func__, addr);
	WRITE8(sc, AXI_TAILDESC(AXIDMA_RX_CHAN), addr);

out:
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
axidma_txstart(device_t dev, if_t ifp)
{
	struct axidma_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev); //if_getsoftc(ifp);
	sc->ifp = ifp;

dprintf("%s\n", __func__);

	reg = READ4(sc, AXI_DMACR(AXIDMA_TX_CHAN));
	reg |= DMACR_RS;
	WRITE4(sc, AXI_DMACR(AXIDMA_TX_CHAN), reg);

	reg = READ4(sc, AXI_DMACR(AXIDMA_RX_CHAN));
	reg |= DMACR_RS;
	WRITE4(sc, AXI_DMACR(AXIDMA_RX_CHAN), reg);

	uint32_t addr;
	addr = sc->rxdesc_ring_paddr +
	    (RX_DESC_COUNT - 1) * sizeof(struct axidma_desc);
dprintf("%s: new RX tail desc %x\n", __func__, addr);
	WRITE8(sc, AXI_TAILDESC(AXIDMA_RX_CHAN), addr);

	AXIDMA_LOCK(sc);
	axidma_txstart_locked(sc);
	AXIDMA_UNLOCK(sc);

	return (0);
}

static device_method_t axidma_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,			axidma_probe),
	DEVMETHOD(device_attach,		axidma_attach),
	DEVMETHOD(device_detach,		axidma_detach),

	DEVMETHOD(axidma_txstart,		axidma_txstart),

	DEVMETHOD_END
};

static driver_t axidma_driver = {
	"axidma",
	axidma_methods,
	sizeof(struct axidma_softc),
};

EARLY_DRIVER_MODULE(axidma, simplebus, axidma_driver, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
