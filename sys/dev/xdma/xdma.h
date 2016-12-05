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
 *
 * $FreeBSD$
 */

#ifndef _DEV_EXTRES_XDMA_H_
#define _DEV_EXTRES_XDMA_H_

enum xdma_direction {
	XDMA_MEM_TO_MEM,
	XDMA_MEM_TO_DEV,
	XDMA_DEV_TO_MEM,
	XDMA_DEV_TO_DEV,
};

enum xdma_operation_type {
	XDMA_MEMCPY,
	XDMA_SG,
	XDMA_CYCLIC,
};

enum xdma_command {
	XDMA_CMD_START,
	XDMA_CMD_STOP,
	XDMA_CMD_PAUSE,
};

struct xdma_controller {
	device_t dev;		/* A real DMA device_t. */
	void *data;		/* MD part */
};

typedef struct xdma_controller *xdma_controller_t;

struct xdma_channel {
	xdma_controller_t		xdma;
	void				*chan;
	void				*descs;
	uintptr_t			descs_phys;
	uint32_t			ndescs;
	//struct xdma_intr_handler	*ih;
	TAILQ_HEAD(, xdma_intr_handler)	ie_handlers; /* Interrupt handlers. */

	int				(*cb)(void *);
	void				*cb_user;
};

typedef struct xdma_channel xdma_channel_t;

struct xdma_channel_config {
	enum xdma_direction	direction;
	uintptr_t		src_addr;
	uintptr_t		dst_addr;
	int			period_len;	/* In bytes. */
	int			hwdesc_num;
	int			width;		/* In bytes. */
	//int			(*cb)(void *);
	//void			*cb_user;
};

xdma_controller_t xdma_get(device_t dev, const char *prop);
xdma_channel_t * xdma_channel_alloc(xdma_controller_t xdma);
int xdma_prepare(struct xdma_channel *xchan, struct xdma_channel_config *xconf);
int xdma_test(device_t dev);
int xdma_control(xdma_controller_t xdma, int command);
int xdma_callback(struct xdma_channel *xchan);
int xdma_desc_alloc(xdma_channel_t *xchan, uint32_t ndescs, uint32_t desc_sz);
int xdma_begin(xdma_channel_t *xchan);
int xdma_terminate(xdma_channel_t *xchan);
int xdma_setup_intr(xdma_channel_t *xchan, int (*cb)(void *), void *arg);

struct xdma_intr_handler {
	int	(*cb)(void *);
	void	*cb_user;
	TAILQ_ENTRY(xdma_intr_handler)	ih_next;
};

#endif /* !_DEV_EXTRES_XDMA_H_ */
