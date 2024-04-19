/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/sysctl.h>
#include <sys/libkern.h>
#include <sys/ioccom.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>

#include <machine/machdep.h>
#include <machine/vmparam.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/md_var.h>
#include <machine/sbi.h>

#include "riscv.h"

#define	BHYVE_IMPL_ID	4
#define	BHYVE_VERSION	((uint64_t)__FreeBSD_version)

static int
vmm_sbi_probe_extension(struct hypctx *hypctx, int ext_id)
{

	switch (ext_id) {
	case SBI_EXT_ID_TIME:
	case SBI_EXT_ID_IPI:
	case SBI_EXT_ID_RFNC:
	case SBI_EXT_ID_SRST:
	case SBI_CONSOLE_PUTCHAR:
	case SBI_CONSOLE_GETCHAR:
		break;
	default:
		panic("%s: unknown ext_id %d", __func__, ext_id);
	}

	return (1);
}

static int
vmm_sbi_handle_base(struct hypctx *hypctx)
{
	int sbi_function_id;
	int ext_id;
	uint32_t val;

	sbi_function_id = hypctx->guest_regs.hyp_a[6];

	switch (sbi_function_id) {
	case SBI_BASE_GET_SPEC_VERSION:
		val = 2 << SBI_SPEC_VERS_MAJOR_OFFSET;
		val |= 0 << SBI_SPEC_VERS_MINOR_OFFSET;
		break;
	case SBI_BASE_GET_IMPL_ID:
		val = BHYVE_IMPL_ID;
		break;
	case SBI_BASE_GET_IMPL_VERSION:
		val = BHYVE_VERSION;
		break;
	case SBI_BASE_PROBE_EXTENSION:
		ext_id = hypctx->guest_regs.hyp_a[0];
		val = vmm_sbi_probe_extension(hypctx, ext_id);
		break;
	case SBI_BASE_GET_MVENDORID:
		val = mvendorid;
		break;
	case SBI_BASE_GET_MARCHID:
		val = marchid;
		break;
	case SBI_BASE_GET_MIMPID:
		val = mimpid;
		break;
	default:
		panic("unknown sbi function id %d", sbi_function_id);
	}

	hypctx->guest_regs.hyp_a[0] = 0;
	hypctx->guest_regs.hyp_a[1] = val;

	return (0);
}

static int
vmm_sbi_handle_srst(struct hypctx *hypctx)
{
	int func_id;
	int type;

	func_id = hypctx->guest_regs.hyp_a[6];
	type = hypctx->guest_regs.hyp_a[0];

	switch (func_id) {
	case SBI_SRST_SYSTEM_RESET:
		switch (type) {
		case SBI_SRST_TYPE_SHUTDOWN:
		case SBI_SRST_TYPE_COLD_REBOOT:
		case SBI_SRST_TYPE_WARM_REBOOT:
			panic("sbi reset issued");
		}
	}

	return (0);
}

int
vmm_sbi_ecall(struct vcpu *vcpu, bool *retu)
{
	struct hypctx *hypctx;
	int sbi_extension_id;

	hypctx = riscv_get_active_vcpu();

	printf("%s: args %lx %lx %lx %lx %lx %lx %lx %lx\n", __func__,
	    hypctx->guest_regs.hyp_a[0],
	    hypctx->guest_regs.hyp_a[1],
	    hypctx->guest_regs.hyp_a[2],
	    hypctx->guest_regs.hyp_a[3],
	    hypctx->guest_regs.hyp_a[4],
	    hypctx->guest_regs.hyp_a[5],
	    hypctx->guest_regs.hyp_a[6],
	    hypctx->guest_regs.hyp_a[7]);

	sbi_extension_id = hypctx->guest_regs.hyp_a[7];

	switch (sbi_extension_id) {
	case SBI_EXT_ID_BASE:
		vmm_sbi_handle_base(hypctx);
		break;
	case SBI_EXT_ID_SRST:
		vmm_sbi_handle_srst(hypctx);
		break;
	default:
		panic("unknown sbi extension id 0x%x", sbi_extension_id);
	}

	return (0);
}
