/*-
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Innovate
 * UK project 105694, "Digital Security by Design (DSbD) Technology Platform
 * Prototype".
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

/*
 * SBI is fully handled in userspace.
 *
 * TODO: We may need to handle the SBI IPI extension here in kernel.
 * The same for the SBI TIME extension in case of no SSTC support in HW.
 */

static int
vmm_sbi_handle_ipi(struct vcpu *vcpu, struct hypctx *hypctx)
{
	uint64_t func_id;
	uint64_t hart_mask;

	func_id = hypctx->guest_regs.hyp_a[6];

	printf("%s: func %ld\n", __func__, func_id);

	switch (func_id) {
	case SBI_IPI_SEND_IPI:
		hart_mask = hypctx->guest_regs.hyp_a[0];
		printf("hart_mask %lx\n", hart_mask);
		break;
	default:
		break;
	}

	return (0);
}

int
vmm_sbi_ecall(struct vcpu *vcpu, bool *retu)
{
	int sbi_extension_id __unused;
	struct hypctx *hypctx;

	hypctx = riscv_get_active_vcpu();
	sbi_extension_id = hypctx->guest_regs.hyp_a[7];

	dprintf("%s: args %lx %lx %lx %lx %lx %lx %lx %lx\n", __func__,
	    hypctx->guest_regs.hyp_a[0],
	    hypctx->guest_regs.hyp_a[1],
	    hypctx->guest_regs.hyp_a[2],
	    hypctx->guest_regs.hyp_a[3],
	    hypctx->guest_regs.hyp_a[4],
	    hypctx->guest_regs.hyp_a[5],
	    hypctx->guest_regs.hyp_a[6],
	    hypctx->guest_regs.hyp_a[7]);

	switch (sbi_extension_id) {
	case SBI_EXT_ID_TIME:
		break;
	case SBI_EXT_ID_IPI:
		vmm_sbi_handle_ipi(vcpu, hypctx);
		break;
	default:
		*retu = true;
		break;
	}

	return (0);
}
