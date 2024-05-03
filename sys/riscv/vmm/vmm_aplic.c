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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>

#include <riscv/vmm/hyp.h>
#include <riscv/vmm/riscv.h>
#include <riscv/vmm/vmm_aplic.h>

#include <machine/vmm_instruction_emul.h>
#include <machine/vmm_dev.h>

MALLOC_DEFINE(M_APLIC, "RISC-V VMM APLIC", "RISC-V AIA APLIC");

struct aplic {
	uint32_t dist_start;
	uint32_t dist_end;
	struct mtx mtx;
};

static int
dist_read(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{

	printf("%s: fault_ipa %lx size %d\n", __func__,
	    fault_ipa, size);

	return (0);
}

static int
dist_write(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{
	struct hypctx *hypctx;
	struct hyp *hyp;
	struct aplic *aplic;
	uint64_t reg;

	hypctx = vcpu_get_cookie(vcpu);
	hyp = hypctx->hyp;
	aplic = hyp->aplic;

	printf("%s: fault_ipa %lx wval %lx size %d\n", __func__,
	    fault_ipa, wval, size);

	/* Ensure that we get here correctly. */
	if (fault_ipa < aplic->dist_start ||
	    fault_ipa + size > aplic->dist_end)
		return (EINVAL);

	reg = fault_ipa - aplic->dist_start;

	printf("Reg %lx\n", reg);

	return (0);
}

static int
redist_read(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{

	printf("%s: fault_ipa %lx size %d\n", __func__,
	    fault_ipa, size);

	return (0);
}

static int
redist_write(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{

	printf("%s: fault_ipa %lx wval %lx size %d\n", __func__,
	    fault_ipa, wval, size);

	return (0);
}

#if 0
static int
aplic_icc_sgi1r_read(struct vcpu *vcpu, uint64_t *rval, void *arg)
{

	printf("%s\n", __func__);

	return (0);  
}

static int
aplic_icc_sgi1r_write(struct vcpu *vcpu, uint64_t rval, void *arg)
{

	printf("%s\n", __func__);

	return (0);  
}
#endif

void
aplic_vminit(struct hyp *hyp)
{
	struct aplic *aplic;

	hyp->aplic = malloc(sizeof(*hyp->aplic), M_APLIC,
	    M_WAITOK | M_ZERO);
	aplic = hyp->aplic;

	mtx_init(&aplic->mtx, "APLIC lock", NULL, MTX_SPIN);
}

int
aplic_attach_to_vm(struct hyp *hyp, struct vm_aplic_descr *descr)
{
	struct vm *vm;
	struct aplic *aplic;

	vm = hyp->vm;

	printf("%s\n", __func__);

	vm_register_inst_handler(vm, descr->v3_regs.dist_start,
	    descr->v3_regs.dist_size, dist_read, dist_write);
	vm_register_inst_handler(vm, descr->v3_regs.redist_start,
	    descr->v3_regs.redist_size, redist_read, redist_write);

#if 0
	vm_register_reg_handler(vm, ISS_MSR_REG(ICC_SGI1R_EL1),
            ISS_MSR_REG_MASK, aplic_icc_sgi1r_read, aplic_icc_sgi1r_write,
            NULL);
#endif

	aplic = hyp->aplic;
	aplic->dist_start = descr->v3_regs.dist_start;
	aplic->dist_end = descr->v3_regs.dist_start + descr->v3_regs.dist_size;

	hyp->aplic_attached = true;

	return (0);
}

int
aplic_inject_irq(struct hyp *hyp, int vcpuid, uint32_t irqid, bool level)
{

	if (irqid != 32) // uart ?
		printf("%s: %d %d\n", __func__, irqid, level);

	return (0);
}
