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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/bus.h>

#include <riscv/vmm/hyp.h>
#include <riscv/vmm/riscv.h>
#include <riscv/vmm/vmm_aplic.h>

#include <machine/vmm_instruction_emul.h>
#include <machine/vmm_dev.h>


static int
dist_read(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{

	printf("%s\n", __func__);

	return (0);
}

static int
dist_write(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{

	printf("%s\n", __func__);

	return (0);
}

static int
redist_read(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{

	printf("%s\n", __func__);

	return (0);
}

static int
redist_write(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{

	printf("%s\n", __func__);

	return (0);
}

#if 0
static int
vgic_v3_icc_sgi1r_read(struct vcpu *vcpu, uint64_t *rval, void *arg)
{

	printf("%s\n", __func__);

	return (0);  
}

static int
vgic_v3_icc_sgi1r_write(struct vcpu *vcpu, uint64_t rval, void *arg)
{

	printf("%s\n", __func__);

	return (0);  
}
#endif

int
vgic_attach_to_vm(struct hyp *hyp, struct vm_vgic_descr *descr)
{
	struct vm *vm;

	vm = hyp->vm;

	printf("%s\n", __func__);

	vm_register_inst_handler(vm, descr->v3_regs.dist_start,
	    descr->v3_regs.dist_size, dist_read, dist_write);
	vm_register_inst_handler(vm, descr->v3_regs.redist_start,
	    descr->v3_regs.redist_size, redist_read, redist_write);

#if 0
	vm_register_reg_handler(vm, ISS_MSR_REG(ICC_SGI1R_EL1),
            ISS_MSR_REG_MASK, vgic_v3_icc_sgi1r_read, vgic_v3_icc_sgi1r_write,
            NULL);
#endif

	hyp->vgic_attached = true;

	return (0);
}

int
vgic_inject_irq(struct hyp *hyp, int vcpuid, uint32_t irqid, bool level)
{

	if (irqid != 32) // uart ?
		printf("%s: %d %d\n", __func__, irqid, level);

	return (0);
}
