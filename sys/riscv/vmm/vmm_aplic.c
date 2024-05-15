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
#include <sys/smp.h>

#include <riscv/vmm/riscv.h>
#include <riscv/vmm/vmm_aplic.h>

#include <machine/vmm_instruction_emul.h>
#include <machine/vmm_dev.h>

MALLOC_DEFINE(M_APLIC, "RISC-V VMM APLIC", "RISC-V AIA APLIC");

#define	APLIC_DOMAINCFG		0x0000
#define	 DOMAINCFG_IE		(1 << 8) /* Interrupt Enable. */
#define	 DOMAINCFG_DM		(1 << 2) /* Direct Mode. */
#define	 DOMAINCFG_BE		(1 << 0) /* Big-Endian. */
#define	APLIC_SOURCECFG(x)	(0x0004 + ((x) - 1) * 4)
#define	 SOURCECFG_D		(1 << 10) /* D - Delegate. */
/* If D == 0. */
#define	 SOURCECFG_SM_S		(0)
#define	 SOURCECFG_SM_M		(0x7 << SOURCECFG_SM_S)
#define	 SOURCECFG_SM_INACTIVE	(0) /* Not delegated. */
#define	 SOURCECFG_SM_DETACHED	(1)
#define	 SOURCECFG_SM_RESERVED	(2)
#define	 SOURCECFG_SM_RESERVED1	(3)
#define	 SOURCECFG_SM_EDGE1	(4) /* Rising edge. */
#define	 SOURCECFG_SM_EDGE0	(5) /* Falling edge. */
#define	 SOURCECFG_SM_LEVEL1	(6) /* High. */
#define	 SOURCECFG_SM_LEVEL0	(7) /* Low. */
/* If D == 1. */
#define	 SOURCECFG_CHILD_INDEX_S	(0)
#define	 SOURCECFG_CHILD_INDEX_M	(0x3ff << SOURCECFG_CHILD_INDEX_S)
#define	APLIC_SETIPNUM		0x1cdc
#define	APLIC_CLRIPNUM		0x1ddc
#define	APLIC_SETIENUM		0x1edc
#define	APLIC_CLRIENUM		0x1fdc
#define	APLIC_GENMSI		0x3000
#define	APLIC_TARGET(x)		(0x3004 + ((x) - 1) * 4)
#define	APLIC_IDC(x)		(0x4000 + (x) * 32)
#define	 IDC_IDELIVERY(x)	(APLIC_IDC(x) + 0x0)
#define	 IDC_IFORCE(x)		(APLIC_IDC(x) + 0x4)
#define	 IDC_ITHRESHOLD(x)	(APLIC_IDC(x) + 0x8)
#define	 IDC_TOPI(x)		(APLIC_IDC(x) + 0x18)
#define	 IDC_CLAIMI(x)		(APLIC_IDC(x) + 0x1C)
#define	   CLAIMI_IRQ_S		(16)
#define	   CLAIMI_IRQ_M		(0x3ff << CLAIMI_IRQ_S)
#define	   CLAIMI_PRIO_S	(0)
#define	   CLAIMI_PRIO_M	(0xff << CLAIMI_PRIO_S)

struct aplic_irq {
	uint32_t sourcecfg;
	uint32_t state;
#define	APLIC_IRQ_STATE_PENDING	(1 << 0)
#define	APLIC_IRQ_STATE_ENABLED	(1 << 1)
	uint32_t target;
};

struct aplic {
	uint32_t dist_start;
	uint32_t dist_end;
	struct mtx mtx;
	struct aplic_irq *irqs;
	int nirqs;
	uint32_t domaincfg;
};

static int
aplic_handle_sourcecfg(struct aplic *aplic, int i, bool write, uint64_t *val)
{
	struct aplic_irq *irq;

	irq = &aplic->irqs[i];
	if (write)
		irq->sourcecfg = *val;
	else
		*val = irq->sourcecfg;

	return (0);
}

static int
aplic_set_enabled(struct aplic *aplic, bool write, uint64_t *val, bool enabled)
{
	struct aplic_irq *irq;
	int i;

	if (!write) {
		*val = 0;
		return (0);
	}

	i = *val;
	if (i <= 0 || i > aplic->nirqs)
		return (-1);

	irq = &aplic->irqs[i];

	if (enabled)
		irq->state |= APLIC_IRQ_STATE_ENABLED;
	else
		irq->state &= ~APLIC_IRQ_STATE_ENABLED;

	return (0);
}

static int
aplic_handle_target(struct aplic *aplic, int i, bool write, uint64_t *val)
{

	printf("%s: i %d\n", __func__, i);

	return (0);
}

static int
aplic_handle_idc_claimi(struct aplic *aplic, int cpu, bool write, uint64_t *val)
{
	struct aplic_irq *irq;
	int i;

	/* Writes to claimi are ignored. */
	if (write)
		return (-1);

	for (i = 0; i < aplic->nirqs; i++) {
		irq = &aplic->irqs[i];
		if (irq->state & APLIC_IRQ_STATE_PENDING) {
			*val = (i << CLAIMI_IRQ_S) | (0 << CLAIMI_PRIO_S);
			irq->state &= ~APLIC_IRQ_STATE_PENDING;
			return (0);
		}
	}

	panic("claimi without pending");

	return (0);
}

static int
aplic_handle_idc(struct aplic *aplic, int cpu, int reg, bool write,
    uint64_t *val)
{
	int error;

	switch (reg + APLIC_IDC(0)) {
	case IDC_IDELIVERY(0):
	case IDC_IFORCE(0):
	case IDC_ITHRESHOLD(0):
	case IDC_TOPI(0):
		error = 0;
		break;
	case IDC_CLAIMI(0):
		error = aplic_handle_idc_claimi(aplic, cpu, write, val);
		break;
	default:
		panic("unknown reg");
	}

	return (error);
}

static int
aplic_mmio_access(struct aplic *aplic, uint64_t reg, bool write, uint64_t *val)
{
	int error;
	int cpu;
	int r;
	int i;

	if ((reg >= APLIC_SOURCECFG(1)) &&
	    (reg <= APLIC_SOURCECFG(aplic->nirqs))) {
		i = ((reg - APLIC_SOURCECFG(1)) >> 2) + 1;
		error = aplic_handle_sourcecfg(aplic, i, write, val);
		return (error);
	}

	if ((reg >= APLIC_TARGET(1)) && (reg <= APLIC_TARGET(aplic->nirqs))) {
		i = (reg - APLIC_TARGET(1)) >> 2;
		error = aplic_handle_target(aplic, i, write, val);
		return (error);
	}

	if ((reg >= APLIC_IDC(0)) && (reg < APLIC_IDC(mp_ncpus))) {
		cpu = (reg - APLIC_IDC(0)) >> 5;
		r = (reg - APLIC_IDC(0)) % 32;
		error = aplic_handle_idc(aplic, cpu, r, write, val);
		return (error);
	}

	switch (reg) {
	case APLIC_DOMAINCFG:
		aplic->domaincfg = *val & DOMAINCFG_IE;
		break;
	case APLIC_SETIENUM:
		aplic_set_enabled(aplic, write, val, true);
		break;
	case APLIC_CLRIENUM:
		aplic_set_enabled(aplic, write, val, false);
		break;
	default:
		panic("unknown reg %lx", reg);
		break;
	};

	return (0);
}

static int
dist_read(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{
	struct hypctx *hypctx;
	struct hyp *hyp;
	struct aplic *aplic;
	uint64_t reg;
	uint64_t val;
	int error;

	hypctx = vcpu_get_cookie(vcpu);
	hyp = hypctx->hyp;
	aplic = hyp->aplic;

#if 0
	printf("%s: fault_ipa %lx size %d\n", __func__, fault_ipa, size);
#endif

	if (fault_ipa < aplic->dist_start || fault_ipa + size > aplic->dist_end)
		return (EINVAL);

	reg = fault_ipa - aplic->dist_start;

	error = aplic_mmio_access(aplic, reg, false, &val);
	if (error == 0)
		*rval = val;

	return (error);
}

static int
dist_write(struct vcpu *vcpu, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{
	struct hypctx *hypctx;
	struct hyp *hyp;
	struct aplic *aplic;
	uint64_t reg;
	uint64_t val;
	int error;

	hypctx = vcpu_get_cookie(vcpu);
	hyp = hypctx->hyp;
	aplic = hyp->aplic;

#if 0
	printf("%s: fault_ipa %lx wval %lx size %d\n", __func__, fault_ipa,
	    wval, size);
#endif

	if (fault_ipa < aplic->dist_start || fault_ipa + size > aplic->dist_end)
		return (EINVAL);

	reg = fault_ipa - aplic->dist_start;

	val = wval;

	error = aplic_mmio_access(aplic, reg, true, &val);

	return (error);
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
	struct aplic *aplic;
	struct vm *vm;

	vm = hyp->vm;

	printf("%s\n", __func__);

	vm_register_inst_handler(vm, descr->v3_regs.dist_start,
	    descr->v3_regs.dist_size, dist_read, dist_write);
	vm_register_inst_handler(vm, descr->v3_regs.redist_start,
	    descr->v3_regs.redist_size, redist_read, redist_write);

	aplic = hyp->aplic;
	aplic->nirqs = 63;
	aplic->dist_start = descr->v3_regs.dist_start;
	aplic->dist_end = descr->v3_regs.dist_start + descr->v3_regs.dist_size;
	aplic->irqs = malloc(sizeof(struct aplic_irq) * aplic->nirqs, M_DEVBUF,
	    M_WAITOK | M_ZERO);

	hyp->aplic_attached = true;

	return (0);
}

int
aplic_check_pending(struct hypctx *hypctx)
{
	struct aplic_irq *irq;
	struct aplic *aplic;
	struct hyp *hyp;
	int i;

	hyp = hypctx->hyp;
	aplic = hyp->aplic;
	if ((aplic->domaincfg & DOMAINCFG_IE) == 0)
		return (0);

	for (i = 0; i < aplic->nirqs; i++) {
		irq = &aplic->irqs[i];
		if (irq->state & APLIC_IRQ_STATE_PENDING)
			return (1);
	}

	return (0);
}

int
aplic_inject_irq(struct hyp *hyp, int vcpuid, uint32_t irqid, bool level)
{
	struct aplic_irq *irq;
	struct aplic *aplic;

	aplic = hyp->aplic;
	if ((aplic->domaincfg & DOMAINCFG_IE) == 0)
		return (0);

	irq = &aplic->irqs[irqid];
	if (irq->sourcecfg & SOURCECFG_D)
		return (0);

	switch (irq->sourcecfg & SOURCECFG_SM_M) {
	case SOURCECFG_SM_EDGE1:
		if (level)
			irq->state |= APLIC_IRQ_STATE_PENDING;
		else
			irq->state &= ~APLIC_IRQ_STATE_PENDING;
		break;
	default:
		break;
	}

	return (0);
}
