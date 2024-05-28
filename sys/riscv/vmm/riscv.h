/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
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
#ifndef _VMM_RISCV_H_
#define _VMM_RISCV_H_

#include <machine/reg.h>
#include <machine/hypervisor.h>
#include <machine/pcpu.h>
#include <machine/vmm.h>

#include "vmm_aplic.h"

struct aplic;

struct hypregs {
	uint64_t hyp_ra;
	uint64_t hyp_sp;
	uint64_t hyp_gp;
	uint64_t hyp_tp;
	uint64_t hyp_t[7];
	uint64_t hyp_s[12];
	uint64_t hyp_a[8];
	uint64_t hyp_sepc;
	uint64_t hyp_sstatus;
	uint64_t hyp_hstatus;
};

struct hypcsr {
	uint64_t hvip;
};

struct hypctx {
	struct hypregs host_regs;
	struct hypregs guest_regs;
	struct hypcsr guest_csrs;
	uint64_t host_sscratch;
	uint64_t host_stvec;
	uint64_t host_scounteren;
	uint64_t guest_scounteren;
	struct hyp *hyp;
	struct vcpu *vcpu;
	bool has_exception;
};

struct hyp {
	struct vm	*vm;
	uint64_t	vmid_generation;
	bool		aplic_attached;
	struct aplic	*aplic;
	struct hypctx	*ctx[];
};

#define	DEFINE_VMMOPS_IFUNC(ret_type, opname, args)			\
	ret_type vmmops_##opname args;

DEFINE_VMMOPS_IFUNC(int, modinit, (int ipinum))
DEFINE_VMMOPS_IFUNC(int, modcleanup, (void))
DEFINE_VMMOPS_IFUNC(void *, init, (struct vm *vm, struct pmap *pmap))
DEFINE_VMMOPS_IFUNC(int, gla2gpa, (void *vcpui, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *is_fault))
DEFINE_VMMOPS_IFUNC(int, run, (void *vcpui, register_t pc, struct pmap *pmap,
    struct vm_eventinfo *info))
DEFINE_VMMOPS_IFUNC(void, cleanup, (void *vmi))
DEFINE_VMMOPS_IFUNC(void *, vcpu_init, (void *vmi, struct vcpu *vcpu,
    int vcpu_id))
DEFINE_VMMOPS_IFUNC(void, vcpu_cleanup, (void *vcpui))
DEFINE_VMMOPS_IFUNC(int, exception, (void *vcpui, uint64_t esr, uint64_t far))
DEFINE_VMMOPS_IFUNC(int, getreg, (void *vcpui, int num, uint64_t *retval))
DEFINE_VMMOPS_IFUNC(int, setreg, (void *vcpui, int num, uint64_t val))
DEFINE_VMMOPS_IFUNC(int, getcap, (void *vcpui, int num, int *retval))
DEFINE_VMMOPS_IFUNC(int, setcap, (void *vcpui, int num, int val))
DEFINE_VMMOPS_IFUNC(struct vmspace *, vmspace_alloc, (vm_offset_t min,
    vm_offset_t max))
DEFINE_VMMOPS_IFUNC(void, vmspace_free, (struct vmspace *vmspace))

uint64_t vmm_call_hyp(struct hypctx *);

#if 0
#define	eprintf(fmt, ...)	printf("%s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
#define	eprintf(fmt, ...)	do {} while(0)
#endif

struct hypctx *riscv_get_active_vcpu(void);
void raise_data_insn_abort(struct hypctx *, uint64_t, bool, int);

int vmm_sbi_ecall(struct vcpu *, bool *);

#endif /* !_VMM_RISCV_H_ */
