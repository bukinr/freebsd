/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/smp.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/rman.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/vmem.h>
#include <sys/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include <machine/riscvreg.h>
#include <machine/vm.h>
#include <machine/cpufunc.h>
#include <machine/cpu.h>
#include <machine/machdep.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/atomic.h>
#include <machine/hypervisor.h>
#include <machine/pmap.h>
#include <machine/intr.h>
#include <machine/encoding.h>
#include <machine/db_machdep.h>

#include "mmu.h"
#include "riscv.h"
#include "hyp.h"
#include "reset.h"
#include "vmm_aplic.h"
#include "io/vtimer.h"
#include "vmm_stat.h"

#define	HANDLED		1
#define	UNHANDLED	0

/* Number of bits in an EL2 virtual address */
#define	EL2_VIRT_BITS	48
CTASSERT((1ul << EL2_VIRT_BITS) >= HYP_VM_MAX_ADDRESS);

/* TODO: Move the host hypctx off the stack */
#define	VMM_STACK_PAGES	4
#define	VMM_STACK_SIZE	(VMM_STACK_PAGES * PAGE_SIZE)

#if 0
static int vmm_pmap_levels, vmm_virt_bits, vmm_max_ipa_bits;
#endif

/* Register values passed to arm_setup_vectors to set in the hypervisor */
struct vmm_init_regs {
	uint64_t tcr_el2;
	uint64_t vtcr_el2;
};

MALLOC_DEFINE(M_HYP, "ARM VMM HYP", "ARM VMM HYP");

#if 0
extern char hyp_init_vectors[];
extern char hyp_vectors[];
extern char hyp_stub_vectors[];

static vm_paddr_t hyp_code_base;
static size_t hyp_code_len;

static char *stack[MAXCPU];
static vm_offset_t stack_hyp_va[MAXCPU];

static vmem_t *el2_mem_alloc;

static void arm_setup_vectors(void *arg);
static void vmm_pmap_clean_stage2_tlbi(void);
static void vmm_pmap_invalidate_range(uint64_t, vm_offset_t, vm_offset_t, bool);
static void vmm_pmap_invalidate_all(uint64_t);
#endif

DPCPU_DEFINE_STATIC(struct hypctx *, vcpu);

static int
m_op(uint32_t insn, int match, int mask)
{

	if (((insn ^ match) & mask) == 0)
		return (1);

	return (0);
}

static inline void
riscv_set_active_vcpu(struct hypctx *hypctx)
{
	DPCPU_SET(vcpu, hypctx);
}

struct hypctx *
riscv_get_active_vcpu(void)
{
	return (DPCPU_GET(vcpu));
}

static void
arm_setup_vectors(void *arg)
{
#if 0
	struct vmm_init_regs *el2_regs;
	uintptr_t stack_top;
	uint32_t sctlr_el2;
	register_t daif;

	el2_regs = arg;
	riscv_set_active_vcpu(NULL);

	daif = intr_disable();

	/*
	 * Install the temporary vectors which will be responsible for
	 * initializing the VMM when we next trap into EL2.
	 *
	 * x0: the exception vector table responsible for hypervisor
	 * initialization on the next call.
	 */
	vmm_call_hyp(vtophys(&vmm_hyp_code));

	/* Create and map the hypervisor stack */
	stack_top = stack_hyp_va[PCPU_GET(cpuid)] + VMM_STACK_SIZE;

	/*
	 * Configure the system control register for EL2:
	 *
	 * SCTLR_EL2_M: MMU on
	 * SCTLR_EL2_C: Data cacheability not affected
	 * SCTLR_EL2_I: Instruction cacheability not affected
	 * SCTLR_EL2_A: Instruction alignment check
	 * SCTLR_EL2_SA: Stack pointer alignment check
	 * SCTLR_EL2_WXN: Treat writable memory as execute never
	 * ~SCTLR_EL2_EE: Data accesses are little-endian
	 */
	sctlr_el2 = SCTLR_EL2_RES1;
	sctlr_el2 |= SCTLR_EL2_M | SCTLR_EL2_C | SCTLR_EL2_I;
	sctlr_el2 |= SCTLR_EL2_A | SCTLR_EL2_SA;
	sctlr_el2 |= SCTLR_EL2_WXN;
	sctlr_el2 &= ~SCTLR_EL2_EE;

	/* Special call to initialize EL2 */
	vmm_call_hyp(vmmpmap_to_ttbr0(), stack_top, el2_regs->tcr_el2,
	    sctlr_el2, el2_regs->vtcr_el2);

	intr_restore(daif);
#endif
}

static void
arm_teardown_vectors(void *arg)
{
#if 0
	register_t daif;

	/*
	 * vmm_cleanup() will disable the MMU. For the next few instructions,
	 * before the hardware disables the MMU, one of the following is
	 * possible:
	 *
	 * a. The instruction addresses are fetched with the MMU disabled,
	 * and they must represent the actual physical addresses. This will work
	 * because we call the vmm_cleanup() function by its physical address.
	 *
	 * b. The instruction addresses are fetched using the old translation
	 * tables. This will work because we have an identity mapping in place
	 * in the translation tables and vmm_cleanup() is called by its physical
	 * address.
	 */
	daif = intr_disable();
	/* TODO: Invalidate the cache */
	vmm_call_hyp(HYP_CLEANUP, vtophys(hyp_stub_vectors));
	intr_restore(daif);

	riscv_set_active_vcpu(NULL);
#endif
}

static uint64_t
vmm_vtcr_el2_sl(u_int levels)
{
#if 0

	switch (levels) {
	case 2:
		return (VTCR_EL2_SL0_4K_LVL2);
	case 3:
		return (VTCR_EL2_SL0_4K_LVL1);
	case 4:
		return (VTCR_EL2_SL0_4K_LVL0);
	default:
		panic("%s: Invalid number of page table levels %u", __func__,
		    levels);
	}
#endif

	return (0);
}

int
vmmops_modinit(int ipinum)
{
#if 0
	struct vmm_init_regs el2_regs;
	vm_offset_t next_hyp_va;
	vm_paddr_t vmm_base;
	uint64_t id_aa64mmfr0_el1, pa_range_bits, pa_range_field;
	uint64_t cnthctl_el2;
	register_t daif;
	int cpu, i;
	bool rv __diagused;
#endif

	if (!virt_enabled()) {
		printf(
		    "vmm: Processor doesn't have support for virtualization\n");
		return (ENXIO);
	}

#if 0
	/* TODO: Support VHE */
	if (in_vhe()) {
		printf("vmm: VHE is unsupported\n");
		return (ENXIO);
	}

	if (!vgic_present()) {
		printf("vmm: No vgic found\n");
		return (ENODEV);
	}

	if (!get_kernel_reg(ID_AA64MMFR0_EL1, &id_aa64mmfr0_el1)) {
		printf("vmm: Unable to read ID_AA64MMFR0_EL1\n");
		return (ENXIO);
	}
	pa_range_field = ID_AA64MMFR0_PARange_VAL(id_aa64mmfr0_el1);
	/*
	 * Use 3 levels to give us up to 39 bits with 4k pages, or
	 * 47 bits with 16k pages.
	 */
	/* TODO: Check the number of levels for 64k pages */
	vmm_pmap_levels = 3;
	switch (pa_range_field) {
	case ID_AA64MMFR0_PARange_4G:
		printf("vmm: Not enough physical address bits\n");
		return (ENXIO);
	case ID_AA64MMFR0_PARange_64G:
		vmm_virt_bits = 36;
		break;
	default:
		vmm_virt_bits = 39;
		break;
	}
	pa_range_bits = pa_range_field >> ID_AA64MMFR0_PARange_SHIFT;

	/* Initialise the EL2 MMU */
	if (!vmmpmap_init()) {
		printf("vmm: Failed to init the EL2 MMU\n");
		return (ENOMEM);
	}

	/* Set up the stage 2 pmap callbacks */
	MPASS(pmap_clean_stage2_tlbi == NULL);
	pmap_clean_stage2_tlbi = vmm_pmap_clean_stage2_tlbi;
	pmap_stage2_invalidate_range = vmm_pmap_invalidate_range;
	pmap_stage2_invalidate_all = vmm_pmap_invalidate_all;

	/*
	 * Create an allocator for the virtual address space used by EL2.
	 * EL2 code is identity-mapped; the allocator is used to find space for
	 * VM structures.
	 */
	el2_mem_alloc = vmem_create("VMM EL2", 0, 0, PAGE_SIZE, 0, M_WAITOK);

	/* Create the mappings for the hypervisor translation table. */
	hyp_code_len = round_page(&vmm_hyp_code_end - &vmm_hyp_code);

	/* We need an physical identity mapping for when we activate the MMU */
	hyp_code_base = vmm_base = vtophys(&vmm_hyp_code);
	rv = vmmpmap_enter(vmm_base, hyp_code_len, vmm_base,
	    VM_PROT_READ | VM_PROT_EXECUTE);
	MPASS(rv);

	next_hyp_va = roundup2(vmm_base + hyp_code_len, L2_SIZE);

	/* Create a per-CPU hypervisor stack */
	CPU_FOREACH(cpu) {
		stack[cpu] = malloc(VMM_STACK_SIZE, M_HYP, M_WAITOK | M_ZERO);
		stack_hyp_va[cpu] = next_hyp_va;

		for (i = 0; i < VMM_STACK_PAGES; i++) {
			rv = vmmpmap_enter(stack_hyp_va[cpu] + ptoa(i),
			    PAGE_SIZE, vtophys(stack[cpu] + ptoa(i)),
			    VM_PROT_READ | VM_PROT_WRITE);
			MPASS(rv);
		}
		next_hyp_va += L2_SIZE;
	}

	el2_regs.tcr_el2 = TCR_EL2_RES1;
	el2_regs.tcr_el2 |= min(pa_range_bits << TCR_EL2_PS_SHIFT,
	    TCR_EL2_PS_52BITS);
	el2_regs.tcr_el2 |= TCR_EL2_T0SZ(64 - EL2_VIRT_BITS);
	el2_regs.tcr_el2 |= TCR_EL2_IRGN0_WBWA | TCR_EL2_ORGN0_WBWA;
	el2_regs.tcr_el2 |= TCR_EL2_TG0_4K;
#ifdef SMP
	el2_regs.tcr_el2 |= TCR_EL2_SH0_IS;
#endif

	switch (el2_regs.tcr_el2 & TCR_EL2_PS_MASK) {
	case TCR_EL2_PS_32BITS:
		vmm_max_ipa_bits = 32;
		break;
	case TCR_EL2_PS_36BITS:
		vmm_max_ipa_bits = 36;
		break;
	case TCR_EL2_PS_40BITS:
		vmm_max_ipa_bits = 40;
		break;
	case TCR_EL2_PS_42BITS:
		vmm_max_ipa_bits = 42;
		break;
	case TCR_EL2_PS_44BITS:
		vmm_max_ipa_bits = 44;
		break;
	case TCR_EL2_PS_48BITS:
		vmm_max_ipa_bits = 48;
		break;
	case TCR_EL2_PS_52BITS:
	default:
		vmm_max_ipa_bits = 52;
		break;
	}

	/*
	 * Configure the Stage 2 translation control register:
	 *
	 * VTCR_IRGN0_WBWA: Translation table walks access inner cacheable
	 * normal memory
	 * VTCR_ORGN0_WBWA: Translation table walks access outer cacheable
	 * normal memory
	 * VTCR_EL2_TG0_4K/16K: Stage 2 uses the same page size as the kernel
	 * VTCR_EL2_SL0_4K_LVL1: Stage 2 uses concatenated level 1 tables
	 * VTCR_EL2_SH0_IS: Memory associated with Stage 2 walks is inner
	 * shareable
	 */
	el2_regs.vtcr_el2 = VTCR_EL2_RES1;
	el2_regs.vtcr_el2 |=
	    min(pa_range_bits << VTCR_EL2_PS_SHIFT, VTCR_EL2_PS_48BIT);
	el2_regs.vtcr_el2 |= VTCR_EL2_IRGN0_WBWA | VTCR_EL2_ORGN0_WBWA;
	el2_regs.vtcr_el2 |= VTCR_EL2_T0SZ(64 - vmm_virt_bits);
	el2_regs.vtcr_el2 |= vmm_vtcr_el2_sl(vmm_pmap_levels);
	el2_regs.vtcr_el2 |= VTCR_EL2_TG0_4K;
#ifdef SMP
	el2_regs.vtcr_el2 |= VTCR_EL2_SH0_IS;
#endif

	smp_rendezvous(NULL, arm_setup_vectors, NULL, &el2_regs);

	printf("vmm_base %lx, l2_size %lx\n", vmm_base, L2_SIZE);

	/* Add memory to the vmem allocator (checking there is space) */
	if (vmm_base > (L2_SIZE + PAGE_SIZE)) {
		/*
		 * Ensure there is an L2 block before the vmm code to check
		 * for buffer overflows on earlier data. Include the PAGE_SIZE
		 * of the minimum we can allocate.
		 */
		vmm_base -= L2_SIZE + PAGE_SIZE;
		vmm_base = rounddown2(vmm_base, L2_SIZE);

		/*
		 * Check there is memory before the vmm code to add.
		 *
		 * Reserve the L2 block at address 0 so NULL dereference will
		 * raise an exception.
		 */
		if (vmm_base > L2_SIZE)
			vmem_add(el2_mem_alloc, L2_SIZE, vmm_base - L2_SIZE,
			    M_WAITOK);
	}

	/*
	 * Add the memory after the stacks. There is most of an L2 block
	 * between the last stack and the first allocation so this should
	 * be safe without adding more padding.
	 */
	if (next_hyp_va < HYP_VM_MAX_ADDRESS - PAGE_SIZE)
		vmem_add(el2_mem_alloc, next_hyp_va,
		    HYP_VM_MAX_ADDRESS - next_hyp_va, M_WAITOK);

	daif = intr_disable();
	cnthctl_el2 = vmm_call_hyp(HYP_READ_REGISTER, HYP_REG_CNTHCTL);
	intr_restore(daif);

	vgic_init();
	vtimer_init(cnthctl_el2);
#endif

	return (0);
}

int
vmmops_modcleanup(void)
{
#if 0
	int cpu;

	smp_rendezvous(NULL, arm_teardown_vectors, NULL, NULL);

	CPU_FOREACH(cpu) {
		vmmpmap_remove(stack_hyp_va[cpu], VMM_STACK_PAGES * PAGE_SIZE,
		    false);
	}

	vmmpmap_remove(hyp_code_base, hyp_code_len, false);

	vtimer_cleanup();

	vmmpmap_fini();

	CPU_FOREACH(cpu)
		free(stack[cpu], M_HYP);

	pmap_clean_stage2_tlbi = NULL;
	pmap_stage2_invalidate_range = NULL;
	pmap_stage2_invalidate_all = NULL;

#endif
	return (0);
}

static vm_size_t
el2_hyp_size(struct vm *vm)
{
	return (round_page(sizeof(struct hyp) +
	    sizeof(struct hypctx *) * vm_get_maxcpus(vm)));
}

static vm_size_t
el2_hypctx_size(void)
{
	return (round_page(sizeof(struct hypctx)));
}

#if 0
static vm_offset_t
el2_map_enter(vm_offset_t data, vm_size_t size, vm_prot_t prot)
{
	vmem_addr_t addr;
	int err __diagused;
	bool rv __diagused;

	err = vmem_alloc(el2_mem_alloc, size, M_NEXTFIT | M_WAITOK, &addr);
	MPASS(err == 0);
	rv = vmmpmap_enter(addr, size, vtophys(data), prot);
	MPASS(rv);

	return (addr);
}
#endif

void *
vmmops_init(struct vm *vm, pmap_t pmap)
{
	struct hyp *hyp;
	vm_size_t size;

printf("%s\n", __func__);
	size = el2_hyp_size(vm);
printf("%s size %ld\n", __func__, size);
	hyp = malloc_aligned(size, PAGE_SIZE, M_HYP, M_WAITOK | M_ZERO);
printf("%s hyp %p\n", __func__, hyp);

	hyp->vm = vm;
	hyp->aplic_attached = false;

#if 0
	vtimer_vminit(hyp);
#endif
	aplic_vminit(hyp);

#if 0
	hyp->el2_addr = el2_map_enter((vm_offset_t)hyp, size,
	    VM_PROT_READ | VM_PROT_WRITE);

	printf("%s el2_addr %lx\n", __func__, hyp->el2_addr);
#endif

	return (hyp);
}

void *
vmmops_vcpu_init(void *vmi, struct vcpu *vcpu1, int vcpuid)
{
	struct hyp *hyp = vmi;
	struct hypctx *hypctx;
	vm_size_t size;

	size = el2_hypctx_size();
	hypctx = malloc_aligned(size, PAGE_SIZE, M_HYP, M_WAITOK | M_ZERO);

	KASSERT(vcpuid >= 0 && vcpuid < vm_get_maxcpus(hyp->vm),
	    ("%s: Invalid vcpuid %d", __func__, vcpuid));
	hyp->ctx[vcpuid] = hypctx;

	hypctx->hyp = hyp;
	hypctx->vcpu = vcpu1;

	reset_vm_el01_regs(hypctx);
	reset_vm_el2_regs(hypctx);

#if 0
	vtimer_cpuinit(hypctx);
	vgic_cpuinit(hypctx);

	hypctx->el2_addr = el2_map_enter((vm_offset_t)hypctx, size,
	    VM_PROT_READ | VM_PROT_WRITE);
#endif

//printf("%s hypctx->el2_addr %lx\n", __func__, hypctx->el2_addr);

	uint64_t henvcfg;
	uint64_t hedeleg;
	uint64_t hideleg;

	hedeleg  = (1UL << SCAUSE_INST_MISALIGNED);
	hedeleg |= (1UL << SCAUSE_BREAKPOINT);
	hedeleg |= (1UL << SCAUSE_ECALL_USER);
	hedeleg |= (1UL << SCAUSE_INST_PAGE_FAULT);
	hedeleg |= (1UL << SCAUSE_LOAD_PAGE_FAULT);
	hedeleg |= (1UL << SCAUSE_STORE_PAGE_FAULT);
	csr_write(hedeleg, hedeleg);

	hideleg  = (1 << IRQ_SOFTWARE_HYPERVISOR);
	hideleg |= (1 << IRQ_TIMER_HYPERVISOR);
	hideleg |= (1 << IRQ_EXTERNAL_HYPERVISOR);
	csr_write(hideleg, hideleg);

/* xENVCFG flags */
#define ENVCFG_STCE                     (1ULL << 63)
#define ENVCFG_PBMTE                    (1ULL << 62)

	henvcfg = ENVCFG_STCE | ENVCFG_PBMTE;
	csr_write(henvcfg, henvcfg);

	/* TODO: should we trap rdcycle / rdtime ? */
	csr_write(hcounteren, 0x1 | 0x2 /* rdtime */);
	hypctx->guest_scounteren = 0x1 | 0x2; /* rdtime */
	csr_write(hie, (1 << 10) | (1 << 12));

#if 1
	hypctx->guest_regs.hyp_sstatus = SSTATUS_SPP | SSTATUS_SPIE;
	hypctx->guest_regs.hyp_sstatus |= SSTATUS_FS_INITIAL;

	uint64_t hstatus;
	hstatus = 0;
	hstatus |= (1 << 7); //SPV
	/* Allow WFI for now. */
	//hstatus |= (1 << 21); //VTW
	hypctx->guest_regs.hyp_hstatus = hstatus;
#endif

	return (hypctx);
}

static int
riscv_vmm_pinit(pmap_t pmap)
{

#if 0
	pmap_pinit_stage(pmap, PM_STAGE2, vmm_pmap_levels);
#endif

	pmap_pinit(pmap);

	return (1);
}

struct vmspace *
vmmops_vmspace_alloc(vm_offset_t min, vm_offset_t max)
{

	return (vmspace_alloc(min, max, riscv_vmm_pinit));
}

void
vmmops_vmspace_free(struct vmspace *vmspace)
{

	pmap_remove_pages(vmspace_pmap(vmspace));
	vmspace_free(vmspace);
}

static void
vmm_pmap_clean_stage2_tlbi(void)
{
#if 0
	vmm_call_hyp(HYP_CLEAN_S2_TLBI);
#endif
}

static void
vmm_pmap_invalidate_range(uint64_t vttbr, vm_offset_t sva, vm_offset_t eva,
    bool final_only)
{
#if 0
	MPASS(eva > sva);
	vmm_call_hyp(HYP_S2_TLBI_RANGE, vttbr, sva, eva, final_only);
#endif
}

static void
vmm_pmap_invalidate_all(uint64_t vttbr)
{
#if 0
	vmm_call_hyp(HYP_S2_TLBI_ALL, vttbr);
#endif
}

static inline void
arm64_print_hyp_regs(struct vm_exit *vme)
{
#if 0
	printf("esr_el2:   0x%016lx\n", vme->u.hyp.esr_el2);
	printf("far_el2:   0x%016lx\n", vme->u.hyp.far_el2);
	printf("hpfar_el2: 0x%016lx\n", vme->u.hyp.hpfar_el2);
	printf("elr_el2:   0x%016lx\n", vme->pc);
#endif
}

static void
riscv_gen_inst_emul_data(struct hypctx *hypctx, uint32_t esr_iss,
    struct vm_exit *vme_ret)
{
#if 0
	struct vm_guest_paging *paging;
	struct vie *vie;
	uint32_t esr_sas, reg_num;

	/*
	 * Get the page address from HPFAR_EL2.
	 */
	vme_ret->u.inst_emul.gpa =
	    HPFAR_EL2_FIPA_ADDR(hypctx->exit_info.hpfar_el2);
	/* Bits [11:0] are the same as bits [11:0] from the virtual address. */
	vme_ret->u.inst_emul.gpa += hypctx->exit_info.far_el2 &
	    FAR_EL2_HPFAR_PAGE_MASK;

	esr_sas = (esr_iss & ISS_DATA_SAS_MASK) >> ISS_DATA_SAS_SHIFT;
	reg_num = (esr_iss & ISS_DATA_SRT_MASK) >> ISS_DATA_SRT_SHIFT;

	vie = &vme_ret->u.inst_emul.vie;
	vie->access_size = 1 << esr_sas;
	vie->sign_extend = (esr_iss & ISS_DATA_SSE) ? 1 : 0;
	vie->dir = (esr_iss & ISS_DATA_WnR) ? VM_DIR_WRITE : VM_DIR_READ;
	vie->reg = reg_num;

	paging = &vme_ret->u.inst_emul.paging;
	paging->ttbr0_addr = hypctx->ttbr0_el1 & ~(TTBR_ASID_MASK | TTBR_CnP);
	paging->ttbr1_addr = hypctx->ttbr1_el1 & ~(TTBR_ASID_MASK | TTBR_CnP);
	paging->tcr_el1 = hypctx->tcr_el1;
	paging->tcr2_el1 = hypctx->tcr2_el1;
	paging->flags = hypctx->tf.tf_spsr & (PSR_M_MASK | PSR_M_32);
	if ((hypctx->sctlr_el1 & SCTLR_M) != 0)
		paging->flags |= VM_GP_MMU_ENABLED;
#else
	struct vie *vie;

	vme_ret->u.inst_emul.gpa = (vme_ret->htval << 2) |
	    (vme_ret->stval & 0x3);

	uint64_t guest_addr;
	uint64_t old_hstatus;
	//uint64_t old_stvec;

	guest_addr = vme_ret->sepc;

	old_hstatus = csr_swap(hstatus, hypctx->guest_regs.hyp_hstatus);
	//old_stvec = csr_swap(stvec, hypctx->guest_regs.hyp_stvec);

#if 0
	if (vme_ret->u.inst_emul.gpa >= 0x11000)
		printf("htval %lx stval %lx sepc %lx\n",
		    vme_ret->htval, vme_ret->stval, vme_ret->sepc);
#endif

	vie = &vme_ret->u.inst_emul.vie;
	vie->dir = vme_ret->scause == SCAUSE_STORE_GUEST_PAGE_FAULT ? \
	    VM_DIR_WRITE : VM_DIR_READ;

	uint64_t insn;
	uint64_t val1;
	int reg_num;
	int rs2, rd;

	__asm __volatile(".option push\n"
			 ".option norvc\n"
			"hlvx.hu %[insn], (%[addr])\n"
			".option pop\n"
	    : [insn] "=&r" (insn), [addr] "+&r" (guest_addr)
	    :: "memory");

	vie->sign_extend = 1;

	if ((insn & 0x3) == 0x3) {
		guest_addr += 2;
		__asm __volatile(".option push\n"
				 ".option norvc\n"
				"hlvx.hu %[val1], (%[addr])\n"
				".option pop\n"
		    : [val1] "=&r" (val1), [addr] "+&r" (guest_addr)
		    :: "memory");
		insn |= (val1 << 16);

		//rs1 = (insn & RS1_MASK) >> RS1_SHIFT;
		rs2 = (insn & RS2_MASK) >> RS2_SHIFT;
		rd = (insn & RD_MASK) >> RD_SHIFT;

		if (vie->dir == VM_DIR_WRITE) {
			if (m_op(insn, MATCH_SB, MASK_SB))
				vie->access_size = 1;
			else if (m_op(insn, MATCH_SH, MASK_SH))
				vie->access_size = 2;
			else if (m_op(insn, MATCH_SW, MASK_SW))
				vie->access_size = 4;
			else if (m_op(insn, MATCH_SD, MASK_SD))
				vie->access_size = 8;
			else
				panic("unknown store instr at %lx", guest_addr);
			reg_num = rs2;
		} else {
			if (m_op(insn, MATCH_LB, MASK_LB))
				vie->access_size = 1;
			else if (m_op(insn, MATCH_LH, MASK_LH))
				vie->access_size = 2;
			else if (m_op(insn, MATCH_LW, MASK_LW))
				vie->access_size = 4;
			else if (m_op(insn, MATCH_LD, MASK_LD))
				vie->access_size = 8;
			else if (m_op(insn, MATCH_LBU, MASK_LBU)) {
				vie->access_size = 1;
				vie->sign_extend = 0;
			} else if (m_op(insn, MATCH_LHU, MASK_LHU)) {
				vie->access_size = 2;
				vie->sign_extend = 0;
			} else if (m_op(insn, MATCH_LWU, MASK_LWU)) {
				vie->access_size = 4;
				vie->sign_extend = 0;
			} else
				panic("unknown load instr at %lx", guest_addr);
			reg_num = rd;
		}
		vme_ret->inst_length = 4;
	} else {
		rs2 = (insn >> 7) & 0x7;
		rs2 += 0x8;
		rd = (insn >> 2) & 0x7;
		rd += 0x8;

		if (vie->dir == VM_DIR_WRITE) {
			if (m_op(insn, MATCH_C_SW, MASK_C_SW))
				vie->access_size = 4;
			else if (m_op(insn, MATCH_C_SD, MASK_C_SD))
				vie->access_size = 8;
			else
				panic("unknown store instr at %lx", guest_addr);
		} else  {
			if (m_op(insn, MATCH_C_LW, MASK_C_LW))
				vie->access_size = 4;
			else if (m_op(insn, MATCH_C_LD, MASK_C_LD))
				vie->access_size = 8;
			else
				panic("unknown load instr at %lx", guest_addr);
		}
		reg_num = rd;
		vme_ret->inst_length = 2;
	}

#if 0
	printf("guest_addr %lx insn %lx, reg %d\n", guest_addr, insn, reg_num);
#endif

	csr_write(hstatus, old_hstatus);
	//csr_write(stvec, old_stvec);
	vie->reg = reg_num;
#endif
}

static void
arm64_gen_reg_emul_data(uint32_t esr_iss, struct vm_exit *vme_ret)
{
#if 0
	uint32_t reg_num;
	struct vre *vre;

	/* u.hyp member will be replaced by u.reg_emul */
	vre = &vme_ret->u.reg_emul.vre;

	vre->inst_syndrome = esr_iss;
	/* ARMv8 Architecture Manual, p. D7-2273: 1 means read */
	vre->dir = (esr_iss & ISS_MSR_DIR) ? VM_DIR_READ : VM_DIR_WRITE;
	reg_num = ISS_MSR_Rt(esr_iss);
	vre->reg = reg_num;
#endif
}

void
raise_data_insn_abort(struct hypctx *hypctx, uint64_t far, bool dabort, int fsc)
{
#if 0
	uint64_t esr;

	if ((hypctx->tf.tf_spsr & PSR_M_MASK) == PSR_M_EL0t)
		esr = EXCP_INSN_ABORT_L << ESR_ELx_EC_SHIFT;
	else
		esr = EXCP_INSN_ABORT << ESR_ELx_EC_SHIFT;
	/* Set the bit that changes from insn -> data abort */
	if (dabort)
		esr |= EXCP_DATA_ABORT_L << ESR_ELx_EC_SHIFT;
	/* Set the IL bit if set by hardware */
	esr |= hypctx->tf.tf_esr & ESR_ELx_IL;

	vmmops_exception(hypctx, esr | fsc, far);
#endif
}

static int
handle_el1_sync_excp(struct hypctx *hypctx, struct vm_exit *vme_ret,
    pmap_t pmap)
{
#if 0
	uint64_t gpa;
	uint32_t esr_ec, esr_iss;

	esr_ec = ESR_ELx_EXCEPTION(hypctx->tf.tf_esr);
	esr_iss = hypctx->tf.tf_esr & ESR_ELx_ISS_MASK;

	switch (esr_ec) {
	case EXCP_UNKNOWN:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_UNKNOWN, 1);
		arm64_print_hyp_regs(vme_ret);
		vme_ret->exitcode = VM_EXITCODE_HYP;
		break;
	case EXCP_TRAP_WFI_WFE:
		if ((hypctx->tf.tf_esr & 0x3) == 0) { /* WFI */
			vmm_stat_incr(hypctx->vcpu, VMEXIT_WFI, 1);
			vme_ret->exitcode = VM_EXITCODE_WFI;
		} else {
			vmm_stat_incr(hypctx->vcpu, VMEXIT_WFE, 1);
			vme_ret->exitcode = VM_EXITCODE_HYP;
		}
		break;
	case EXCP_HVC:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_HVC, 1);
		vme_ret->exitcode = VM_EXITCODE_HVC;
		break;
	case EXCP_MSR:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_MSR, 1);
		arm64_gen_reg_emul_data(esr_iss, vme_ret);
		vme_ret->exitcode = VM_EXITCODE_REG_EMUL;
		break;

	case EXCP_INSN_ABORT_L:
	case EXCP_DATA_ABORT_L:
		vmm_stat_incr(hypctx->vcpu, esr_ec == EXCP_DATA_ABORT_L ?
		    VMEXIT_DATA_ABORT : VMEXIT_INSN_ABORT, 1);
		switch (hypctx->tf.tf_esr & ISS_DATA_DFSC_MASK) {
		case ISS_DATA_DFSC_TF_L0:
		case ISS_DATA_DFSC_TF_L1:
		case ISS_DATA_DFSC_TF_L2:
		case ISS_DATA_DFSC_TF_L3:
		case ISS_DATA_DFSC_AFF_L1:
		case ISS_DATA_DFSC_AFF_L2:
		case ISS_DATA_DFSC_AFF_L3:
		case ISS_DATA_DFSC_PF_L1:
		case ISS_DATA_DFSC_PF_L2:
		case ISS_DATA_DFSC_PF_L3:
			gpa = HPFAR_EL2_FIPA_ADDR(hypctx->exit_info.hpfar_el2);
			/* Check the IPA is valid */
			if (gpa >= (1ul << vmm_max_ipa_bits)) {
				raise_data_insn_abort(hypctx,
				    hypctx->exit_info.far_el2,
				    esr_ec == EXCP_DATA_ABORT_L,
				    ISS_DATA_DFSC_ASF_L0);
				vme_ret->inst_length = 0;
				return (HANDLED);
			}

			if (vm_mem_allocated(hypctx->vcpu, gpa)) {
				vme_ret->exitcode = VM_EXITCODE_PAGING;
				vme_ret->inst_length = 0;
				vme_ret->u.paging.esr = hypctx->tf.tf_esr;
				vme_ret->u.paging.gpa = gpa;
			} else if (esr_ec == EXCP_INSN_ABORT_L) {
				/*
				 * Raise an external abort. Device memory is
				 * not executable
				 */
				raise_data_insn_abort(hypctx,
				    hypctx->exit_info.far_el2, false,
				    ISS_DATA_DFSC_EXT);
				vme_ret->inst_length = 0;
				return (HANDLED);
			} else {
				arm64_gen_inst_emul_data(hypctx, esr_iss,
				    vme_ret);
				vme_ret->exitcode = VM_EXITCODE_INST_EMUL;
			}
			break;
		default:
			arm64_print_hyp_regs(vme_ret);
			vme_ret->exitcode = VM_EXITCODE_HYP;
			break;
		}

		break;

	default:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_UNHANDLED_SYNC, 1);
		arm64_print_hyp_regs(vme_ret);
		vme_ret->exitcode = VM_EXITCODE_HYP;
		break;
	}
#endif

	/* We don't don't do any instruction emulation here */
	return (UNHANDLED);
}

static int
riscv_handle_world_switch(struct hypctx *hypctx, int excp_type,
    struct vm_exit *vme, pmap_t pmap)
{
	uint64_t gpa;
	int handled;

#if 0
	switch (excp_type) {
	case EXCP_TYPE_EL1_SYNC:
		/* The exit code will be set by handle_el1_sync_excp(). */
		handled = handle_el1_sync_excp(hypctx, vme, pmap);
		break;

	case EXCP_TYPE_EL1_IRQ:
	case EXCP_TYPE_EL1_FIQ:
		/* The host kernel will handle IRQs and FIQs. */
		vmm_stat_incr(hypctx->vcpu,
		    excp_type == EXCP_TYPE_EL1_IRQ ? VMEXIT_IRQ : VMEXIT_FIQ,1);
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;

	case EXCP_TYPE_EL1_ERROR:
	case EXCP_TYPE_EL2_SYNC:
	case EXCP_TYPE_EL2_IRQ:
	case EXCP_TYPE_EL2_FIQ:
	case EXCP_TYPE_EL2_ERROR:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_UNHANDLED_EL2, 1);
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;

	default:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_UNHANDLED, 1);
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;
	}
#endif

	uint64_t insn;
	handled = UNHANDLED;

	switch (vme->scause) {
	case SCAUSE_FETCH_GUEST_PAGE_FAULT:
	case SCAUSE_LOAD_GUEST_PAGE_FAULT:
	case SCAUSE_STORE_GUEST_PAGE_FAULT:

		gpa = (vme->htval << 2) | (vme->stval & 0x3);
#if 0
		/* Check the IPA is valid */
		if (gpa >= (1ul << vmm_max_ipa_bits)) {
			raise_data_insn_abort(hypctx,
			    hypctx->exit_info.far_el2,
			    esr_ec == EXCP_DATA_ABORT_L,
			    ISS_DATA_DFSC_ASF_L0);
			vme_ret->inst_length = 0;
			return (HANDLED);
		}
#endif

		if (vm_mem_allocated(hypctx->vcpu, gpa)) {
			vme->exitcode = VM_EXITCODE_PAGING;
			vme->inst_length = 0;
#if 0
			vme->u.paging.esr = hypctx->tf.tf_esr;
#endif
			vme->u.paging.gpa = gpa;
#if 0
		} else if (esr_ec == EXCP_INSN_ABORT_L) {
			/*
			 * Raise an external abort. Device memory is
			 * not executable
			 */
			raise_data_insn_abort(hypctx,
			    hypctx->exit_info.far_el2, false,
			    ISS_DATA_DFSC_EXT);
			vme->inst_length = 0;
			return (HANDLED);
#endif
		} else {
			riscv_gen_inst_emul_data(hypctx, 0 /*esr_iss*/, vme);
			vme->exitcode = VM_EXITCODE_INST_EMUL;
		}
		break;
	case SCAUSE_ILLEGAL_INSTRUCTION:
#if 0
		printf("%s: Illegal instruction at %lx stval 0x%lx htval 0x%lx\n",
		    __func__, vme->sepc, vme->stval, vme->htval);
#endif

		//old_hstatus = csr_swap(hstatus, hypctx->guest_regs.hyp_hstatus);
		__asm __volatile(".option push\n"
				 ".option norvc\n"
				"hlvx.hu %[insn], (%[addr])\n"
				".option pop\n"
		    : [insn] "=&r" (insn), [addr] "+&r" (vme->sepc)
		    :: "memory");

		//printf("insn %lx\n", insn);
		//print_instr(insn);
		csr_write(vsstatus, SSTATUS_FS_INITIAL);
		//panic("handle me");
		handled = HANDLED;
		break;
	case SCAUSE_VIRTUAL_SUPERVISOR_ECALL:
		vme->exitcode = VM_EXITCODE_ECALL;
		handled = UNHANDLED;
		break;
	case SCAUSE_VIRTUAL_INSTRUCTION:
	default:
		vmm_stat_incr(hypctx->vcpu, VMEXIT_UNHANDLED, 1);
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;
	}

	return (handled);
}

static void
ptp_release(void **cookie)
{
	if (*cookie != NULL) {
		vm_gpa_release(*cookie);
		*cookie = NULL;
	}
}

static void *
ptp_hold(struct vcpu *vcpu, vm_paddr_t ptpphys, size_t len, void **cookie)
{
	void *ptr;

	ptp_release(cookie);
	ptr = vm_gpa_hold(vcpu, ptpphys, len, VM_PROT_RW, cookie);
	return (ptr);
}

/* log2 of the number of bytes in a page table entry */
#define	PTE_SHIFT	3
int
vmmops_gla2gpa(void *vcpui, struct vm_guest_paging *paging, uint64_t gla,
    int prot, uint64_t *gpa, int *is_fault)
{

	printf("%s: %lx\n", __func__, gla);
	panic("implement me");

#if 0
	struct hypctx *hypctx;
	void *cookie;
	uint64_t mask, *ptep, pte, pte_addr;
	int address_bits, granule_shift, ia_bits, levels, pte_shift, tsz;
	bool is_el0;

	/* Check if the MMU is off */
	if ((paging->flags & VM_GP_MMU_ENABLED) == 0) {
		*is_fault = 0;
		*gpa = gla;
		return (0);
	}

	is_el0 = (paging->flags & PSR_M_MASK) == PSR_M_EL0t;

	if (ADDR_IS_KERNEL(gla)) {
		/* If address translation is disabled raise an exception */
		if ((paging->tcr_el1 & TCR_EPD1) != 0) {
			*is_fault = 1;
			return (0);
		}
		if (is_el0 && (paging->tcr_el1 & TCR_E0PD1) != 0) {
			*is_fault = 1;
			return (0);
		}
		pte_addr = paging->ttbr1_addr;
		tsz = (paging->tcr_el1 & TCR_T1SZ_MASK) >> TCR_T1SZ_SHIFT;
		/* Clear the top byte if TBI is on */
		if ((paging->tcr_el1 & TCR_TBI1) != 0)
			gla |= (0xfful << 56);
		switch (paging->tcr_el1 & TCR_TG1_MASK) {
		case TCR_TG1_4K:
			granule_shift = PAGE_SHIFT_4K;
			break;
		case TCR_TG1_16K:
			granule_shift = PAGE_SHIFT_16K;
			break;
		case TCR_TG1_64K:
			granule_shift = PAGE_SHIFT_64K;
			break;
		default:
			*is_fault = 1;
			return (EINVAL);
		}
	} else {
		/* If address translation is disabled raise an exception */
		if ((paging->tcr_el1 & TCR_EPD0) != 0) {
			*is_fault = 1;
			return (0);
		}
		if (is_el0 && (paging->tcr_el1 & TCR_E0PD0) != 0) {
			*is_fault = 1;
			return (0);
		}
		pte_addr = paging->ttbr0_addr;
		tsz = (paging->tcr_el1 & TCR_T0SZ_MASK) >> TCR_T0SZ_SHIFT;
		/* Clear the top byte if TBI is on */
		if ((paging->tcr_el1 & TCR_TBI0) != 0)
			gla &= ~(0xfful << 56);
		switch (paging->tcr_el1 & TCR_TG0_MASK) {
		case TCR_TG0_4K:
			granule_shift = PAGE_SHIFT_4K;
			break;
		case TCR_TG0_16K:
			granule_shift = PAGE_SHIFT_16K;
			break;
		case TCR_TG0_64K:
			granule_shift = PAGE_SHIFT_64K;
			break;
		default:
			*is_fault = 1;
			return (EINVAL);
		}
	}

	/*
	 * TODO: Support FEAT_TTST for smaller tsz values and FEAT_LPA2
	 * for larger values.
	 */
	switch (granule_shift) {
	case PAGE_SHIFT_4K:
	case PAGE_SHIFT_16K:
		/*
		 * See "Table D8-11 4KB granule, determining stage 1 initial
		 * lookup level" and "Table D8-21 16KB granule, determining
		 * stage 1 initial lookup level" from the "Arm Architecture
		 * Reference Manual for A-Profile architecture" revision I.a
		 * for the minimum and maximum values.
		 *
		 * TODO: Support less than 16 when FEAT_LPA2 is implemented
		 * and TCR_EL1.DS == 1
		 * TODO: Support more than 39 when FEAT_TTST is implemented
		 */
		if (tsz < 16 || tsz > 39) {
			*is_fault = 1;
			return (EINVAL);
		}
		break;
	case PAGE_SHIFT_64K:
	/* TODO: Support 64k granule. It will probably work, but is untested */
	default:
		*is_fault = 1;
		return (EINVAL);
	}

	/*
	 * Calculate the input address bits. These are 64 bit in an address
	 * with the top tsz bits being all 0 or all 1.
	  */
	ia_bits = 64 - tsz;

	/*
	 * Calculate the number of address bits used in the page table
	 * calculation. This is ia_bits minus the bottom granule_shift
	 * bits that are passed to the output address.
	 */
	address_bits = ia_bits - granule_shift;

	/*
	 * Calculate the number of levels. Each level uses
	 * granule_shift - PTE_SHIFT bits of the input address.
	 * This is because the table is 1 << granule_shift and each
	 * entry is 1 << PTE_SHIFT bytes.
	 */
	levels = howmany(address_bits, granule_shift - PTE_SHIFT);

	/* Mask of the upper unused bits in the virtual address */
	gla &= (1ul << ia_bits) - 1;
	hypctx = (struct hypctx *)vcpui;
	cookie = NULL;
	/* TODO: Check if the level supports block descriptors */
	for (;levels > 0; levels--) {
		int idx;

		pte_shift = (levels - 1) * (granule_shift - PTE_SHIFT) +
		    granule_shift;
		idx = (gla >> pte_shift) &
		    ((1ul << (granule_shift - PTE_SHIFT)) - 1);
		while (idx > PAGE_SIZE / sizeof(pte)) {
			idx -= PAGE_SIZE / sizeof(pte);
			pte_addr += PAGE_SIZE;
		}

		ptep = ptp_hold(hypctx->vcpu, pte_addr, PAGE_SIZE, &cookie);
		if (ptep == NULL)
			goto error;
		pte = ptep[idx];

		/* Calculate the level we are looking at */
		switch (levels) {
		default:
			goto fault;
		/* TODO: Level -1 when FEAT_LPA2 is implemented */
		case 4: /* Level 0 */
			if ((pte & ATTR_DESCR_MASK) != L0_TABLE)
				goto fault;
			/* FALLTHROUGH */
		case 3: /* Level 1 */
		case 2: /* Level 2 */
			switch (pte & ATTR_DESCR_MASK) {
			/* Use L1 macro as all levels are the same */
			case L1_TABLE:
				/* Check if EL0 can access this address space */
				if (is_el0 &&
				    (pte & TATTR_AP_TABLE_NO_EL0) != 0)
					goto fault;
				/* Check if the address space is writable */
				if ((prot & PROT_WRITE) != 0 &&
				    (pte & TATTR_AP_TABLE_RO) != 0)
					goto fault;
				if ((prot & PROT_EXEC) != 0) {
					/* Check the table exec attribute */
					if ((is_el0 &&
					    (pte & TATTR_UXN_TABLE) != 0) ||
					    (!is_el0 &&
					     (pte & TATTR_PXN_TABLE) != 0))
						goto fault;
				}
				pte_addr = pte & ~ATTR_MASK;
				break;
			case L1_BLOCK:
				goto done;
			default:
				goto fault;
			}
			break;
		case 1: /* Level 3 */
			if ((pte & ATTR_DESCR_MASK) == L3_PAGE)
				goto done;
			goto fault;
		}
	}

done:
	/* Check if EL0 has access to the block/page */
	if (is_el0 && (pte & ATTR_S1_AP(ATTR_S1_AP_USER)) == 0)
		goto fault;
	if ((prot & PROT_WRITE) != 0 && (pte & ATTR_S1_AP_RW_BIT) != 0)
		goto fault;
	if ((prot & PROT_EXEC) != 0) {
		if ((is_el0 && (pte & ATTR_S1_UXN) != 0) ||
		    (!is_el0 && (pte & ATTR_S1_PXN) != 0))
			goto fault;
	}
	mask = (1ul << pte_shift) - 1;
	*gpa = (pte & ~ATTR_MASK) | (gla & mask);
	*is_fault = 0;
	ptp_release(&cookie);
	return (0);

error:
	ptp_release(&cookie);
	return (EFAULT);
fault:
	*is_fault = 1;
	ptp_release(&cookie);
#endif
	return (0);
}

static void
riscv_sync_interrupts(struct hypctx *hypctx)
{
	struct hyp *hyp;
	int pending;

	hyp = hypctx->hyp;
	pending = aplic_check_pending(hyp);

	if (pending)
		hypctx->guest_csrs.hvip |= HVIP_VSEIP;
	else
		hypctx->guest_csrs.hvip &= ~HVIP_VSEIP;

	csr_write(hvip, hypctx->guest_csrs.hvip);
}

int
vmmops_run(void *vcpui, register_t pc, pmap_t pmap, struct vm_eventinfo *evinfo)
{
	uint64_t excp_type;
	int handled;
	register_t daif;
	//struct hyp *hyp;
	struct hypctx *hypctx;
	struct vcpu *vcpu;
	struct vm_exit *vme;
#if 0
	int mode;
#endif

	hypctx = (struct hypctx *)vcpui;
	//hyp = hypctx->hyp;
	vcpu = hypctx->vcpu;
	vme = vm_exitinfo(vcpu);

#if 0
	hypctx->tf.tf_sepc = (uint64_t)pc;
#endif
	hypctx->guest_regs.hyp_sepc = (uint64_t)pc;
	if (hypctx->guest_regs.hyp_sstatus & SSTATUS_SPP)
		hypctx->guest_regs.hyp_hstatus |= (1 << 8); //SPVP;
	else
		hypctx->guest_regs.hyp_hstatus &= ~(1 << 8); //SPVP;

	hypctx->guest_regs.hyp_hstatus |= (1 << 7); //SPV

#if 0
	uint64_t hgatp;

	hgatp = (vmmpmap_to_ttbr0() >> PAGE_SHIFT) | SATP_MODE_SV48;
	printf("hgatp %lx\n", hgatp);
	csr_write(hgatp, hgatp);
	printf("hgatp %lx\n", csr_read(hgatp));
	printf("pm_satp %lx\n", pmap->pm_satp);
#endif
	csr_write(hgatp, pmap->pm_satp);
#if 0
	printf("hgatp %lx\n", csr_read(hgatp));
#endif

	for (;;) {
		//printf("%s: pc %lx\n", __func__, pc);

		if (hypctx->has_exception) {
			hypctx->has_exception = false;
#if 0
			hypctx->elr_el1 = hypctx->tf.tf_sepc;

			mode = hypctx->tf.tf_spsr & (PSR_M_MASK | PSR_M_32);

			if (mode == PSR_M_EL1t) {
				hypctx->tf.tf_elr = hypctx->vbar_el1 + 0x0;
			} else if (mode == PSR_M_EL1h) {
				hypctx->tf.tf_elr = hypctx->vbar_el1 + 0x200;
			} else if ((mode & PSR_M_32) == PSR_M_64) {
				/* 64-bit EL0 */
				hypctx->tf.tf_elr = hypctx->vbar_el1 + 0x400;
			} else {
				/* 32-bit EL0 */
				hypctx->tf.tf_elr = hypctx->vbar_el1 + 0x600;
			}

			/* Set the new spsr */
			hypctx->spsr_el1 = hypctx->tf.tf_spsr;

			/* Set the new cpsr */
			hypctx->tf.tf_spsr = hypctx->spsr_el1 & PSR_FLAGS;
			hypctx->tf.tf_spsr |= PSR_DAIF | PSR_M_EL1h;

			/*
			 * Update fields that may change on exeption entry
			 * based on how sctlr_el1 is configured.
			 */
			if ((hypctx->sctlr_el1 & SCTLR_SPAN) != 0)
				hypctx->tf.tf_spsr |= PSR_PAN;
			if ((hypctx->sctlr_el1 & SCTLR_DSSBS) == 0)
				hypctx->tf.tf_spsr &= ~PSR_SSBS;
			else
				hypctx->tf.tf_spsr |= PSR_SSBS;
#endif
		}

		daif = intr_disable();

		/* Check if the vcpu is suspended */
		if (vcpu_suspended(evinfo)) {
			intr_restore(daif);
			vm_exit_suspended(vcpu, pc);
			break;
		}

		if (vcpu_debugged(vcpu)) {
			intr_restore(daif);
			vm_exit_debug(vcpu, pc);
			break;
		}

#if 0
		/* Activate the stage2 pmap so the vmid is valid */
		pmap_activate_vm(pmap);
		pmap_activate_boot(pmap);
		hyp->vttbr_el2 = pmap_to_ttbr0(pmap);
#endif

		/*
		 * TODO: What happens if a timer interrupt is asserted exactly
		 * here, but for the previous VM?
		 */
		riscv_set_active_vcpu(hypctx);
#if 0
		vgic_flush_hwstate(hypctx);
#endif

		riscv_sync_interrupts(hypctx);

		/* Call into EL2 to switch to the guest */
#if 0
		printf("%s: Entering Guest VM, vsatp %lx, ss %lx, "
		 "hs %lx\n", __func__,
		    csr_read(vsatp),
		    hypctx->guest_regs.hyp_sstatus,
		    hypctx->guest_regs.hyp_hstatus);
#endif
		excp_type = vmm_call_hyp(hypctx);
#if 0
printf("%s: leaving Guest VM\n", __func__);
#endif

#if 0
		excp_type = vmm_call_hyp(HYP_ENTER_GUEST,
		    hyp->el2_addr, hypctx->el2_addr);
		vgic_sync_hwstate(hypctx);
		vtimer_sync_hwstate(hypctx);

		/*
		 * Deactivate the stage2 pmap. vmm_pmap_clean_stage2_tlbi
		 * depends on this meaning we activate the VM before entering
		 * the vm again
		 */
		PCPU_SET(curvmpmap, NULL);
#else
		/* TODO */
#endif

		vme->scause = csr_read(scause);
		vme->sepc = csr_read(sepc);
		vme->stval = csr_read(stval);
		vme->htval = csr_read(htval);
		vme->htinst = csr_read(htinst);

		intr_restore(daif);

		vmm_stat_incr(vcpu, VMEXIT_COUNT, 1);
#if 0
		if (excp_type == EXCP_TYPE_MAINT_IRQ)
			continue;
#endif

#if 0
		uint64_t vsie, hvip;
		vsie = csr_read(vsie);
		hvip = csr_read(hvip);
		if (vsie & (1 << 5))
			printf("vsie hvip %lx %lx\n", vsie, hvip);
#endif

#if 0
	if (vme->scause == SCAUSE_ILLEGAL_INSTRUCTION)
		printf("exit scause 0x%lx stval %lx sepc %lx htval %lx "
		    "htinst %lx\n",
		    vme->scause, vme->stval, vme->sepc, vme->htval,
		    vme->htinst);
#endif

#if 0
		printf("exit vsatp 0x%lx\n", csr_read(vsatp));
		vme->u.hyp.exception_nr = excp_type;
		vme->u.hyp.esr_el2 = hypctx->tf.tf_esr;
		vme->u.hyp.far_el2 = hypctx->exit_info.far_el2;
		vme->u.hyp.hpfar_el2 = hypctx->exit_info.hpfar_el2;
#endif

		vme->pc = hypctx->guest_regs.hyp_sepc;
		vme->inst_length = INSN_SIZE;

		handled = riscv_handle_world_switch(hypctx, excp_type, vme,
		    pmap);
		if (handled == UNHANDLED)
			/* Exit loop to emulate instruction. */
			break;
		else {
			/* Resume guest execution from the next instruction. */
			hypctx->guest_regs.hyp_sepc += vme->inst_length;
		}
	}

	return (0);
}

static void
arm_pcpu_vmcleanup(void *arg)
{
	struct hyp *hyp;
	int i, maxcpus;

	hyp = arg;
	maxcpus = vm_get_maxcpus(hyp->vm);
	for (i = 0; i < maxcpus; i++) {
		if (riscv_get_active_vcpu() == hyp->ctx[i]) {
			riscv_set_active_vcpu(NULL);
			break;
		}
	}
}

void
vmmops_vcpu_cleanup(void *vcpui)
{
	struct hypctx *hypctx;

	hypctx = vcpui;

#if 0
	vtimer_cpucleanup(hypctx);
	vgic_cpucleanup(hypctx);

	vmmpmap_remove(hypctx->el2_addr, el2_hypctx_size(), true);
#endif

	free(hypctx, M_HYP);
}

void
vmmops_cleanup(void *vmi)
{
#if 0
	struct hyp *hyp = vmi;

	vtimer_vmcleanup(hyp);
	vgic_vmcleanup(hyp);

	smp_rendezvous(NULL, arm_pcpu_vmcleanup, NULL, hyp);

	vmmpmap_remove(hyp->el2_addr, el2_hyp_size(hyp->vm), true);

	free(hyp, M_HYP);
#endif
}

/*
 * Return register value. Registers have different sizes and an explicit cast
 * must be made to ensure proper conversion.
 */
static uint64_t *
hypctx_regptr(struct hypctx *hypctx, int reg)
{
	switch (reg) {
#if 0
	case VM_REG_GUEST_X0 ... VM_REG_GUEST_X29:
		return (&hypctx->tf.tf_x[reg]);
	case VM_REG_GUEST_LR:
		return (&hypctx->tf.tf_lr);
	case VM_REG_GUEST_SP:
		return (&hypctx->tf.tf_sp);
	case VM_REG_GUEST_CPSR:
		return (&hypctx->tf.tf_spsr);
	case VM_REG_GUEST_PC:
		return (&hypctx->tf.tf_elr);
	case VM_REG_GUEST_SCTLR_EL1:
		return (&hypctx->sctlr_el1);
	case VM_REG_GUEST_TTBR0_EL1:
		return (&hypctx->ttbr0_el1);
	case VM_REG_GUEST_TTBR1_EL1:
		return (&hypctx->ttbr1_el1);
	case VM_REG_GUEST_TCR_EL1:
		return (&hypctx->tcr_el1);
	case VM_REG_GUEST_TCR2_EL1:
		return (&hypctx->tcr2_el1);
#else

#if 0
        "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
        "s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
        "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
        "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6"
#endif

	case VM_REG_GUEST_X5:
		return (&hypctx->guest_regs.hyp_t[0]);
	case VM_REG_GUEST_X6:
		return (&hypctx->guest_regs.hyp_t[1]);
	case VM_REG_GUEST_X7:
		return (&hypctx->guest_regs.hyp_t[2]);
	case VM_REG_GUEST_X8:
		return (&hypctx->guest_regs.hyp_s[0]);
	case VM_REG_GUEST_X9:
		return (&hypctx->guest_regs.hyp_s[1]);
	case VM_REG_GUEST_X10 ... VM_REG_GUEST_X17:
		return (&hypctx->guest_regs.hyp_a[reg - 10]);
	case VM_REG_GUEST_X18:
		return (&hypctx->guest_regs.hyp_s[2]);
	case VM_REG_GUEST_X19:
		return (&hypctx->guest_regs.hyp_s[3]);
	case VM_REG_GUEST_X20:
		return (&hypctx->guest_regs.hyp_s[4]);
	case VM_REG_GUEST_X21:
		return (&hypctx->guest_regs.hyp_s[5]);
	case VM_REG_GUEST_X22:
		return (&hypctx->guest_regs.hyp_s[6]);
	case VM_REG_GUEST_X23:
		return (&hypctx->guest_regs.hyp_s[7]);
	case VM_REG_GUEST_X24:
		return (&hypctx->guest_regs.hyp_s[8]);
	case VM_REG_GUEST_X25:
		return (&hypctx->guest_regs.hyp_s[9]);
	case VM_REG_GUEST_X26:
		return (&hypctx->guest_regs.hyp_s[10]);
	case VM_REG_GUEST_X27:
		return (&hypctx->guest_regs.hyp_s[11]);
	case VM_REG_GUEST_X28:
		return (&hypctx->guest_regs.hyp_t[3]);
	case VM_REG_GUEST_X29:
		return (&hypctx->guest_regs.hyp_t[4]);
#if 0
	case VM_REG_GUEST_X30:
		return (&hypctx->guest_regs.hyp_t[5]);
	case VM_REG_GUEST_X31:
		return (&hypctx->guest_regs.hyp_t[6]);
#endif
	case VM_REG_GUEST_PC:
		return (&hypctx->guest_regs.hyp_sepc);
#endif
	default:
		break;
	}

	return (NULL);
}

int
vmmops_getreg(void *vcpui, int reg, uint64_t *retval)
{
	uint64_t *regp;
	int running, hostcpu;
	struct hypctx *hypctx;

	hypctx = vcpui;

	running = vcpu_is_running(hypctx->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("%s: %s%d is running", __func__, vm_name(hypctx->hyp->vm),
		    vcpu_vcpuid(hypctx->vcpu));

	regp = hypctx_regptr(hypctx, reg);
	if (regp == NULL)
		return (EINVAL);

	*retval = *regp;

	return (0);
}

int
vmmops_setreg(void *vcpui, int reg, uint64_t val)
{
	uint64_t *regp;
	struct hypctx *hypctx;
	int running, hostcpu;

	hypctx = vcpui;

//printf("%s: set reg %d val %lx\n", __func__, reg, val);

	running = vcpu_is_running(hypctx->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("%s: %s%d is running", __func__, vm_name(hypctx->hyp->vm),
		    vcpu_vcpuid(hypctx->vcpu));

	regp = hypctx_regptr(hypctx, reg);
	if (regp == NULL)
		return (EINVAL);

	*regp = val;

//printf("%s: set reg ok\n", __func__);

	return (0);
}

int
vmmops_exception(void *vcpui, uint64_t esr, uint64_t far)
{
	struct hypctx *hypctx = vcpui;
	int running, hostcpu;

	running = vcpu_is_running(hypctx->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("%s: %s%d is running", __func__, vm_name(hypctx->hyp->vm),
		    vcpu_vcpuid(hypctx->vcpu));

#if 0
	hypctx->far_el1 = far;
	hypctx->esr_el1 = esr;
#endif
	hypctx->has_exception = true;

	return (0);
}

int
vmmops_getcap(void *vcpui, int num, int *retval)
{
	int ret;

	ret = ENOENT;

	switch (num) {
	case VM_CAP_UNRESTRICTED_GUEST:
		*retval = 1;
		ret = 0;
		break;
	default:
		break;
	}

	return (ret);
}

int
vmmops_setcap(void *vcpui, int num, int val)
{

	return (ENOENT);
}
