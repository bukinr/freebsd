/*-
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

#include "riscv.h"
#include "vmm_aplic.h"
#include "vmm_stat.h"

#define	HANDLED		1
#define	UNHANDLED	0

/* TODO: Move the host hypctx off the stack */
#define	VMM_STACK_PAGES	4
#define	VMM_STACK_SIZE	(VMM_STACK_PAGES * PAGE_SIZE)

MALLOC_DEFINE(M_HYP, "ARM VMM HYP", "ARM VMM HYP");

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

int
vmmops_modinit(int ipinum)
{

	if (!has_hyp()) {
		printf("vmm: hart doesn't have support for H-extension.\n");
		return (ENXIO);
	}

	return (0);
}

int
vmmops_modcleanup(void)
{

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

void *
vmmops_init(struct vm *vm, pmap_t pmap)
{
	struct hyp *hyp;
	vm_size_t size;

	size = el2_hyp_size(vm);
	hyp = malloc_aligned(size, PAGE_SIZE, M_HYP, M_WAITOK | M_ZERO);
	hyp->vm = vm;
	hyp->aplic_attached = false;

#if 0
	vtimer_vminit(hyp);
#endif
	aplic_vminit(hyp);

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

	/* TODO: Reset vm state here. */

#if 0
	vtimer_cpuinit(hypctx);
	vgic_cpuinit(hypctx);
#endif

	uint64_t henvcfg;
	uint64_t hedeleg;
	uint64_t hideleg;

	hedeleg  = (1UL << SCAUSE_INST_MISALIGNED);
	hedeleg |= (1UL << SCAUSE_ILLEGAL_INSTRUCTION);
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

	hypctx->guest_regs.hyp_sstatus = SSTATUS_SPP | SSTATUS_SPIE;
	hypctx->guest_regs.hyp_sstatus |= SSTATUS_FS_INITIAL;

	uint64_t hstatus;
	hstatus = 0;
	hstatus |= (1 << 7); //SPV
	hstatus |= (1 << 21); //VTW
	hypctx->guest_regs.hyp_hstatus = hstatus;

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
riscv_gen_inst_emul_data(struct hypctx *hypctx, uint32_t esr_iss,
    struct vm_exit *vme_ret)
{
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
}

#if 0
void
raise_data_insn_abort(struct hypctx *hypctx, uint64_t far, bool dabort, int fsc)
{
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
}
#endif

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
		panic("%s: Illegal instr at %lx stval 0x%lx htval 0x%lx\n",
		    __func__, vme->sepc, vme->stval, vme->htval);
	case SCAUSE_VIRTUAL_SUPERVISOR_ECALL:
		vme->exitcode = VM_EXITCODE_ECALL;
		handled = UNHANDLED;
		break;
	case SCAUSE_VIRTUAL_INSTRUCTION:
		insn = vme->stval;
		if (m_op(insn, MATCH_WFI, MASK_WFI))
			vme->exitcode = VM_EXITCODE_WFI;
		else
			vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;
	default:
#if 0
		printf("unknown scause %lx\n", vme->scause);
#endif
		vmm_stat_incr(hypctx->vcpu, VMEXIT_UNHANDLED, 1);
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;
	}

	return (handled);
}

int
vmmops_gla2gpa(void *vcpui, struct vm_guest_paging *paging, uint64_t gla,
    int prot, uint64_t *gpa, int *is_fault)
{

	/* Implement me. */

	return (0);
}

static void
riscv_sync_interrupts(struct hypctx *hypctx)
{
	int pending;

	pending = aplic_check_pending(hypctx);

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
	register_t val;
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
	hypctx->guest_regs.hyp_hstatus |= (1 << 21); //VTW

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
			/* TODO. */
		}

		val = intr_disable();

		/* Check if the vcpu is suspended */
		if (vcpu_suspended(evinfo)) {
			intr_restore(val);
			vm_exit_suspended(vcpu, pc);
			break;
		}

		if (vcpu_debugged(vcpu)) {
			intr_restore(val);
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

		intr_restore(val);

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
riscv_pcpu_vmcleanup(void *arg)
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
	struct hyp *hyp;

	hyp = vmi;

#if 0
	vtimer_vmcleanup(hyp);
	vgic_vmcleanup(hyp);
#endif

	smp_rendezvous(NULL, riscv_pcpu_vmcleanup, NULL, hyp);

	free(hyp, M_HYP);
}

/*
 * Return register value. Registers have different sizes and an explicit cast
 * must be made to ensure proper conversion.
 */
static uint64_t *
hypctx_regptr(struct hypctx *hypctx, int reg)
{
	switch (reg) {
	case VM_REG_GUEST_RA:
		return (&hypctx->guest_regs.hyp_ra);
	case VM_REG_GUEST_SP:
		return (&hypctx->guest_regs.hyp_sp);
	case VM_REG_GUEST_GP:
		return (&hypctx->guest_regs.hyp_gp);
	case VM_REG_GUEST_TP:
		return (&hypctx->guest_regs.hyp_tp);
	case VM_REG_GUEST_T0:
		return (&hypctx->guest_regs.hyp_t[0]);
	case VM_REG_GUEST_T1:
		return (&hypctx->guest_regs.hyp_t[1]);
	case VM_REG_GUEST_T2:
		return (&hypctx->guest_regs.hyp_t[2]);
	case VM_REG_GUEST_S0:
		return (&hypctx->guest_regs.hyp_s[0]);
	case VM_REG_GUEST_S1:
		return (&hypctx->guest_regs.hyp_s[1]);
	case VM_REG_GUEST_A0:
		return (&hypctx->guest_regs.hyp_a[0]);
	case VM_REG_GUEST_A1:
		return (&hypctx->guest_regs.hyp_a[1]);
	case VM_REG_GUEST_A2:
		return (&hypctx->guest_regs.hyp_a[2]);
	case VM_REG_GUEST_A3:
		return (&hypctx->guest_regs.hyp_a[3]);
	case VM_REG_GUEST_A4:
		return (&hypctx->guest_regs.hyp_a[4]);
	case VM_REG_GUEST_A5:
		return (&hypctx->guest_regs.hyp_a[5]);
	case VM_REG_GUEST_A6:
		return (&hypctx->guest_regs.hyp_a[6]);
	case VM_REG_GUEST_A7:
		return (&hypctx->guest_regs.hyp_a[7]);
	case VM_REG_GUEST_S2:
		return (&hypctx->guest_regs.hyp_s[2]);
	case VM_REG_GUEST_S3:
		return (&hypctx->guest_regs.hyp_s[3]);
	case VM_REG_GUEST_S4:
		return (&hypctx->guest_regs.hyp_s[4]);
	case VM_REG_GUEST_S5:
		return (&hypctx->guest_regs.hyp_s[5]);
	case VM_REG_GUEST_S6:
		return (&hypctx->guest_regs.hyp_s[6]);
	case VM_REG_GUEST_S7:
		return (&hypctx->guest_regs.hyp_s[7]);
	case VM_REG_GUEST_S8:
		return (&hypctx->guest_regs.hyp_s[8]);
	case VM_REG_GUEST_S9:
		return (&hypctx->guest_regs.hyp_s[9]);
	case VM_REG_GUEST_S10:
		return (&hypctx->guest_regs.hyp_s[10]);
	case VM_REG_GUEST_S11:
		return (&hypctx->guest_regs.hyp_s[11]);
	case VM_REG_GUEST_T3:
		return (&hypctx->guest_regs.hyp_t[3]);
	case VM_REG_GUEST_T4:
		return (&hypctx->guest_regs.hyp_t[4]);
	case VM_REG_GUEST_T5:
		return (&hypctx->guest_regs.hyp_t[5]);
	case VM_REG_GUEST_T6:
		return (&hypctx->guest_regs.hyp_t[6]);
	case VM_REG_GUEST_SEPC:
		return (&hypctx->guest_regs.hyp_sepc);
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
vmmops_exception(void *vcpui, uint64_t scause)
{
	struct hypctx *hypctx = vcpui;
	int running, hostcpu;

	running = vcpu_is_running(hypctx->vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("%s: %s%d is running", __func__, vm_name(hypctx->hyp->vm),
		    vcpu_vcpuid(hypctx->vcpu));

	/* TODO: set registers. */

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
