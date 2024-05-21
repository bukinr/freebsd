/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/cpuset.h>

#include <dev/psci/psci.h>
#include <dev/psci/smccc.h>

#include <machine/riscvreg.h>
#include <machine/cpu.h>
#include <machine/sbi.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/vmm_instruction_emul.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <vmmapi.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "mem.h"
#include "vmexit.h"

//static cpuset_t running_cpumask;

static int __unused
vmexit_inst_emul(struct vmctx *ctx __unused, struct vcpu *vcpu,
    struct vm_run *vmrun)
{
	struct vm_exit *vme;
	struct vie *vie;
	int err;

	vme = vmrun->vm_exit;
	vie = &vme->u.inst_emul.vie;

#if 0
	if (vme->u.inst_emul.gpa >= 0x11000)
		printf("%s: gpa %lx dir %d access_size %d reg %d sign %d\n",
		    __func__, vme->u.inst_emul.gpa, vie->dir, vie->access_size,
		    vie->reg, vie->sign_extend);
#endif

	err = emulate_mem(vcpu, vme->u.inst_emul.gpa, vie,
	    &vme->u.inst_emul.paging);
	if (err) {
		if (err == ESRCH) {
			EPRINTLN("Unhandled memory access to 0x%lx\n",
			    vme->u.inst_emul.gpa);
		}
		goto fail;
	}

	return (VMEXIT_CONTINUE);

fail:
	fprintf(stderr, "Failed to emulate instruction ");
	FPRINTLN(stderr, "at 0x%lx", vme->pc);
	return (VMEXIT_ABORT);
}

static int
vmexit_suspend(struct vmctx *ctx, struct vcpu *vcpu, struct vm_run *vmrun)
{
	struct vm_exit *vme;
	enum vm_suspend_how how;
	int vcpuid = vcpu_id(vcpu);

	vme = vmrun->vm_exit;
	how = vme->u.suspended.how;

	fbsdrun_deletecpu(vcpuid);

	switch (how) {
	case VM_SUSPEND_RESET:
		exit(0);
	case VM_SUSPEND_POWEROFF:
		if (get_config_bool_default("destroy_on_poweroff", false))
			vm_destroy(ctx);
		exit(1);
	case VM_SUSPEND_HALT:
		exit(2);
	default:
		fprintf(stderr, "vmexit_suspend: invalid reason %d\n", how);
		exit(100);
	}
	return (0);	/* NOTREACHED */
}

static int
vmexit_debug(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_run *vmrun __unused)
{
	return (VMEXIT_CONTINUE);
}

static int
vmexit_bogus(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_run *vmrun __unused)
{
	return (VMEXIT_CONTINUE);
}

#if 0
static uint64_t
smccc_affinity_info(uint64_t target_affinity __unused, uint32_t lowest_affinity_level __unused)
{
	uint64_t cpu_aff, mask = 0;

	switch (lowest_affinity_level) {
	case 0:
		mask |= CPU_AFF0_MASK;
		/* FALLTHROUGH */
	case 1:
		mask |= CPU_AFF1_MASK;
		/* FALLTHROUGH */
	case 2:
		mask |= CPU_AFF2_MASK;
		/* FALLTHROUGH */
	case 3:
		mask |= CPU_AFF3_MASK;
		break;
	default:
		return (PSCI_RETVAL_INVALID_PARAMS);
	}

	for (int vcpu = 0; vcpu < guest_ncpus; vcpu++) {
		/* TODO: We should get this from the kernel */
		cpu_aff = (vcpu & 0xf) << MPIDR_AFF0_SHIFT |
		    ((vcpu >> 4) & 0xff) << MPIDR_AFF1_SHIFT |
		    ((vcpu >> 12) & 0xff) << MPIDR_AFF2_SHIFT |
		    (uint64_t)((vcpu >> 20) & 0xff) << MPIDR_AFF3_SHIFT;

		if ((cpu_aff & mask) == (target_affinity & mask) &&
		    CPU_ISSET(vcpu, &running_cpumask)) {
			/* Return ON if any CPUs are on */
			return (PSCI_AFFINITY_INFO_ON);
		}
	}

	/* No CPUs in the affinity mask are on, return OFF */
	return (PSCI_AFFINITY_INFO_OFF);
}
#endif

static void
vmexit_ecall_srst(struct vmctx *ctx, struct vm_exit *vme)
{
	enum vm_suspend_how how;
	int func_id;
	int type;

	func_id = vme->u.ecall.args[6];
	type = vme->u.ecall.args[0];

#if 0
	printf("%s: srst %d %d\n", __func__, func_id, type);
#endif

	switch (func_id) {
	case SBI_SRST_SYSTEM_RESET:
		switch (type) {
		case SBI_SRST_TYPE_SHUTDOWN:
		case SBI_SRST_TYPE_COLD_REBOOT:
		case SBI_SRST_TYPE_WARM_REBOOT:
			how = VM_SUSPEND_POWEROFF;
			vm_suspend(ctx, how);
		default:
			break;
		}
	default:
		break;
	}
}

static int
vmexit_ecall(struct vmctx *ctx, struct vcpu *vcpu __unused,
    struct vm_run *vmrun)
{
	int sbi_extension_id;
	struct vm_exit *vme;

	vme = vmrun->vm_exit;

	sbi_extension_id = vme->u.ecall.args[7];
	switch (sbi_extension_id) {
	case SBI_EXT_ID_SRST:
		vmexit_ecall_srst(ctx, vme);
		break;
	default:
		break;
	}

	return (VMEXIT_CONTINUE);
}

const vmexit_handler_t vmexit_handlers[VM_EXITCODE_MAX] = {
	[VM_EXITCODE_BOGUS]  = vmexit_bogus,
	[VM_EXITCODE_INST_EMUL] = vmexit_inst_emul,
	[VM_EXITCODE_SUSPENDED] = vmexit_suspend,
	[VM_EXITCODE_DEBUG] = vmexit_debug,
	[VM_EXITCODE_ECALL] = vmexit_ecall,
};
