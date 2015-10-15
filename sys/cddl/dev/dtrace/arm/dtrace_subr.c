/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * $FreeBSD$
 *
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/kmem.h>
#include <sys/smp.h>
#include <sys/dtrace_impl.h>
#include <sys/dtrace_bsd.h>
#include <machine/armreg.h>
#include <machine/clock.h>
#include <machine/cpu.h>
#include <machine/frame.h>
#include <machine/trap.h>
#include <vm/pmap.h>

#define	DELAYBRANCH(x)	((int)(x) < 0)

#define	BIT_PC		15
#define	BIT_LR		14
#define	BIT_SP		13

extern uintptr_t 	dtrace_in_probe_addr;
extern int		dtrace_in_probe;
extern dtrace_id_t	dtrace_probeid_error;
extern int (*dtrace_invop_jump_addr)(struct trapframe *);
extern void dtrace_getnanotime(struct timespec *tsp);

int dtrace_invop(uintptr_t, uintptr_t *, uintptr_t);
void dtrace_invop_init(void);
void dtrace_invop_uninit(void);

typedef struct dtrace_invop_hdlr {
	int (*dtih_func)(uintptr_t, uintptr_t *, uintptr_t);
	struct dtrace_invop_hdlr *dtih_next;
} dtrace_invop_hdlr_t;

dtrace_invop_hdlr_t *dtrace_invop_hdlr;

int
dtrace_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax)
{
	dtrace_invop_hdlr_t *hdlr;
	int rval;

	for (hdlr = dtrace_invop_hdlr; hdlr != NULL; hdlr = hdlr->dtih_next)
		if ((rval = hdlr->dtih_func(addr, stack, eax)) != 0)
			return (rval);

	return (0);
}


void
dtrace_invop_add(int (*func)(uintptr_t, uintptr_t *, uintptr_t))
{
	dtrace_invop_hdlr_t *hdlr;

	hdlr = kmem_alloc(sizeof (dtrace_invop_hdlr_t), KM_SLEEP);
	hdlr->dtih_func = func;
	hdlr->dtih_next = dtrace_invop_hdlr;
	dtrace_invop_hdlr = hdlr;
}

void
dtrace_invop_remove(int (*func)(uintptr_t, uintptr_t *, uintptr_t))
{
	dtrace_invop_hdlr_t *hdlr = dtrace_invop_hdlr, *prev = NULL;

	for (;;) {
		if (hdlr == NULL)
			panic("attempt to remove non-existent invop handler");

		if (hdlr->dtih_func == func)
			break;

		prev = hdlr;
		hdlr = hdlr->dtih_next;
	}

	if (prev == NULL) {
		ASSERT(dtrace_invop_hdlr == hdlr);
		dtrace_invop_hdlr = hdlr->dtih_next;
	} else {
		ASSERT(dtrace_invop_hdlr != hdlr);
		prev->dtih_next = hdlr->dtih_next;
	}

	kmem_free(hdlr, 0);
}


/*ARGSUSED*/
void
dtrace_toxic_ranges(void (*func)(uintptr_t base, uintptr_t limit))
{
	printf("IMPLEMENT ME: dtrace_toxic_ranges\n");
}

void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
	cpuset_t cpus;

	if (cpu == DTRACE_CPUALL)
		cpus = all_cpus;
	else
		CPU_SETOF(cpu, &cpus);

	smp_rendezvous_cpus(cpus, smp_no_rendevous_barrier, func,
	    smp_no_rendevous_barrier, arg);
}

static void
dtrace_sync_func(void)
{
}

void
dtrace_sync(void)
{
	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)dtrace_sync_func, NULL);
}

/*
 * DTrace needs a high resolution time function which can
 * be called from a probe context and guaranteed not to have
 * instrumented with probes itself.
 *
 * Returns nanoseconds since boot.
 */
static int64_t	tgt_cpu_ccnt;
static int64_t	hst_cpu_ccnt;
static int64_t	ccnt_skew[MAXCPU];
static uint64_t	nsec_scale;

/* See below for the explanation of this macro. */
#define SCALE_SHIFT	28

static void
dtrace_gethrtime_init_cpu(void *arg)
{
	uintptr_t cpu = (uintptr_t) arg;

	if (cpu == curcpu)
		tgt_cpu_ccnt = get_cyclecount();
	else
		hst_cpu_ccnt = get_cyclecount();
}

static void
dtrace_gethrtime_init(void *arg)
{
	struct pcpu *pc;
	uint64_t ccnt_f;
	cpuset_t map;
	int i;

	/*
	 * Get CCNT frequency known at this moment.
	 * This should be constant if CCNT is invariant.
	 * Otherwise tick->time conversion will be inaccurate, but
	 * will preserve monotonic property of CCNT.
	 */
	ccnt_f = atomic_load_acq_64(&ccnt_freq);

	/*
	 * The following line checks that nsec_scale calculated below
	 * doesn't overflow 32-bit unsigned integer, so that it can multiply
	 * another 32-bit integer without overflowing 64-bit.
	 * Thus minimum supported CCNT frequency is 62.5MHz.
	 */
	KASSERT(ccnt_f > (NANOSEC >> (32 - SCALE_SHIFT)),
	    ("CCNT frequency is too low"));

	/*
	 * We scale up NANOSEC/ccnt_f ratio to preserve as much precision
	 * as possible.
	 * 2^28 factor was chosen quite arbitrarily from practical
	 * considerations:
	 * - it supports CCNT frequencies as low as 62.5MHz (see above);
	 * - it provides quite good precision (e < 0.01%) up to THz
	 *   (terahertz) values;
	 */
	nsec_scale = ((uint64_t)NANOSEC << SCALE_SHIFT) / ccnt_f;

	/* The current CPU is the reference one. */
	sched_pin();
	ccnt_skew[curcpu] = 0;
	CPU_FOREACH(i) {
		if (i == curcpu)
			continue;

		pc = pcpu_find(i);
		CPU_SETOF(PCPU_GET(cpuid), &map);
		CPU_SET(pc->pc_cpuid, &map);

		smp_rendezvous_cpus(map, NULL,
		    dtrace_gethrtime_init_cpu,
		    smp_no_rendevous_barrier, (void *)(uintptr_t) i);

		ccnt_skew[i] = tgt_cpu_ccnt - hst_cpu_ccnt;
	}
	sched_unpin();
}

SYSINIT(dtrace_gethrtime_init, SI_SUB_SMP, SI_ORDER_ANY, dtrace_gethrtime_init, NULL);

/*
 * DTrace needs a high resolution time function which can
 * be called from a probe context and guaranteed not to have
 * instrumented with probes itself.
 *
 * Returns nanoseconds since boot.
 */
uint64_t
dtrace_gethrtime()
{
	uint64_t ccnt;
	uint32_t lo;
	uint32_t hi;

	/*
	 * We split CCNT value into lower and higher 32-bit halves and separately
	 * scale them with nsec_scale, then we scale them down by 2^28
	 * (see nsec_scale calculations) taking into account 32-bit shift of
	 * the higher half and finally add.
	 */
	ccnt = get_cyclecount() - ccnt_skew[curcpu];
	lo = ccnt;
	hi = ccnt >> 32;
	return (((lo * nsec_scale) >> SCALE_SHIFT) +
	    ((hi * nsec_scale) << (32 - SCALE_SHIFT)));
}

uint64_t
dtrace_gethrestime(void)
{
	struct timespec current_time;

	dtrace_getnanotime(&current_time);

	return (current_time.tv_sec * 1000000000UL + current_time.tv_nsec);
}

/* Function to handle DTrace traps during probes. See amd64/amd64/trap.c */
int
dtrace_trap(struct trapframe *frame, u_int type)
{
	/*
	 * A trap can occur while DTrace executes a probe. Before
	 * executing the probe, DTrace blocks re-scheduling and sets
	 * a flag in it's per-cpu flags to indicate that it doesn't
	 * want to fault. On returning from the probe, the no-fault
	 * flag is cleared and finally re-scheduling is enabled.
	 *
	 * Check if DTrace has enabled 'no-fault' mode:
	 *
	 */
	if ((cpu_core[curcpu].cpuc_dtrace_flags & CPU_DTRACE_NOFAULT) != 0) {
		/*
		 * There are only a couple of trap types that are expected.
		 * All the rest will be handled in the usual way.
		 */
		switch (type) {
		/* Page fault. */
		case FAULT_ALIGN:
			/* Flag a bad address. */
			cpu_core[curcpu].cpuc_dtrace_flags |= CPU_DTRACE_BADADDR;
			cpu_core[curcpu].cpuc_dtrace_illval = 0;

			/*
			 * Offset the instruction pointer to the instruction
			 * following the one causing the fault.
			 */
			frame->tf_pc += sizeof(int);
			return (1);
		default:
			/* Handle all other traps in the usual way. */
			break;
		}
	}

	/* Handle the trap in the usual way. */
	return (0);
}

void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int which,
    int fault, int fltoffs, uintptr_t illval)
{

	dtrace_probe(dtrace_probeid_error, (uint64_t)(uintptr_t)state,
	    (uintptr_t)epid,
	    (uintptr_t)which, (uintptr_t)fault, (uintptr_t)fltoffs);
}

static int
dtrace_invop_start(struct trapframe *frame)
{
	register_t *r0, *sp;
	int data, invop, reg, update_sp;

	/* pc points to the instruction after the one we simulating */
	frame->tf_pc -= INSN_SIZE;

	invop = dtrace_invop(frame->tf_pc, (uintptr_t *)frame, frame->tf_pc);
	switch (invop & DTRACE_INVOP_MASK) {
	case DTRACE_INVOP_PUSHM:
		sp = (register_t *)frame->tf_svc_sp;
		r0 = &frame->tf_r0;
		data = DTRACE_INVOP_DATA(invop);

		/*
		 * Store the pc, lr, and sp. These have their own
		 * entries in the struct.
		 */
		if (data & (1 << BIT_PC)) {
			sp--;
			*sp = frame->tf_pc;
		}
		if (data & (1 << BIT_LR)) {
			sp--;
			*sp = frame->tf_svc_lr;
		}
		if (data & (1 << BIT_SP)) {
			sp--;
			*sp = frame->tf_svc_sp;
		}

		/* Store the general registers */
		for (reg = 12; reg >= 0; reg--) {
			if (data & (1 << reg)) {
				sp--;
				*sp = r0[reg];
			}
		}

		/* Update the stack pointer and program counter to continue */
		frame->tf_svc_sp = (register_t)sp;
		frame->tf_pc += 4;
		break;
	case DTRACE_INVOP_POPM:
		sp = (register_t *)frame->tf_svc_sp;
		r0 = &frame->tf_r0;
		data = DTRACE_INVOP_DATA(invop);

		/* Read the general registers */
		for (reg = 0; reg <= 12; reg++) {
			if (data & (1 << reg)) {
				r0[reg] = *sp;
				sp++;
			}
		}

		/*
		 * Set the stack pointer. If we don't update it here we will
		 * need to update it at the end as the instruction would do
		 */
		update_sp = 1;
		if (data & (1 << BIT_SP)) {
			frame->tf_svc_sp = *sp;
			*sp++;
			update_sp = 0;
		}

		/* Update the link register, we need to use the correct copy */
		if (data & (1 << BIT_LR)) {
			frame->tf_svc_lr = *sp;
			*sp++;
		}
		/*
		 * And the program counter. If it's not in the list skip over
		 * it when we return so to not hit this again.
		 */
		if (data & (1 << BIT_PC)) {
			frame->tf_pc = *sp;
			*sp++;
		} else
			frame->tf_pc += 4;

		/* Update the stack pointer if we haven't already done so */
		if (update_sp)
			frame->tf_svc_sp = (register_t)sp;
		break;
	case DTRACE_INVOP_B:
		data = DTRACE_INVOP_DATA(invop) & 0x00ffffff;
		/* Sign extend the data */
		if ((data & (1 << 23)) != 0)
			data |= 0xff000000;
		/* The data is the number of 4-byte words to change the pc */
		data *= 4;
		data += 8;
		frame->tf_pc += data;
		break;
	default:
		return (-1);
		break;
	}

	return (0);
}

void dtrace_invop_init(void)
{
	dtrace_invop_jump_addr = dtrace_invop_start;
}

void dtrace_invop_uninit(void)
{
	dtrace_invop_jump_addr = 0;
}
