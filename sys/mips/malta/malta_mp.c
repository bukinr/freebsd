/*-
 * Copyright (c) 2016 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/smp.h>
#include <sys/systm.h>

#include <machine/cpufunc.h>
#include <machine/hwfunc.h>
#include <machine/md_var.h>
#include <machine/smp.h>

//#include <mips/ingenic/malta_regs.h>
//#include <mips/ingenic/malta_cpuregs.h>

/*
 * R4x00 interrupt cause bits
 */
#define C_SW0           ((1) <<  8)
#define C_SW1           ((1) <<  9)
#define C_IRQ0          ((1) << 10)
#define C_IRQ1          ((1) << 11)
#define C_IRQ2          ((1) << 12)
#define C_IRQ3          ((1) << 13)
#define C_IRQ4          ((1) << 14)
#define C_IRQ5          ((1) << 15)

static inline void ehb(void)
{
        __asm__ __volatile__(
        "       .set    mips32r2                                \n"
        "       ehb                                             \n"
        "       .set    mips0                                   \n");
}

#define mttc0(rd,sel,v)                                                 \
({                                                                      \
        __asm__ __volatile__(                                           \
        "       .set    push                                    \n"     \
        "       .set    mips32r2                                \n"     \
        "       .set    noat                                    \n"     \
        "       move    $1, %0                                  \n"     \
        "      # mttc0 %0," #rd ", " #sel "                    \n"     \
        "       .word   0x41810000 | (" #rd " << 11) | " #sel " \n"     \
        "       .set    pop                                     \n"     \
        :                                                               \
        : "r" (v));                                                     \
})

#define mftc0(rt,sel)                                                   \
({                                                                      \
         unsigned long  __res;                                          \
                                                                        \
        __asm__ __volatile__(                                           \
        "       .set    push                                    \n"     \
        "       .set    mips32r2                                \n"     \
        "       .set    noat                                    \n"     \
        "      # mftc0 $1, $" #rt ", " #sel "                  \n"     \
        "       .word   0x41000800 | (" #rt " << 16) | " #sel " \n"     \
        "       move    %0, $1                                  \n"     \
        "       .set    pop                                     \n"     \
        : "=r" (__res));                                                \
                                                                        \
        __res;                                                          \
})

#define write_vpe_c0_cause(val)		mttc0(13, 0, val)
#define read_vpe_c0_cause()             mftc0(13, 0)

#define read_vpe_c0_vpeconf0()          mftc0(1, 2)
#define write_vpe_c0_vpeconf0(val)      mttc0(1, 2, val)

#define write_c0_register32(reg,  sel, value)                   \
        __asm__ __volatile__(                                   \
            ".set       push\n\t"                               \
            ".set       mips32\n\t"                             \
            "mtc0       %0, $%1, %2\n\t"                        \
            ".set       pop\n"                                  \
        : : "r" (value), "i" (reg), "i" (sel) );

#define read_c0_register32(reg, sel)                            \
({                                                              \
         uint32_t __rv;                                         \
        __asm__ __volatile__(                                   \
            ".set       push\n\t"                               \
            ".set       mips32\n\t"                             \
            "mfc0       %0, $%1, %2\n\t"                        \
            ".set       pop\n"                                  \
            : "=r" (__rv) : "i" (reg), "i" (sel) );             \
        __rv;                                                   \
 })


unsigned malta_ap_boot = ~0;

void malta_mpentry(void);

#define MALTA_MAXCPU	2

void
platform_ipi_send(int cpuid)
{

	//printf("%s: fromcpu %d -> tocpu %d\n", __func__, PCPU_GET(cpuid), cpuid);

#if 0
	uint32_t cfg3;
	cfg3 = mips_rd_config3();
	printf("cfg3: %x\n", cfg3);

	uint64_t *vaddr;
	//uint32_t ofs = 0x1bdc0000; /* gic base */
	uint32_t ofs = 0x1fbf8000; /* gcr base */

	vaddr = (uint64_t *)(MIPS_PHYS_TO_KSEG0(ofs));
	printf("vaddr 0x%016lx\n", (uint64_t)vaddr);
	printf("gic sh config: %lx\n", *(vaddr + 0x0));
	printf("gic sh+8 config: %lx\n", *(vaddr + 0x08));
	printf("gic sh+80 config: %lx\n", *(vaddr + 0x80));

	printf("15.3: %x\n", read_c0_register32(15, 3));
#endif
	uint32_t reg;
	uint32_t cause;

	/* Set thread context */
	reg = read_c0_register32(1, 1);
	//printf("read reg 0x%08x\n", reg);
	reg &= ~0xff;
	reg |= cpuid;
	//printf("writing tc reg 0x%08x\n", reg);
	write_c0_register32(1, 1, reg);

	ehb();
	//reg = read_c0_register32(1, 1);
	//printf("new reg 0x%08x\n", reg);

	/* Set cause */
	cause = read_vpe_c0_cause();
	//printf("vpe cause 0x%x\n", cause);
	write_vpe_c0_cause(cause | C_SW1);
	//cause = read_vpe_c0_cause();
	//printf("new cause 0x%x\n", cause);
}

void
platform_ipi_clear(void)
{
	int cpuid;

	cpuid = PCPU_GET(cpuid);

	//printf("%s: %d\n", __func__, cpuid);

	uint32_t reg;
	reg = read_c0_register32(13, 0);
	//printf("%s: %d cause 0x%x\n", __func__, cpuid, reg);
	reg &= ~(C_SW1);
	write_c0_register32(13, 0, reg);

#if 0
	int cpuid = PCPU_GET(cpuid);
	uint32_t action;

	action = (cpuid == 0) ? mips_rd_xburst_mbox0() : mips_rd_xburst_mbox1();
	KASSERT(action == 1, ("CPU %d: unexpected IPIs: %#x", cpuid, action));
	mips_wr_xburst_core_sts(~(JZ_CORESTS_MIRQ0P << cpuid));
#endif
}

int
platform_ipi_hardintr_num(void)
{

	return (-1);
}

int
platform_ipi_softintr_num(void)
{

	return (1);
}

void
platform_init_ap(int cpuid)
{
	unsigned reg;

	//printf("%s: %d\n", __func__, cpuid);
	//write_vpe_c0_vpeconf0(VPECONF0_MVP | VPECONF0_VPA);

	/*
	 * Set the exception base.
	 */
	mips_wr_ebase(0x80000000);

#if 0
	/*
	 * Clear any pending IPIs.
	 */
	mips_wr_xburst_core_sts(~(JZ_CORESTS_MIRQ0P << cpuid));

	/* Allow IPI mbox for this core */
	reg = mips_rd_xburst_reim();
	reg |= (JZ_REIM_MIRQ0M << cpuid);
	mips_wr_xburst_reim(reg);
#endif

	/*
	 * Unmask the ipi interrupts.
	 */
	reg = soft_int_mask(platform_ipi_softintr_num());
	set_intr_mask(reg);
}

void
platform_cpu_mask(cpuset_t *mask)
{
	uint32_t i, m;

	CPU_ZERO(mask);
	for (i = 0, m = 1 ; i < MALTA_MAXCPU; i++, m <<= 1)
		CPU_SET(i, mask);
}

struct cpu_group *
platform_smp_topo(void)
{

	return (smp_topo_none());
}

int
platform_start_ap(int cpuid)
{

	printf("%s: %d\n", __func__, cpuid);

	if (atomic_cmpset_32(&malta_ap_boot, ~0, cpuid) == 0)
		return (-1);

	for (;;) {
		DELAY(1000);
		if (atomic_cmpset_32(&malta_ap_boot, 0, ~0) != 0) {
			printf("CPU %d started\n", cpuid);
			return (0);
		}
		printf("Waiting for cpu%d to start\n", cpuid);
	}

	return (0);
}
