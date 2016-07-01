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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#ifdef _KERNEL
#include "opt_bpf.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <net/if.h>
#else
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#endif

#include <sys/types.h>

#include <net/bpf.h>
#include <net/bpf_jitter.h>

#include <arm64/arm64/bpf_jit_machdep.h>
#include <arm/include/trap.h>

bpf_filter_func	bpf_jit_compile(struct bpf_insn *, u_int, size_t *);

#define	REG_A		A64_R(4)
#define	REG_X		A64_R(5)
#define	REG_MBUF	A64_R(6)
#define	REG_MBUFLEN	A64_R(7)

/*
 * Emit routine to update the jump table.
 */
static void
emit_length(bpf_bin_stream *stream, __unused u_int value)
{

	printf("%s\n", __func__);

	if (stream->refs != NULL)
		(stream->refs)[stream->bpf_pc] += 4;
	stream->cur_ip += 4;
}

/*
 * Emit routine to output the actual binary code.
 */
static void
emit_code(bpf_bin_stream *stream, u_int value)
{

	printf("emitting 0x%08x\n", value);

	*((u_int *)(stream->ibuf + stream->cur_ip)) = value;
	stream->cur_ip += 4;
}

/*
 * Manual used:
 * ARM Architecture Reference Manual
 * ARMv8, for ARMv8-A architecture profile, Beta
 * pdf, 44134380 bytes
 */

static void
stp(emit_func emitm, bpf_bin_stream *stream,
    uint32_t reg_list)
{
	uint32_t instr;

	/* Load/store register pair (post-indexed) */
	instr = (1 << 23) | (1 << 27) | (1 << 29);
	instr |= (OPC_STP << OPC_S);

	emitm(stream, instr);
}

/*
 * C6.6.20 B
 * Unconditional branch (immediate), PC-relative offset
 */
static void
arm64_branch_i(emit_func emitm, bpf_bin_stream *stream,
    uint32_t imm26)
{
	uint32_t instr;

	instr = (1 << 28) | (1 << 26);
	instr |= (imm26 << IMM26_S);

	emitm(stream, instr);
}

/*
 * C6.6.28 BR
 * Unconditional branch (register)
 */
static void
arm64_branch_ret(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 31) | (1 << 30) | (1 << 28);
	instr |= (1 << 26) | (1 << 25);
	instr |= (0b10 << 21);		/* op BranchType_RET */
	instr |= (0b11111 << 16);	/* op2 */
	instr |= (rn << RN_S);

	emitm(stream, instr);
}

static void
ret(emit_func emitm, bpf_bin_stream *stream)
{

	arm64_branch_ret(emitm, stream, A64_LR);
}

/*
 * C6.6.19 B.cond
 * Conditional branch (immediate), PC-relative offset
 */
static void
arm64_branch_cond(emit_func emitm, bpf_bin_stream *stream,
    uint32_t cond, uint32_t val)
{
	uint32_t instr;
	uint32_t imm19;

	imm19 = (val / 4);
	imm19 += 1;

	instr = (1 << 30) | (1 << 28) | (1 << 26);
	instr |= (imm19 << IMM19_S);
	instr |= (cond << COND_S);

	emitm(stream, instr);
}

/*
 * C6.6.126 MOVK
 *    Move 16-bit immediate into register, keeping other bits unchanged:
 *    Rd<shift+15:shift> = imm16
 * C6.6.127 MOVN
 *    Move inverse of shifted 16-bit immediate to register:
 *    Rd = NOT (LSL (imm16, shift))
 * C6.6.128 MOVZ
 *    Move shifted 16-bit immediate to register:
 *    Rd = LSL (imm16, shift)
 */
static void
arm64_mov_wide(emit_func emitm, bpf_bin_stream *stream,
    uint32_t op, uint32_t rd, uint32_t imm16, uint32_t shift)
{
	uint32_t instr;

	instr = (1 << 31); /* 64 bit datasize */
	instr |= (op << MOVE_WIDE_OP_S);
	instr |= (1 << 28) | (1 << 25) | (1 << 23);
	instr |= (imm16 << IMM16_S);
	instr |= (rd << RD_S);
	instr |= (shift / 16) << HW_S;

	emitm(stream, instr);
}

static void
arm64_mov_i(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint64_t val)
{
	uint32_t shift;
	uint64_t tmp;

	arm64_mov_wide(emitm, stream, MOVE_WIDE_OP_Z,
	    rd, (val & 0xffff), 0);
	tmp = (val >> 16);
	shift = 16;

	while (tmp != 0) {
		if (tmp & 0xffff)
			arm64_mov_wide(emitm, stream, MOVE_WIDE_OP_K,
			    rd, (tmp & 0xffff), shift);
		tmp >>= 16;
		shift += 16;
	}
}

/*
 * C6.6.125 MOV (register)
 * Move register to register: Rd = Rm
 */
static void
arm64_mov_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint64_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64 bit datasize */
	instr |= (1 << 29) | (1 << 27) | (1 << 25);
	instr |= (rm << RM_S) | (rd << RD_S);
	instr |= (A64_R(31) << RN_S);

	emitm(stream, instr);
}

/*
 * C6.6.4  ADD (immediate)
 * Add (immediate): Rd = Rn + shift(imm)
 */
static void
arm64_add_i(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t imm12)
{
	uint32_t instr;

	instr = (1 << 31); /* 64 bit datasize */
	instr |= (1 << 28) | (1 << 24);
	instr |= (rd << RD_S);
	instr |= (rn << RN_S);
	instr |= (imm12 << IMM12_S);

	emitm(stream, instr);
}

/*
 * C6.6.5  ADD (shifted register)
 * Add (shifted register): Rd = Rn + shift(Rm, amount)
 */
static void
arm64_add_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64 bit datasize */
	instr |= (1 << 27) | (1 << 25) | (1 << 24);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
arm64_add(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t val)
{

	if (val > 0xfff) {
		arm64_mov_i(emitm, stream, A64_R(1), val);
		arm64_add_r(emitm, stream, rd, rn, A64_R(1));
	} else {
		arm64_add_i(emitm, stream, rd, rn, val);
	}
}

/*
 * C6.6.83 LDR (immediate), Unsigned offset
 */
static void
arm64_ldr(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rt, uint32_t rn, uint32_t imm9)
{
	uint32_t instr;

	instr = (0b10 << 30);	/* 32-bit variant */
	instr |= (1 << 29) | (1 << 28) | (1 << 27);
	instr |= (1 << 22);
	instr |= (1 << 24);
	instr |= (rn << RN_S) | (rt << RT_S);
	instr |= (imm9 << IMM9_S);

	emitm(stream, instr);
}

/*
 * C6.6.88 LDRH (immediate), Unsigned offset
 */
static void
arm64_ldrh(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rt, uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 30);
	instr |= (1 << 29) | (1 << 28) | (1 << 27);
	instr |= (1 << 22);
	instr |= (1 << 24);
	//instr |= (1 << 11) | (1 << 10);
	instr |= (rn << RN_S) | (rt << RT_S);
	
	emitm(stream, instr);
}
/*
 * C6.6.86 LDRB (immediate), Unsigned offset
 */
static void
arm64_ldrb(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rt, uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 29) | (1 << 28) | (1 << 27);
	instr |= (1 << 22);
	instr |= (1 << 24);
	instr |= (rn << RN_S) | (rt << RT_S);

	emitm(stream, instr);
}

/*
 * C6.6.149 REV
 * Reverse bytes
 */
static void
arm64_rev(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 30) | (1 << 28) | (1 << 27);
	instr |= (1 << 25) | (1 << 23) | (1 << 22);
	instr |= (rd << RD_S) | (rn << RN_S);
	instr |= (0b10 << 10); /* 32-bit variant */
	instr |= (rd << RD_S) | (rn << RN_S);

	emitm(stream, instr);
}

/*
 * C6.6.150 REV16
 * Reverse bytes in 16-bit halfwords
 */
static void
arm64_rev16(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 30) | (1 << 28) | (1 << 27);
	instr |= (1 << 25) | (1 << 23) | (1 << 22);
	instr |= (1 << 10);
	instr |= (rd << RD_S) | (rn << RN_S);

	emitm(stream, instr);
}

/*
 * C6.6.46 CMP (shifted register)
 * Compare (shifted register), setting the condition flags and
 * discarding the result: Rn - shift(Rm,amount)
 */
static void
arm64_cmp_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 30) | (1 << 29) | (1 << 27);
	instr |= (1 << 25) | (1 << 24);
	instr |= (rn << RN_S) | (rm << RM_S);
	instr |= (A64_R(31) << RD_S);

	emitm(stream, instr);
}

/*
 * C6.6.209 TST (immediate)
 * Test bits (immediate), setting the condition flags and
 * discarding the result: Rn AND imm
 */
static void
arm64_tst_i(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	uint32_t immr;
	uint32_t imms;
	uint32_t sz;

	sz = 64;
	immr = (unsigned)-(val) % sz;
	imms = sz - 1 - (val);

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 30) | (1 << 29);
	instr |= (1 << 28) | (1 << 25);
	instr |= (immr << IMMR_S);
	instr |= (imms << IMMS_S);
	instr |= (rn << RN_S);
	instr |= (A64_R(31) << RD_S);	/* discard result */
	//if (val & (1 << 12))
	//	instr |= IMM_N;

	emitm(stream, instr);
}

/*
 * C6.6.210 TST (shifted register)
 * Test bits (shifted register), setting the condition flags and
 * discarding the result: Rn AND shift(Rm, amount)
 */
static void
arm64_tst_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rn,
    uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 30) | (1 << 29);
	instr |= (1 << 27) | (1 << 25);
	instr |= (rn << RN_S);
	instr |= (rm << RM_S);
	instr |= (A64_R(31) << RD_S);	/* discard result */

	emitm(stream, instr);
}

/*
 * C6.6.11 AND (immediate)
 * Bitwise AND (immediate): Rd = Rn AND imm
 */
static void
arm64_and_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	uint32_t immr;
	uint32_t imms;

	if (val > 0xfff)
		panic("%s: implement me\n", __func__);

	uint32_t sz;
	sz = 64;
	immr = (unsigned)-(val) % sz;
	imms = sz - 1 - (val);

	printf("immr 0x%08x imms 0x%08x\n", immr, imms);

	instr = (1 << 31); /* 64-bit variant */
	instr |= IMM_N;
	instr |= (1 << 28) | (1 << 25);
	instr |= (immr << IMMR_S);
	instr |= (imms << IMMS_S);
	instr |= (rn << RN_S);
	instr |= (rd << RD_S);

	emitm(stream, instr);
}

/*
 * C6.6.12 AND (shifted register)
 * Bitwise AND (shifted register): Rd = Rn AND shift(Rm, amount)
 */
static void
arm64_and_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 27) | (1 << 25);
	instr |= (rm << RM_S);
	instr |= (rn << RN_S);
	instr |= (rd << RD_S);

	emitm(stream, instr);
}

/*
 * C6.6.114 LSL (immediate)
 * Logical shift left (immediate): Rd = LSL(Rn, shift)
 */
static void
arm64_lsl_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	uint32_t immr;
	uint32_t imms;
	uint32_t sz;

	sz = 64;
	immr = (unsigned)-(val) % sz;
	imms = sz - 1 - (val);

	printf("immr 0x%08x imms 0x%08x\n", immr, imms);
	printf("val 0x%08x, unsigned -val is 0x%08x\n", val, (unsigned)-val);

	if (imms == 63)
		panic("unexpected imms\n");

	instr = (1 << 31); /* 64-bit variant */
	instr |= IMM_N;
	instr |= (1 << 30);
	instr |= (1 << 28) | (1 << 25) | (1 << 24);
	instr |= (immr << IMMR_S);
	instr |= (imms << IMMS_S);
	instr |= (rn << RN_S);
	instr |= (rd << RD_S);

	emitm(stream, instr);
}

/*
 * C6.6.117 LSR (immediate)
 * Logical shift right (immediate): Rd = LSR(Rn, shift)
 */
static void
arm64_lsr_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	uint32_t immr;
	uint32_t imms;
	//uint32_t sz;

	//sz = 64;
	immr = val; //(unsigned)-(val) % sz;
	imms = 0b111111; //sz - 1 - (val);

	printf("immr 0x%08x imms 0x%08x\n", immr, imms);
	//printf("val 0x%08x, unsigned -val is 0x%08x\n", val, (unsigned)-val);

	instr = (1 << 31); /* 64-bit variant */
	instr |= IMM_N;
	instr |= (1 << 30);
	instr |= (1 << 28) | (1 << 25) | (1 << 24);
	instr |= (immr << IMMR_S);
	instr |= (imms << IMMS_S);
	instr |= (rn << RN_S);
	instr |= (rd << RD_S);

	emitm(stream, instr);
}

/*
 * C6.6.116 LSR (register)
 * Logical shift right (register): Rd = LSR(Rn, Rm)
 */
static void
arm64_lsr_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 28) | (1 << 27) | (1 << 25);
	instr |= (1 << 23) | (1 << 22);
	instr |= (1 << 13) | (1 << 10);
	instr |= (rn << RN_S) | (rd << RD_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

/*
 * C6.6.113 LSL (register)
 * Logical shift left (register): Rd = LSL(Rn, Rm)
 */
static void
arm64_lsl_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 28) | (1 << 27) | (1 << 25);
	instr |= (1 << 23) | (1 << 22);
	instr |= (1 << 13);
	instr |= (rn << RN_S) | (rd << RD_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

/*
 * C6.6.196 SUB (shifted register)
 * Subtract (shifted register): Rd = Rn - shift(Rm, amount)
 */
static void
arm64_sub_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 30) | (1 << 27) | (1 << 25);
	instr |= (1 << 24);
	instr |= (rn << RN_S) | (rm << RM_S);
	instr |= (rd << RD_S);

	emitm(stream, instr);
}

/*
 * C6.6.195 SUB (immediate)
 * Subtract (immediate): Rd = Rn - shift(imm)
 */
static void
arm64_sub_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t imm12)
{
	uint32_t instr;

	if (imm12 > 0xfff)
		panic("%s: implement me", __func__);

	instr = (1 << 30) | (1 << 28) | (1 << 24);
	instr |= (rn << RN_S) | (rd << RD_S);
	instr |= (imm12 << IMM12_S);

	emitm(stream, instr);
}

/*
 * C6.6.142 ORR (shifted register)
 * Bitwise inclusive OR (shifted register):
 * Rd = Rn OR shift(Rm, amount)
 */
static void
arm64_orr_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 29) | (1 << 27) | (1 << 25);
	instr |= (rn << RN_S) | (rd << RD_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

/*
 * C6.6.214 UDIV
 * Rd = Rn / Rm
 */
static void
arm64_udiv_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 28) | (1 << 27) | (1 << 25);
	instr |= (1 << 23) | (1 << 22) | (1 << 11);
	instr |= (rn << RN_S) | (rd << RD_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

/*
 * C6.6.133 MUL
 * Multiply: Rd = Rn * Rm
 */
static void
arm64_mul_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 28) | (1 << 27);
	instr |= (1 << 25) | (1 << 24);
	instr |= (rn << RN_S) | (rd << RD_S);
	instr |= (rm << RM_S) | (A64_R(31) << RA_S);

	emitm(stream, instr);
}

/*
 * C6.6.179 STR (register)
 */
static void
arm64_str_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rt,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (0b11 << 30); /* 64-bit variant */
	instr |= (1 << 29) | (1 << 28) | (1 << 27);
	instr |= (1 << 21) | (1 << 11);
	instr |= (rn << RN_S) | (rt << RT_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

/*
 * C6.6.178 STR (immediate), Unsigned offset
 */
static void
arm64_str_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rt,
    uint32_t rn, uint32_t imm12)
{
	uint32_t instr;

	instr = (0b11 << 30); /* 64-bit variant */
	instr |= (1 << 29) | (1 << 28) | (1 << 27);
	instr |= (1 << 24);
	instr |= (rn << RN_S) | (rt << RT_S);
	instr |= (imm12 << IMM12_S);

	emitm(stream, instr);
}

static void
jcc(emit_func emitm, bpf_bin_stream *stream, struct bpf_insn *ins,
    uint8_t cond1, uint8_t cond2)
{
	uint32_t offs;

	if (ins->jt != 0) {
		offs = stream->refs[stream->bpf_pc + ins->jt] - \
		    stream->refs[stream->bpf_pc];
		//printf("offs 0x%08x\n", offs);

		/* TODO: check if offs fit imm19 */

		arm64_branch_cond(emitm, stream, cond1, offs);
		//arm32 branch(emitm, stream, cond1, offs);
	}

	if (ins->jf != 0) {
		offs = stream->refs[stream->bpf_pc + ins->jf] - \
		    stream->refs[stream->bpf_pc];
		//printf("offs 0x%08x\n", offs);

		/* TODO: check if offs fit imm19 */

		arm64_branch_cond(emitm, stream, cond2, offs);
		//arm32 branch(emitm, stream, cond2, offs);
	}
}

/*
 * Scan the filter program and find possible optimization.
 */
static int
bpf_jit_optimize(struct bpf_insn *prog, u_int nins)
{
	int flags;
	u_int i;

	printf("%s\n", __func__);

	/* Do we return immediately? */
	if (BPF_CLASS(prog[0].code) == BPF_RET)
		return (BPF_JIT_FRET);

	for (flags = 0, i = 0; i < nins; i++) {
		switch (prog[i].code) {
		case BPF_LD|BPF_W|BPF_ABS:
		case BPF_LD|BPF_H|BPF_ABS:
		case BPF_LD|BPF_B|BPF_ABS:
		case BPF_LD|BPF_W|BPF_IND:
		case BPF_LD|BPF_H|BPF_IND:
		case BPF_LD|BPF_B|BPF_IND:
		case BPF_LDX|BPF_MSH|BPF_B:
			flags |= BPF_JIT_FPKT;
			break;
		case BPF_LD|BPF_MEM:
		case BPF_LDX|BPF_MEM:
		case BPF_ST:
		case BPF_STX:
			flags |= BPF_JIT_FMEM;
			break;
		case BPF_LD|BPF_W|BPF_LEN:
		case BPF_LDX|BPF_W|BPF_LEN:
			flags |= BPF_JIT_FLEN;
			break;
		case BPF_JMP|BPF_JA:
		case BPF_JMP|BPF_JGT|BPF_K:
		case BPF_JMP|BPF_JGE|BPF_K:
		case BPF_JMP|BPF_JEQ|BPF_K:
		case BPF_JMP|BPF_JSET|BPF_K:
		case BPF_JMP|BPF_JGT|BPF_X:
		case BPF_JMP|BPF_JGE|BPF_X:
		case BPF_JMP|BPF_JEQ|BPF_X:
		case BPF_JMP|BPF_JSET|BPF_X:
			flags |= BPF_JIT_FJMP;
			break;
		}
		if (flags == BPF_JIT_FLAG_ALL)
			break;
	}

	return (flags);
}

/*
 * Function that does the real stuff.
 */
bpf_filter_func
bpf_jit_compile(struct bpf_insn *prog, u_int nins, size_t *size)
{
	int flags, fret, fpkt, fmem, fjmp, flen;
	bpf_bin_stream stream;
	struct bpf_insn *ins;
	//uint32_t reg_list;
	u_int i, pass;

	printf("%s: nins %d\n", __func__, nins);

	/*
	 * NOTE: Do not modify the name of this variable, as it's used by
	 * the macros to emit code.
	 */
	emit_func emitm;

	flags = bpf_jit_optimize(prog, nins);
	fret = (flags & BPF_JIT_FRET) != 0;
	fpkt = (flags & BPF_JIT_FPKT) != 0;
	fmem = (flags & BPF_JIT_FMEM) != 0;
	fjmp = (flags & BPF_JIT_FJMP) != 0;
	flen = (flags & BPF_JIT_FLEN) != 0;

	if (fret)
		nins = 1;

	memset(&stream, 0, sizeof(stream));

	/* Allocate the reference table for the jumps. */
	if (fjmp) {
#ifdef _KERNEL
		stream.refs = malloc((nins + 1) * sizeof(u_int), M_BPFJIT,
		    M_NOWAIT | M_ZERO);
#else
		stream.refs = calloc(nins + 1, sizeof(u_int));
#endif
		if (stream.refs == NULL)
			return (NULL);
	}

	/*
	 * The first pass will emit the lengths of the instructions
	 * to create the reference table.
	 */
	emitm = emit_length;

	//reg_list = (1 << REG_A) | (1 << REG_X);
	//reg_list |= (1 << REG_MBUF) | (1 << REG_MBUFLEN);
	//reg_list |= (1 << ARM_LR); /* Used for jit_udiv */

	for (pass = 0; pass < 2; pass++) {
		ins = prog;

		if (fpkt || flen || fmem) {
			//arm32 push(emitm, &stream, reg_list);
		}

		/* Create the procedure header. */
		if (fmem) {
			printf("fmem\n");
			/* Using stack for memory scratch space */
			//arm32 sub(emitm, &stream, A64_SP, A64_SP,
			//   BPF_MEMWORDS * sizeof(uint32_t));
		}
		if (flen) {
			printf("flen\n");
		}
		if (fpkt) {
			printf("fpkt\n");
			arm64_mov_r(emitm, &stream, REG_MBUF, A64_R(0));
		}

		for (i = 0; i < nins; i++) {
			stream.bpf_pc++;

			printf("ins code %d\n", ins->code);
			switch (ins->code) {
			default:
#ifdef _KERNEL
				return (NULL);
#else
				abort();
#endif

			case BPF_RET|BPF_K:
				/* accept k bytes */
				printf("BPF_RET|BPF_K, ins->k 0x%08x\n", ins->k);
				arm64_mov_i(emitm, &stream, A64_R(0), ins->k);

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				if (fpkt || flen || fmem) {
					//pop(emitm, &stream, reg_list);
				}

				ret(emitm, &stream);

				break;

			case BPF_RET|BPF_A:
				/* accept A bytes */
				printf("BPF_RET|BPF_A\n");
				arm64_mov_r(emitm, &stream, A64_R(0), REG_A);

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				if (fpkt || flen || fmem) {
					//pop(emitm, &stream, reg_list);
				}

				ret(emitm, &stream);

				break;

			case BPF_LD|BPF_W|BPF_ABS:
				/* A <- P[k:4] */
				printf("BPF_LD|BPF_W|BPF_ABS\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load word from offset */
				arm64_ldr(emitm, &stream, A64_R(0), A64_R(0), 0);

				/* Reverse as network packets are big-endian */
				arm64_rev(emitm, &stream, REG_A, A64_R(0));

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LD|BPF_H|BPF_ABS:
				/* A <- P[k:2] */
				printf("BPF_LD|BPF_H|BPF_ABS: ins->k 0x%x\n", ins->k);

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load half word from offset */
				arm64_ldrh(emitm, &stream, A64_R(0), A64_R(0));

				/* Reverse as network packets are big-endian */
				arm64_rev16(emitm, &stream, REG_A, A64_R(0));

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LD|BPF_B|BPF_ABS:
				/* A <- P[k:1] */
				printf("BPF_LD|BPF_B|BPF_ABS: ins->k 0x%x\n", ins->k);

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load byte from offset */
				arm64_ldrb(emitm, &stream, REG_A, A64_R(0));

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LD|BPF_W|BPF_LEN:
				/* A <- len */
				printf("BPF_LD|BPF_W|BPF_LEN\n");
				arm64_mov_r(emitm, &stream, REG_A, REG_MBUFLEN);
				break;

			case BPF_LDX|BPF_W|BPF_LEN:
				/* X <- len */
				printf("BPF_LDX|BPF_W|BPF_LEN\n");
				arm64_mov_r(emitm, &stream, REG_X, REG_MBUFLEN);
				break;

			case BPF_LD|BPF_W|BPF_IND:
				/* A <- P[X+k:4] */
				printf("BPF_LD|BPF_W|BPF_IND\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Add X */
				arm64_add_r(emitm, &stream, A64_R(1), A64_R(1), REG_X);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load word from offset */
				arm64_ldr(emitm, &stream, A64_R(0), A64_R(0), 0);

				/* Change byte order as network packets are big-endian */
				arm64_rev(emitm, &stream, REG_A, A64_R(0));

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LD|BPF_H|BPF_IND:
				/* A <- P[X+k:2] */
				printf("BPF_LD|BPF_H|BPF_IND\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Add X */
				arm64_add_r(emitm, &stream, A64_R(1), A64_R(1), REG_X);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load half word from offset */
				arm64_ldrh(emitm, &stream, A64_R(0), A64_R(0));

				/* Reverse as network packets are big-endian */
				arm64_rev16(emitm, &stream, REG_A, A64_R(0));

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LD|BPF_B|BPF_IND:
				/* A <- P[X+k:1] */
				printf("BPF_LD|BPF_B|BPF_IND\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Add X */
				arm64_add_r(emitm, &stream, A64_R(1), A64_R(1), REG_X);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load byte from offset */
				arm64_ldrb(emitm, &stream, REG_A, A64_R(0));

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LDX|BPF_MSH|BPF_B: //implement me for dst port 22
				/* X <- 4*(P[k:1]&0xf) */
				printf("BPF_LDX|BPF_MSH|BPF_B ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);

				/* Load byte from offset */
				arm64_ldrb(emitm, &stream, A64_R(1), A64_R(0));

				/* And 0xf */
				arm64_mov_i(emitm, &stream, A64_R(3), 0xf);
				arm64_and_r(emitm, &stream, A64_R(1), A64_R(1), A64_R(3));

				/* Mult by 4 */
				arm64_lsl_i(emitm, &stream, REG_X, A64_R(1), 2);

				if (fmem) {
					arm64_add_i(emitm, &stream, A64_SP, A64_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}
				break;

			case BPF_LD|BPF_IMM:
				/* A <- k */
				printf("BPF_LD|BPF_IMM\n");
				arm64_mov_i(emitm, &stream, REG_A, ins->k);
				break;

			case BPF_LDX|BPF_IMM:
				/* X <- k */
				printf("BPF_LDX|BPF_IMM\n");
				arm64_mov_i(emitm, &stream, REG_X, ins->k);
				break;

			case BPF_LD|BPF_MEM:
				/* A <- M[k] */
				printf("BPF_LD|BPF_MEM\n");
				arm64_ldr(emitm, &stream, REG_A, A64_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_LDX|BPF_MEM:
				/* X <- M[k] */
				printf("BPF_LDX|BPF_MEM\n");
				arm64_ldr(emitm, &stream, REG_X, A64_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_ST:
				/* M[k] <- A */
				printf("BPF_ST not tested\n");
				arm64_str_i(emitm, &stream, REG_A, A64_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_STX:
				/* M[k] <- X */
				printf("BPF_STX not tested\n");
				arm64_str_i(emitm, &stream, REG_X, A64_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_JMP|BPF_JA:
				/* pc += k */
				printf("BPF_JMP|BPF_JA\n");
				arm64_branch_i(emitm, &stream, ins->k);
				break;

			case BPF_JMP|BPF_JGT|BPF_K:
				/* pc += (A > k) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_cmp_r(emitm, &stream, REG_A, A64_R(1));
				jcc(emitm, &stream, ins, COND_GT, COND_LE);
				break;

			case BPF_JMP|BPF_JGE|BPF_K:
				/* pc += (A >= k) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_K\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_cmp_r(emitm, &stream, REG_A, A64_R(1));
				jcc(emitm, &stream, ins, COND_GE, COND_LT);
				break;

			case BPF_JMP|BPF_JEQ|BPF_K:
				/* pc += (A == k) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_cmp_r(emitm, &stream, REG_A, A64_R(1));
				jcc(emitm, &stream, ins, COND_EQ, COND_NE);
				break;

			case BPF_JMP|BPF_JSET|BPF_K: //implement me for dst port 22
				/* pc += (A & k) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_tst_r(emitm, &stream, REG_A, A64_R(1));
				jcc(emitm, &stream, ins, COND_NE, COND_EQ);
				break;

			case BPF_JMP|BPF_JGT|BPF_X:
				/* pc += (A > X) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_GT, COND_LE);
				break;

			case BPF_JMP|BPF_JGE|BPF_X:
				/* pc += (A >= X) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_GE, COND_LT);
				break;

			case BPF_JMP|BPF_JEQ|BPF_X:
				/* pc += (A == X) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_EQ, COND_NE);
				break;

			case BPF_JMP|BPF_JSET|BPF_X:
				/* pc += (A & X) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_NE, COND_EQ);
				break;

			case BPF_ALU|BPF_ADD|BPF_X:
				/* A <- A + X */
				printf("BPF_ALU|BPF_ADD|BPF_X\n");
				arm64_add_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_SUB|BPF_X:
				/* A <- A - X */
				printf("BPF_ALU|BPF_SUB|BPF_X not tested: checkme\n");
				arm64_sub_r(emitm, &stream, REG_A, REG_X, REG_A);
				break;

			case BPF_ALU|BPF_MUL|BPF_X:
				/* A <- A * X */
				printf("BPF_ALU|BPF_MUL|BPF_X not tested\n");
				arm64_mul_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_DIV|BPF_X:
				/* A <- A / X */
				printf("BPF_ALU|BPF_DIV|BPF_X\n");
				arm64_udiv_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_AND|BPF_X:
				/* A <- A & X */
				printf("BPF_ALU|BPF_AND|BPF_X\n");
				arm64_and_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_OR|BPF_X:
				/* A <- A | X */
				printf("BPF_ALU|BPF_OR|BPF_X\n");
				arm64_orr_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_LSH|BPF_X:
				/* A <- A << X */
				printf("BPF_ALU|BPF_LSH|BPF_X\n");
				arm64_lsl_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_RSH|BPF_X:
				/* A <- A >> X */
				printf("BPF_ALU|BPF_RSH|BPF_X\n");
				arm64_lsr_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_ADD|BPF_K:
				/* A <- A + k */
				printf("BPF_ALU|BPF_ADD|BPF_K\n");
				arm64_add(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_SUB|BPF_K:
				/* A <- A - k */
				printf("BPF_ALU|BPF_SUB|BPF_K\n");
				arm64_sub_i(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_MUL|BPF_K:
				/* A <- A * k */
				printf("BPF_ALU|BPF_MUL|BPF_K not tested\n");
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_mul_r(emitm, &stream, REG_A, REG_A, A64_R(1));
				break;

			case BPF_ALU|BPF_DIV|BPF_K:
				/* A <- A / k */
				printf("BPF_ALU|BPF_DIV|BPF_K\n");
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_udiv_r(emitm, &stream, REG_A, REG_A, A64_R(1));
				break;

			case BPF_ALU|BPF_AND|BPF_K:
				/* A <- A & k */
				printf("BPF_ALU|BPF_AND|BPF_K ins->k 0x%x\n", ins->k);
				arm64_and_r(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_OR|BPF_K:
				/* A <- A | k */
				printf("BPF_ALU|BPF_OR|BPF_K\n");
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_orr_r(emitm, &stream, REG_A, REG_A, A64_R(1));
				break;

			case BPF_ALU|BPF_LSH|BPF_K:
				/* A <- A << k */
				printf("BPF_ALU|BPF_LSH|BPF_K\n");
				/* TODO: check 0xff fit lsl_i */
				arm64_lsl_i(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				break;

			case BPF_ALU|BPF_RSH|BPF_K:
				/* A <- A >> k */
				printf("BPF_ALU|BPF_RSH|BPF_K ins->k %d\n", ins->k);
				arm64_lsr_i(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				break;

			case BPF_ALU|BPF_NEG:
				/* A <- -A */
				printf("BPF_ALU|BPF_NEG\n");
				/* substruct from xzr */
				arm64_sub_r(emitm, &stream, REG_A, A64_R(31), REG_A);
				break;

			case BPF_MISC|BPF_TAX:
				/* X <- A */
				printf("BPF_MISC|BPF_TAX\n");
				arm64_mov_r(emitm, &stream, REG_X, REG_A);
				break;

			case BPF_MISC|BPF_TXA:
				/* A <- X */
				printf("BPF_MISC|BPF_TXA\n");
				arm64_mov_r(emitm, &stream, REG_A, REG_X);
				break;
			}
			ins++;
		}

		if (pass > 0)
			continue;

		*size = stream.cur_ip;
#ifdef _KERNEL
		stream.ibuf = malloc(*size, M_BPFJIT, M_NOWAIT);
		if (stream.ibuf == NULL)
			break;
#else
		stream.ibuf = mmap(NULL, *size, PROT_READ | PROT_WRITE,
		    MAP_ANON, -1, 0);
		if (stream.ibuf == MAP_FAILED) {
			stream.ibuf = NULL;
			break;
		}
#endif

		/*
		 * Modify the reference table to contain the offsets and
		 * not the lengths of the instructions.
		 */
		if (fjmp)
			for (i = 1; i < nins + 1; i++)
				stream.refs[i] += stream.refs[i - 1];

		/* Reset the counters. */
		stream.cur_ip = 0;
		stream.bpf_pc = 0;

		/* The second pass creates the actual code. */
		emitm = emit_code;
	}

	/*
	 * The reference table is needed only during compilation,
	 * now we can free it.
	 */
	if (fjmp)
#ifdef _KERNEL
		free(stream.refs, M_BPFJIT);
#else
		free(stream.refs);
#endif

#ifndef _KERNEL
	if (stream.ibuf != NULL &&
	    mprotect(stream.ibuf, *size, PROT_READ | PROT_EXEC) != 0) {
		munmap(stream.ibuf, *size);
		stream.ibuf = NULL;
	}
#endif

	if (stream.ibuf != NULL) {
		printf("compilation success: inst buf 0x%016lx\n", (uint64_t)stream.ibuf);
		breakpoint();
	} else {
		printf("compilation failed\n");
	}

	return ((bpf_filter_func)stream.ibuf);
}
