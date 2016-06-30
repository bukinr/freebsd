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
 * Wrapper around __aeabi_uidiv
 */
static uint32_t
jit_udiv(uint32_t dividend, uint32_t divisor)
{

	return (dividend / divisor);
}

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

#define	OPC_S		30
#define	OPC_LDP		0b10
#define	OPC_STP		0b10
#define	IMM7_S		15
#define	RT2_S		10
#define	RT1_S		0
#define	RN_S		5

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

#define	IMM26_S	0
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
arm64_branch_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rn)
{
	uint32_t instr;

#define	RN_S	5

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

	arm64_branch_r(emitm, stream, A64_LR);
}

#define	IMM19_S	5
#define	COND_S	0

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

#define	SHIFT_LSL	0
#define	SHIFT_LSR	1
#define	SHIFT_ASR	10
#define	SHIFT_S		22
#define	RD_S		0
#define	IMM12_S		10
/*
 * C6.6.4  ADD (immediate)
 * Add (immediate): Rd = Rn + shift(imm)
 */
static void
add_i(emit_func emitm, bpf_bin_stream *stream,
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

#define	RM_S	16
#define	IMM6_S	10
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

#define	MOVE_WIDE_OP_S	29
#define	MOVE_WIDE_OP_N	0
#define	MOVE_WIDE_OP_Z	2
#define	MOVE_WIDE_OP_K	3
#define	IMM16_S		5
#define	HW_S		21

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

#define	RT_S	0
#define	IMM9_S	12

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

	//instr = (OPCODE_CMP << OPCODE_S) | (COND_AL << COND_S);
	//instr |= (rd << RD_S) | (rm << RM_S);
	//instr |= (rn << RN_S) | (rm << RM_S);
	//instr |= COND_SET;

	instr = (1 << 31); /* 64-bit variant */
	instr |= (1 << 30) | (1 << 29) | (1 << 27);
	instr |= (1 << 25) | (1 << 24);
	instr |= (rn << RN_S) | (rm << RM_S);
	instr |= (A64_R(31) << RD_S);

	emitm(stream, instr);
}

#define	IMMR_S	16
#define	IMMS_S	10
#define	IMM_N	(1 << 22)

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

/* armv7 */

static int16_t
imm8m(uint32_t x)
{
	uint32_t rot;

	for (rot = 0; rot < 16; rot++) {
		if ((x & ~ror32(0xff, 2 * rot)) == 0) {
			return (rol32(x, 2 * rot) | (rot << 8));
		}
	}

	return (-1);
}

static void
push(emit_func emitm, bpf_bin_stream *stream,
    uint32_t reg_list)
{
	uint32_t instr;

	instr = (1 << 27);
	instr |= (ARM_SP << RN_S);
	instr |= (COND_AL << COND_S);
	instr |= (WRITE_BACK | PRE_INDEX);
	instr |= (reg_list);

	emitm(stream, instr);
}

static void
pop(emit_func emitm, bpf_bin_stream *stream,
    uint32_t reg_list)
{
	uint32_t instr;

	instr = (1 << 27);
	instr |= (ARM_SP << RN_S);
	instr |= (COND_AL << COND_S);
	instr |= (WRITE_BACK | POST_INDEX | UP_BIT | OP_LOAD);
	instr |= (reg_list);

	emitm(stream, instr);
}

static void
branch(emit_func emitm, bpf_bin_stream *stream,
    uint32_t cond, uint32_t offs)
{
	uint32_t instr;

	instr = (1 << 25) | (1 << 27);
	instr |= (cond << COND_S);
	instr |= (offs >> 2);

	emitm(stream, instr);
}

/* Branch and Exchange (BX) */
static void
branch_lx(emit_func emitm, bpf_bin_stream *stream,
    uint32_t cond, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 24) | (1 << 21) | (0xfff << 8);
	instr |= (1 << 4);
	instr |= (1 << 5); /* link */
	instr |= (cond << COND_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

static void
mov_i(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t imm)
{
	uint32_t instr;

	instr = (OPCODE_MOV << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (imm << IMM_S);
	instr |= IMM_OP;	/* operand 2 is an immediate value */

	emitm(stream, instr);
}

static void
movw(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t imm)
{
	uint32_t instr;

	instr = ARM_MOVW | (COND_AL << COND_S);
	instr |= (imm >> 12) << RN_S;
	instr |= (rd << RD_S) | (imm & 0xfff);

	emitm(stream, instr);
}

static void
movt(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t imm)
{
	uint32_t instr;

	instr = ARM_MOVT | (COND_AL << COND_S);
	instr |= (imm >> 12) << RN_S;
	instr |= (rd << RD_S) | (imm & 0xfff);

	emitm(stream, instr);
}

static void
mov(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t val)
{
	int imm12;

	printf("%s\n", __func__);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		mov_i(emitm, stream, rd, imm12);
	} else {
		printf("to emit MOVW\n");
		movw(emitm, stream, rd, val & 0xffff);

		if (val > 0xffff) {
			printf("to emit MOVT\n");
			movt(emitm, stream, rd, (val >> 16));
		}
	}
}

static void
mul(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t rs, uint32_t rn)
{
	uint32_t instr;

	/* Rd:=Rm*Rs */
	instr = (1 << 4) | (1 << 7);
	instr |= (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rs << RS_S) | (rm << RM_S);

	if (rn > 0) {
		/* Rd:=Rm*Rs+Rn */
		instr |= MUL_ACCUMULATE;
		instr |= (rn << RN_S);
	}

	emitm(stream, instr);
}

static void
tst(emit_func emitm, bpf_bin_stream *stream, uint32_t rn,
    uint32_t val)
{
	uint32_t instr;
	int imm12;

	printf("%s\n", __func__);

	instr = (OPCODE_TST << OPCODE_S) | (COND_AL << COND_S);
	instr |= COND_SET;
	instr |= (rn << RN_S);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		printf("%s, imm12 >= 0\n", __func__);
		instr |= (imm12 << IMM_S);
		instr |= IMM_OP; /* operand 2 is an immediate value */
	} else {
		printf("%s, imm12 < 0\n", __func__);
		mov(emitm, stream, ARM_R0, val);
		instr |= (ARM_R0 << RM_S);
	}

	emitm(stream, instr);
}

static void
tst_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rn,
    uint32_t rm)
{
	uint32_t instr;

	printf("%s\n", __func__);

	instr = (OPCODE_TST << OPCODE_S) | (COND_AL << COND_S);
	instr |= COND_SET;
	instr |= (rn << RN_S);
	instr |= (rm << RM_S);

	emitm(stream, instr);
}

static void
lsl(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t imm)
{
	uint32_t instr;

	if (imm > 31)
		panic("lsl");

	instr = ARM_LSL_I | (COND_AL << COND_S);
	instr |= (imm << 7);
	instr |= (rd << RD_S | rm << RM_S);

	emitm(stream, instr);
}

static void
lsr(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t imm)
{
	uint32_t instr;

	if (imm > 31)
		panic("lsr");

	instr = ARM_LSR_I | (COND_AL << COND_S);
	instr |= (imm << 7);
	instr |= (rd << RD_S | rm << RM_S);

	emitm(stream, instr);
}

static void
lsl_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t rs)
{
	uint32_t instr;

	instr = ARM_LSL_R | (COND_AL << COND_S);
	instr |= (rs << RS_S);
	instr |= (rd << RD_S | rm << RM_S);

	emitm(stream, instr);
}

static void
lsr_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t rs)
{
	uint32_t instr;

	instr = ARM_LSR_R | (COND_AL << COND_S);
	instr |= (rs << RS_S);
	instr |= (rd << RD_S | rm << RM_S);

	emitm(stream, instr);
}

static void
add(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	int imm12;

	instr = (OPCODE_ADD << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S);
	instr |= (rn << RN_S);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		instr |= (val << IMM_S);
		instr |= IMM_OP; /* operand 2 is an immediate value */
	} else {
		mov(emitm, stream, ARM_R1, val);
		instr |= (ARM_R1 << RM_S);
	}

	emitm(stream, instr);
}

static void
sub(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	int imm12;

	instr = (OPCODE_SUB << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S);
	instr |= (rn << RN_S);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		instr |= (val << IMM_S);
		instr |= IMM_OP;
	} else {
		mov(emitm, stream, ARM_R1, val);
		instr |= (ARM_R1 << RM_S);
	}

	emitm(stream, instr);
}

static void
orr(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	int imm12;

	instr = (OPCODE_ORR << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S);
	instr |= (rn << RN_S);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		instr |= (val << IMM_S);
		instr |= IMM_OP;
	} else {
		mov(emitm, stream, ARM_R1, val);
		instr |= (ARM_R1 << RM_S);
	}

	emitm(stream, instr);
}

static void
rsb_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;

	printf("%s\n", __func__);

	instr = (OPCODE_RSB << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S | rn << RN_S);

	instr |= (val << IMM_S);
	instr |= IMM_OP;	/* operand 2 is an immediate value */

	emitm(stream, instr);
}

static void
rsb(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	int imm12;

	printf("%s\n", __func__);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		rsb_i(emitm, stream, rd, rn, val);
	} else {
		mov(emitm, stream, ARM_R1, val);

		instr = (OPCODE_RSB << OPCODE_S) | (COND_AL << COND_S);
		instr |= (rd << RD_S | rn << RN_S);
		instr |= (ARM_R1 << RM_S);
		emitm(stream, instr);
	}
}

static void
and_i(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;

	printf("%s\n", __func__);

	instr = (OPCODE_AND << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S | rn << RN_S);
	instr |= (val << IMM_S);
	instr |= IMM_OP;	/* operand 2 is an immediate value */

	emitm(stream, instr);
}

static void
and(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rn, uint32_t val)
{
	uint32_t instr;
	int imm12;

	printf("%s\n", __func__);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		and_i(emitm, stream, rd, rn, val);
	} else {
		mov(emitm, stream, ARM_R1, val);

		instr = (OPCODE_AND << OPCODE_S) | (COND_AL << COND_S);
		instr |= (rd << RD_S | rn << RN_S);
		instr |= (ARM_R1 << RM_S);
		emitm(stream, instr);
	}
}

static void
mov_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_MOV << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
cmp_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_CMP << OPCODE_S) | (COND_AL << COND_S);
	//instr |= (rd << RD_S) | (rm << RM_S);
	instr |= (rn << RN_S) | (rm << RM_S);
	instr |= COND_SET;

	emitm(stream, instr);
}

static void
add_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_ADD << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S);
	instr |= (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
orr_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_ORR << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
rsb_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_RSB << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
and_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_AND << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

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

static void
str(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm, uint32_t offs)
{
	uint32_t instr;

	instr = (1 << 26);
	instr |= (COND_AL << COND_S) | WORD_BIT | OP_STORE;
	instr |= UP_BIT | PRE_INDEX;
	instr |= (rd << RD_S) | (rm << RM_S);

	if (offs > 0) {
		if (offs > 0xfff)
			panic("offset is too big");
		instr |= offs;
	}

	emitm(stream, instr);
}

static void
ldr(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm, uint32_t offs)
{
	uint32_t instr;

	instr = (1 << 26);
	instr |= (COND_AL << COND_S) | WORD_BIT | OP_LOAD;
	instr |= UP_BIT | PRE_INDEX;
	instr |= (rd << RD_S) | (rm << RM_S);

	if (offs > 0) {
		if (offs > 0xfff)
			panic("offset is too big");
		instr |= offs;
	}

	emitm(stream, instr);
}

static void
ldrb(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 26);
	instr |= (COND_AL << COND_S) | BYTE_BIT | OP_LOAD;
	instr |= UP_BIT | PRE_INDEX;
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
ldrh(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 4) | (1 << 7);
	instr |= (COND_AL << COND_S) | OP_LOAD;
	instr |= (BYTE_BIT | UP_BIT | PRE_INDEX);
	instr |= (SH_UH << SH_S);
	instr |= (rd << RD_S) | (rn << RN_S);

	emitm(stream, instr);
}

static void
rev(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = ARM_REV;
	instr |= (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);
}

static void
rev16(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = ARM_REV16;
	instr |= (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);
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
	uint32_t reg_list;
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

	reg_list = (1 << REG_A) | (1 << REG_X);
	reg_list |= (1 << REG_MBUF) | (1 << REG_MBUFLEN);
	reg_list |= (1 << ARM_LR); /* Used for jit_udiv */

	for (pass = 0; pass < 2; pass++) {
		ins = prog;

		if (fpkt || flen || fmem) {
			//arm32 push(emitm, &stream, reg_list);
		}

		/* Create the procedure header. */
		if (fmem) {
			printf("fmem\n");
		//	PUSH(RBP);
		//	MOVrq(RSP, RBP);
		//	SUBib(BPF_MEMWORDS * sizeof(uint32_t), RSP);

			/* Using stack for memory scratch space */
			//arm32 sub(emitm, &stream, ARM_SP, ARM_SP,
			//   BPF_MEMWORDS * sizeof(uint32_t));
		}
		if (flen) {
			printf("flen\n");
			//arm32 mov_r(emitm, &stream, REG_MBUFLEN, ARM_R1);
		//	MOVrd2(ESI, R9D);
		}
		if (fpkt) {
			printf("fpkt\n");

			arm64_mov_r(emitm, &stream, REG_MBUF, A64_R(0));
			//arm32 mov_r(emitm, &stream, REG_MBUF, ARM_R0);

		//	MOVrq2(RDI, R8);
		//	MOVrd(EDX, EDI);
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
				//arm32 mov(emitm, &stream, ARM_R0, ins->k);
				//amd64 MOVid(ins->k, EAX);

				if (fmem) {
					//add(emitm, &stream, ARM_SP, ARM_SP,
					//    BPF_MEMWORDS * sizeof(uint32_t));
				}

				if (fpkt || flen || fmem) {
					//pop(emitm, &stream, reg_list);
				}

				ret(emitm, &stream);
				//emitm(&stream, ARM_RET);

				break;

			case BPF_RET|BPF_A:
				/* accept A bytes */
				printf("BPF_RET|BPF_A\n");
				mov_r(emitm, &stream, ARM_R0, REG_A);
				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				if (fpkt || flen || fmem) {
					pop(emitm, &stream, reg_list);
				}

				emitm(&stream, ARM_RET);

				break;

			case BPF_LD|BPF_W|BPF_ABS:
				/* A <- P[k:4] */
				printf("BPF_LD|BPF_W|BPF_ABS\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load word from offset */
				arm64_ldr(emitm, &stream, A64_R(0), A64_R(0), 0);
				//arm32 ldr(emitm, &stream, ARM_R0, ARM_R0, 0);

				/* Reverse as network packets are big-endian */
				arm64_rev(emitm, &stream, REG_A, A64_R(0));
				//rev(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//MOVid(ins->k, ESI);
				//CMPrd(EDI, ESI);
				//JAb(12);
				//MOVrd(EDI, ECX);
				//SUBrd(ESI, ECX);
				//CMPid(sizeof(int32_t), ECX);
				//if (fmem) {
				//	JAEb(4);
				//	ZEROrd(EAX);
				//	LEAVE();
				//} else {
				//	JAEb(3);
				//	ZEROrd(EAX);
				//}
				//RET();
				//MOVrq3(R8, RCX);
				//MOVobd(RCX, RSI, EAX);
				//BSWAP(EAX);

				break;

			case BPF_LD|BPF_H|BPF_ABS:
				/* A <- P[k:2] */
				printf("BPF_LD|BPF_H|BPF_ABS: ins->k 0x%x\n", ins->k);

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load half word from offset */
				arm64_ldrh(emitm, &stream, A64_R(0), A64_R(0));
				//arm32 ldrh(emitm, &stream, ARM_R0, ARM_R0);

				/* Reverse as network packets are big-endian */
				arm64_rev16(emitm, &stream, REG_A, A64_R(0));
				//arm32 rev16(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//ZEROrd(EAX);
				//MOVid(ins->k, ESI);
				//CMPrd(EDI, ESI);
				//JAb(12);
				//MOVrd(EDI, ECX);
				//SUBrd(ESI, ECX);
				//CMPid(sizeof(int16_t), ECX);
				//if (fmem) {
				//	JAEb(2);
				//	LEAVE();
				//} else
				//	JAEb(1);
				//RET();
				//MOVrq3(R8, RCX);
				//MOVobw(RCX, RSI, AX);
				//SWAP_AX();

				break;

			case BPF_LD|BPF_B|BPF_ABS:
				/* A <- P[k:1] */
				printf("BPF_LD|BPF_B|BPF_ABS: ins->k 0x%x\n", ins->k);

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load byte from offset */
				arm64_ldrb(emitm, &stream, REG_A, A64_R(0));
				//arm32 ldrb(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//ZEROrd(EAX);
				//MOVid(ins->k, ESI);
				//CMPrd(EDI, ESI);
				//if (fmem) {
				//	JBb(2);
				//	LEAVE();
				//} else
				//	JBb(1);
				//RET();
				//MOVrq3(R8, RCX);
				//MOVobb(RCX, RSI, AL);
				break;

			case BPF_LD|BPF_W|BPF_LEN:
				/* A <- len */
				printf("BPF_LD|BPF_W|BPF_LEN\n");
				arm64_mov_r(emitm, &stream, REG_A, REG_MBUFLEN);
				//arm32 mov_r(emitm, &stream, REG_A, REG_MBUFLEN);
				//MOVrd3(R9D, EAX);
				break;

			case BPF_LDX|BPF_W|BPF_LEN:
				/* X <- len */
				printf("BPF_LDX|BPF_W|BPF_LEN\n");
				arm64_mov_r(emitm, &stream, REG_X, REG_MBUFLEN);
				//arm32 mov_r(emitm, &stream, REG_X, REG_MBUFLEN);
				//MOVrd3(R9D, EDX);
				break;

			case BPF_LD|BPF_W|BPF_IND:
				/* A <- P[X+k:4] */
				printf("BPF_LD|BPF_W|BPF_IND\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Add X */
				arm64_add_r(emitm, &stream, A64_R(1), A64_R(1), REG_X);
				//arm32 add_r(emitm, &stream, ARM_R1, ARM_R1, REG_X);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load word from offset */
				arm64_ldr(emitm, &stream, A64_R(0), A64_R(0), 0);
				//arm32 ldr(emitm, &stream, ARM_R0, ARM_R0, 0);

				/* Change byte order as network packets are big-endian */
				arm64_rev(emitm, &stream, REG_A, A64_R(0));
				//arm32 rev(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//CMPrd(EDI, EDX);
				//JAb(27);
				//MOVid(ins->k, ESI);
				//MOVrd(EDI, ECX);
				//SUBrd(EDX, ECX);
				//CMPrd(ESI, ECX);
				//JBb(14);
				//ADDrd(EDX, ESI);
				//MOVrd(EDI, ECX);
				//SUBrd(ESI, ECX);
				//CMPid(sizeof(int32_t), ECX);
				//if (fmem) {
				//	JAEb(4);
				//	ZEROrd(EAX);
				//	LEAVE();
				//} else {
				//	JAEb(3);
				//	ZEROrd(EAX);
				//}
				//RET();
				//MOVrq3(R8, RCX);
				//MOVobd(RCX, RSI, EAX);
				//BSWAP(EAX);
				break;

			case BPF_LD|BPF_H|BPF_IND:
				/* A <- P[X+k:2] */

				printf("BPF_LD|BPF_H|BPF_IND\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Add X */
				arm64_add_r(emitm, &stream, A64_R(1), A64_R(1), REG_X);
				//arm32 add_r(emitm, &stream, ARM_R1, ARM_R1, REG_X);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load half word from offset */
				arm64_ldrh(emitm, &stream, A64_R(0), A64_R(0));
				//arm32 ldrh(emitm, &stream, ARM_R0, ARM_R0);

				/* Reverse as network packets are big-endian */
				arm64_rev16(emitm, &stream, REG_A, A64_R(0));
				//arm32 rev16(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//ZEROrd(EAX);
				//CMPrd(EDI, EDX);
				//JAb(27);
				//MOVid(ins->k, ESI);
				//MOVrd(EDI, ECX);
				//SUBrd(EDX, ECX);
				//CMPrd(ESI, ECX);
				//JBb(14);
				//ADDrd(EDX, ESI);
				//MOVrd(EDI, ECX);
				//SUBrd(ESI, ECX);
				//CMPid(sizeof(int16_t), ECX);
				//if (fmem) {
				//	JAEb(2);
				//	LEAVE();
				//} else
				//	JAEb(1);
				//RET();
				//MOVrq3(R8, RCX);
				//MOVobw(RCX, RSI, AX);
				//SWAP_AX();

				break;

			case BPF_LD|BPF_B|BPF_IND:
				/* A <- P[X+k:1] */
				printf("BPF_LD|BPF_B|BPF_IND\n");

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Add X */
				arm64_add_r(emitm, &stream, A64_R(1), A64_R(1), REG_X);
				//arm32 add_r(emitm, &stream, ARM_R1, ARM_R1, REG_X);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load byte from offset */
				arm64_ldrb(emitm, &stream, REG_A, A64_R(0));
				//arm32 ldrb(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//ZEROrd(EAX);
				//CMPrd(EDI, EDX);
				//JAEb(13);
				//MOVid(ins->k, ESI);
				//MOVrd(EDI, ECX);
				//SUBrd(EDX, ECX);
				//CMPrd(ESI, ECX);
				//if (fmem) {
				//	JAb(2);
				//	LEAVE();
				//} else
				//	JAb(1);
				//RET();
				//MOVrq3(R8, RCX);
				//ADDrd(EDX, ESI);
				//MOVobb(RCX, RSI, AL);
				break;

			case BPF_LDX|BPF_MSH|BPF_B: //implement me for dst port 22
				/* X <- 4*(P[k:1]&0xf) */
				printf("BPF_LDX|BPF_MSH|BPF_B ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);

				/* Copy K value to R1 */
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				//arm32 mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				arm64_add_r(emitm, &stream, A64_R(0), A64_R(1), REG_MBUF);
				//arm32 add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load byte from offset */
				arm64_ldrb(emitm, &stream, A64_R(1), A64_R(0));
				//arm32 ldrb(emitm, &stream, ARM_R1, ARM_R0);

				arm64_mov_i(emitm, &stream, A64_R(3), 0xf);
				arm64_and_r(emitm, &stream, A64_R(1), A64_R(1), A64_R(3));
				//arm32 and_i(emitm, &stream, ARM_R1, ARM_R1, 0xf);

				arm64_lsl_i(emitm, &stream, REG_X, A64_R(1), 2);
				//arm32 lsl(emitm, &stream, REG_X, ARM_R1, 2);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				//MOVid(ins->k, ESI);
				//CMPrd(EDI, ESI);
				//if (fmem) {
				//	JBb(4);
				//	ZEROrd(EAX);
				//	LEAVE();
				//} else {
				//	JBb(3);
				//	ZEROrd(EAX);
				//}
				//RET();
				//ZEROrd(EDX);
				//MOVrq3(R8, RCX);
				//MOVobb(RCX, RSI, DL);
				//ANDib(0x0f, DL);
				//SHLib(2, EDX);
				break;

			case BPF_LD|BPF_IMM:
				/* A <- k */
				printf("BPF_LD|BPF_IMM\n");
				arm64_mov_i(emitm, &stream, REG_A, ins->k);
				//arm32 mov(emitm, &stream, REG_A, ins->k);
				//MOVid(ins->k, EAX);
				break;

			case BPF_LDX|BPF_IMM:
				/* X <- k */
				printf("BPF_LDX|BPF_IMM\n");
				arm64_mov_i(emitm, &stream, REG_X, ins->k);
				//arm32 mov(emitm, &stream, REG_X, ins->k);
				//MOVid(ins->k, EDX);
				break;

			case BPF_LD|BPF_MEM:
				/* A <- M[k] */
				printf("BPF_LD|BPF_MEM\n");
				arm64_ldr(emitm, &stream, REG_A, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				//arm32 ldr(emitm, &stream, REG_A, ARM_SP,
				//   (ins->k * sizeof(uint32_t)));
				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVobd(RSP, RSI, EAX);
				break;

			case BPF_LDX|BPF_MEM:
				/* X <- M[k] */
				printf("BPF_LDX|BPF_MEM\n");
				arm64_ldr(emitm, &stream, REG_X, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				//arm32 ldr(emitm, &stream, REG_X, ARM_SP,
				//   (ins->k * sizeof(uint32_t)));
				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVobd(RSP, RSI, EDX);
				break;

			case BPF_ST:
				/* M[k] <- A */
				printf("BPF_ST not tested\n");

				str(emitm, &stream, REG_A, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				/*
				 * XXX this command and the following could
				 * be optimized if the previous instruction
				 * was already of this type
				 */
				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVomd(EAX, RSP, RSI);
				break;

			case BPF_STX:
				/* M[k] <- X */
				printf("BPF_STX not tested\n");
				str(emitm, &stream, REG_X, ARM_SP,
				    (ins->k * sizeof(uint32_t)));

				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVomd(EDX, RSP, RSI);
				break;

			case BPF_JMP|BPF_JA:
				/* pc += k */
				printf("BPF_JMP|BPF_JA\n");
				arm64_branch_i(emitm, &stream, ins->k);
				//arm32 branch(emitm, &stream, COND_AL, ins->k);
				//JUMP(ins->k);
				break;

			case BPF_JMP|BPF_JGT|BPF_K:
				/* pc += (A > k) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}

				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_cmp_r(emitm, &stream, REG_A, A64_R(1));
				//mov(emitm, &stream, ARM_R1, ins->k);
				//cmp_r(emitm, &stream, REG_A, ARM_R1);
				jcc(emitm, &stream, ins, COND_GT, COND_LE);

				//CMPid(ins->k, EAX);
				//JCC(JA, JBE);
				break;

			case BPF_JMP|BPF_JGE|BPF_K:
				/* pc += (A >= k) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_K\n");

				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}

				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_cmp_r(emitm, &stream, REG_A, A64_R(1));
				//mov(emitm, &stream, ARM_R1, ins->k);
				//cmp_r(emitm, &stream, REG_A, ARM_R1);
				jcc(emitm, &stream, ins, COND_GE, COND_LT);

				//CMPid(ins->k, EAX);
				//JCC(JAE, JB);
				break;

			case BPF_JMP|BPF_JEQ|BPF_K:
				/* pc += (A == k) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//arm32 branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}

				////cmp_i(REG_A, ins->k);

				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_cmp_r(emitm, &stream, REG_A, A64_R(1));
				jcc(emitm, &stream, ins, COND_EQ, COND_NE);

				//emitm(&stream, KERNEL_BREAKPOINT);
				//CMPid(ins->k, EAX);
				//JCC(JE, JNE);
				break;

			case BPF_JMP|BPF_JSET|BPF_K: //implement me for dst port 22
				/* pc += (A & k) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);

				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//arm32 branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				////and(emitm, &stream, ARM_R1, REG_A, ins->k);

				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_tst_r(emitm, &stream, REG_A, A64_R(1));
				//arm32 tst(emitm, &stream, REG_A, ins->k);
				jcc(emitm, &stream, ins, COND_NE, COND_EQ);
				//TESTid(ins->k, EAX);
				//JCC(JNE, JE);
				break;

			case BPF_JMP|BPF_JGT|BPF_X:
				/* pc += (A > X) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				//tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_GT, COND_LE);
				//CMPrd(EDX, EAX);
				//JCC(JA, JBE);
				break;

			case BPF_JMP|BPF_JGE|BPF_X:
				/* pc += (A >= X) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				//tst_r(emitm, &stream, REG_A, REG_X);
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_GE, COND_LT);
				//CMPrd(EDX, EAX);
				//JCC(JAE, JB);
				break;

			case BPF_JMP|BPF_JEQ|BPF_X:
				/* pc += (A == X) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				//tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_EQ, COND_NE);
				//CMPrd(EDX, EAX);
				//JCC(JE, JNE);
				break;

			case BPF_JMP|BPF_JSET|BPF_X:
				/* pc += (A & X) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_X\n");
				if (ins->jt == ins->jf) {
					arm64_branch_i(emitm, &stream, ins->jt);
					//branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				arm64_tst_r(emitm, &stream, REG_A, REG_X);
				//tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_NE, COND_EQ);
				//TESTrd(EDX, EAX);
				//JCC(JNE, JE);
				break;

			case BPF_ALU|BPF_ADD|BPF_X:
				/* A <- A + X */
				printf("BPF_ALU|BPF_ADD|BPF_X\n");

				arm64_add_r(emitm, &stream, REG_A, REG_A, REG_X);
				//add_r(emitm, &stream, REG_A, REG_A, REG_X);

				//ADDrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_SUB|BPF_X:
				/* A <- A - X */
				printf("BPF_ALU|BPF_SUB|BPF_X not tested: checkme\n");
				arm64_sub_r(emitm, &stream, REG_A, REG_X, REG_A);
				//rsb_r(emitm, &stream, REG_A, REG_X, REG_A);
				//SUBrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_MUL|BPF_X:
				/* A <- A * X */
				printf("BPF_ALU|BPF_MUL|BPF_X not tested\n");

				mul(emitm, &stream, REG_A, REG_A, REG_X, 0);

				//MOVrd(EDX, ECX);
				//MULrd(EDX);
				//MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_DIV|BPF_X:
				/* A <- A / X */
				printf("BPF_ALU|BPF_DIV|BPF_X\n");

				mov_r(emitm, &stream, ARM_R0, REG_A);
				mov_r(emitm, &stream, ARM_R1, REG_X);
				mov(emitm, &stream, ARM_R2, (uint32_t)jit_udiv);
				branch_lx(emitm, &stream, COND_AL, ARM_R2);
				mov_r(emitm, &stream, REG_A, ARM_R0);

				//TESTrd(EDX, EDX);
				//if (fmem) {
				//	JNEb(4);
				//	ZEROrd(EAX);
				//	LEAVE();
				//} else {
				//	JNEb(3);
				//	ZEROrd(EAX);
				//}
				//RET();
				//MOVrd(EDX, ECX);
				//ZEROrd(EDX);
				//DIVrd(ECX);
				//MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_AND|BPF_X:
				/* A <- A & X */
				printf("BPF_ALU|BPF_AND|BPF_X\n");

				and_r(emitm, &stream, REG_A, REG_A, REG_X);

				//ANDrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_OR|BPF_X:
				/* A <- A | X */
				printf("BPF_ALU|BPF_OR|BPF_X\n");

				orr_r(emitm, &stream, REG_A, REG_A, REG_X);

				//ORrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_LSH|BPF_X:
				/* A <- A << X */
				printf("BPF_ALU|BPF_LSH|BPF_X\n");
				lsl_r(emitm, &stream, REG_A, REG_A, REG_X);

				//MOVrd(EDX, ECX);
				//SHL_CLrb(EAX);
				break;

			case BPF_ALU|BPF_RSH|BPF_X:
				/* A <- A >> X */
				printf("BPF_ALU|BPF_RSH|BPF_X\n");
				lsr_r(emitm, &stream, REG_A, REG_A, REG_X);

				//MOVrd(EDX, ECX);
				//SHR_CLrb(EAX);
				break;

			case BPF_ALU|BPF_ADD|BPF_K:
				/* A <- A + k */
				//printf("BPF_ALU|BPF_ADD|BPF_K\n");

				add(emitm, &stream, REG_A, REG_A, ins->k);

				//ADD_EAXi(ins->k);
				break;

			case BPF_ALU|BPF_SUB|BPF_K:
				/* A <- A - k */
				printf("BPF_ALU|BPF_SUB|BPF_K\n");
				arm64_sub_i(emitm, &stream, REG_A, REG_A, ins->k);
				//rsb(emitm, &stream, REG_A, REG_A, ins->k);
				//SUB_EAXi(ins->k);
				break;

			case BPF_ALU|BPF_MUL|BPF_K:
				/* A <- A * k */
				printf("BPF_ALU|BPF_MUL|BPF_K not tested\n");

				mov(emitm, &stream, ARM_R1, ins->k);
				mul(emitm, &stream, REG_A, REG_A, ARM_R1, 0);

				//MOVrd(EDX, ECX);
				//MOVid(ins->k, EDX);
				//MULrd(EDX);
				//MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_DIV|BPF_K:
				/* A <- A / k */
				printf("BPF_ALU|BPF_DIV|BPF_K\n");

				mov_r(emitm, &stream, ARM_R0, REG_A);
				mov(emitm, &stream, ARM_R1, ins->k);
				mov(emitm, &stream, ARM_R2, (uint32_t)jit_udiv);
				branch_lx(emitm, &stream, COND_AL, ARM_R2);
				mov_r(emitm, &stream, REG_A, ARM_R0);

				//MOVrd(EDX, ECX);
				//ZEROrd(EDX);
				//MOVid(ins->k, ESI);
				//DIVrd(ESI);
				//MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_AND|BPF_K:
				/* A <- A & k */
				printf("BPF_ALU|BPF_AND|BPF_K ins->k 0x%x\n", ins->k);
				arm64_and_r(emitm, &stream, REG_A, REG_A, ins->k);
				//and(emitm, &stream, REG_A, REG_A, ins->k);
				//ANDid(ins->k, EAX);
				break;

			case BPF_ALU|BPF_OR|BPF_K:
				/* A <- A | k */
				printf("BPF_ALU|BPF_OR|BPF_K\n");
				arm64_mov_i(emitm, &stream, A64_R(1), ins->k);
				arm64_orr_r(emitm, &stream, REG_A, REG_A, A64_R(1));
				//orr(emitm, &stream, REG_A, REG_A, ins->k);
				//ORid(ins->k, EAX);
				break;

			case BPF_ALU|BPF_LSH|BPF_K:
				/* A <- A << k */
				//printf("BPF_ALU|BPF_LSH|BPF_K\n");
				/* TODO: check 0xff fit lsl_i */
				arm64_lsl_i(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				//arm32 lsl(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				//SHLib((ins->k) & 0xff, EAX);
				break;

			case BPF_ALU|BPF_RSH|BPF_K:
				/* A <- A >> k */
				printf("BPF_ALU|BPF_RSH|BPF_K ins->k %d\n", ins->k);
				arm64_lsr_i(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				//lsr(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				//SHRib((ins->k) & 0xff, EAX);
				break;

			case BPF_ALU|BPF_NEG:
				/* A <- -A */
				printf("BPF_ALU|BPF_NEG\n");
				/* substruct from xzr */
				arm64_sub_r(emitm, &stream, REG_A, A64_R(31), REG_A);
				//rsb(emitm, &stream, REG_A, REG_A, 0);
				//NEGd(EAX);
				break;

			case BPF_MISC|BPF_TAX:
				/* X <- A */
				printf("BPF_MISC|BPF_TAX\n");

				arm64_mov_r(emitm, &stream, REG_X, REG_A);
				//arm32 mov_r(emitm, &stream, REG_X, REG_A);

				break;

			case BPF_MISC|BPF_TXA:
				/* A <- X */
				printf("BPF_MISC|BPF_TXA\n");

				arm64_mov_r(emitm, &stream, REG_A, REG_X);
				//arm32 mov_r(emitm, &stream, REG_A, REG_X);

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
