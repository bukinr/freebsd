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

#include <arm/arm/bpf_jit_machdep.h>
#include <arm/include/trap.h>

bpf_filter_func	bpf_jit_compile(struct bpf_insn *, u_int, size_t *);

#define	REG_A		ARM_R4
#define	REG_X		ARM_R5
#define	REG_MBUF	ARM_R6
#define	REG_MBUFLEN	ARM_R7

#define	RET		0xe12fff1e	/* bx lr */

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

static uint32_t
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

	return (0);
}

static uint32_t
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

	return (0);
}

static uint32_t
branch(emit_func emitm, bpf_bin_stream *stream,
    uint32_t cond, uint32_t offs)
{
	uint32_t instr;

	instr = (1 << 25) | (1 << 27);
	instr |= (cond << COND_S);
	instr |= (offs >> 2);

	emitm(stream, instr);

	return (0);
}

static uint32_t
mov_i(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t imm)
{
	uint32_t instr;

	instr = (OPCODE_MOV << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (imm << IMM_S);
	instr |= IMM_OP;	/* operand 2 is an immediate value */

	emitm(stream, instr);

	return (0);
}

static int
mov(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t val)
{
	uint32_t instr;
	int imm12;

	printf("%s\n", __func__);

	imm12 = imm8m(val);
	if (imm12 >= 0) {
		mov_i(emitm, stream, rd, imm12);
	} else {
		printf("to emit MOVW\n");
		instr = ARM_MOVW(rd, val & 0xffff);
		instr |= (COND_AL << COND_S);
		emitm(stream, instr);

		if (val > 0xffff) {
			printf("to emit MOVT\n");
			instr = ARM_MOVT(rd, (val >> 16));
			instr |= (COND_AL << COND_S);
			emitm(stream, instr);
		}
	}

	return (0);
}

static int
mul(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t rs, uint32_t rn)
{
	uint32_t instr;

#define	MUL_ACCUMULATE	(1 << 21)
#define	RS_S		8

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

	return (0);
}

static int
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
		instr |= IMM_OP;	/* operand 2 is an immediate value */
	} else {
		printf("%s, imm12 < 0\n", __func__);
		mov(emitm, stream, ARM_R0, val);
		instr |= (ARM_R0 << RM_S);
	}

	emitm(stream, instr);
	return (0);
}

#define	ARM_LSL_I	0x01a00000
#define	ARM_LSL_R	0x01a00010
#define	ARM_LSR_I	0x01a00020
#define	ARM_LSR_R	0x01a00030

static int
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

	return (0);
}

static int
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

	return (0);
}

static int
lsl_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t rs)
{
	uint32_t instr;

	instr = ARM_LSL_R | (COND_AL << COND_S);
	instr |= (rs << RS_S);
	instr |= (rd << RD_S | rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static int
lsr_r(emit_func emitm, bpf_bin_stream *stream, uint32_t rd,
    uint32_t rm, uint32_t rs)
{
	uint32_t instr;

	instr = ARM_LSR_R | (COND_AL << COND_S);
	instr |= (rs << RS_S);
	instr |= (rd << RD_S | rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static int
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
		instr |= IMM_OP;
	} else {
		mov(emitm, stream, ARM_R1, val);
		instr |= (ARM_R1 << RM_S);
	}

	emitm(stream, instr);

	return (0);
}

static int
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

	return (0);
}

static int
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
	return (0);
}

static int
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

	return (0);
}

static int
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

	return (0);
}

static int
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

	return (0);
}

static uint32_t
mov_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_MOV << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static uint32_t
cmp_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_CMP << OPCODE_S) | (COND_AL << COND_S);
	//instr |= (rd << RD_S) | (rm << RM_S);
	instr |= (rn << RN_S) | (rm << RM_S);
	instr |= COND_SET;

	emitm(stream, instr);

	return (0);
}

static uint32_t
add_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_ADD << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S);
	instr |= (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static uint32_t
orr_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_ORR << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static uint32_t
rsb_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_RSB << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static uint32_t
and_r(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_AND << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rn << RN_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static int
jump(emit_func emitm, bpf_bin_stream *stream, struct bpf_insn *ins,
    uint8_t cond1, uint8_t cond2)
{
	uint32_t offs;

	if (ins->jt != 0 && ins->jf != 0) {
		//panic("implement me 12\n");

		offs = stream->refs[stream->bpf_pc + ins->jt] -	\
		    stream->refs[stream->bpf_pc] - 4;
		printf("offs 0x%08x\n", offs);

		branch(emitm, stream, cond1, offs);

	} else if (ins->jt != 0) {
		offs = stream->refs[stream->bpf_pc + ins->jt] - \
		    stream->refs[stream->bpf_pc] - 4;
		printf("offs 0x%08x\n", offs);

		branch(emitm, stream, cond1, offs);

	} else if (ins->jf != 0) {
		offs = stream->refs[stream->bpf_pc + ins->jf] - \
		    stream->refs[stream->bpf_pc] - 4;
		printf("offs 0x%08x\n", offs);

		branch(emitm, stream, cond2, offs);
	}

	return (0);
}

#if 0
#define	POST_INDEX	(0 << 24)	/* add offset after transfer */
#define	PRE_INDEX	(1 << 24)	/* add offset before transfer */
#define	DOWN_BIT	(0 << 23)	/* subtract offset from base */
#define	UP_BIT		(1 << 23)	/* add offset to base */
#define	WORD_BIT	(0 << 22)	/* transfer word quantity */
#define	BYTE_BIT	(1 << 22)	/* transfer byte quantity */
#define	NO_WRITE_BACK	(0 << 21)	/* no write-back */
#define	WRITE_BACK	(1 << 21)	/* write address into base */
#define	OP_STORE	(0 << 20)	/* Store to memory */
#define	OP_LOAD		(1 << 20)	/* Load from memory */
#endif

static uint32_t
ldr(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 26);
	instr |= (COND_AL << COND_S) | WORD_BIT | OP_LOAD;
	instr |= UP_BIT | PRE_INDEX;
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static uint32_t
ldrb(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 26);
	instr |= (COND_AL << COND_S) | BYTE_BIT | OP_LOAD;
	instr |= UP_BIT | PRE_INDEX;
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

#define	SH_S		5
#define	SH_SWP		0	/* SWP instruction */
#define	SH_UH		1	/* Unsigned halfwords */
#define	SH_SB		2	/* Signed byte */
#define	SH_SH		3	/* Signed halfwords */

static uint32_t
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

	return (0);
}

static uint32_t
rev(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 23) | (1 << 25) | (1 << 26);
	instr |= (1 << 20) | (1 << 21);
	instr |= (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19);
	instr |= (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);
	instr |= (1 << 4) | (1 << 5);

	instr |= (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
}

static uint32_t
rev16(emit_func emitm, bpf_bin_stream *stream,
    uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 23) | (1 << 25) | (1 << 26);
	instr |= (1 << 20) | (1 << 21);
	instr |= (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19);
	instr |= (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);
	instr |= (1 << 4) | (1 << 5);
	instr |= (1 << 7);

	instr |= (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	emitm(stream, instr);

	return (0);
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
	bpf_bin_stream stream;
	struct bpf_insn *ins;
	int flags, fret, fpkt, fmem, fjmp, flen;
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

	uint32_t reg_list;

	//reg_list = (1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 6);
	reg_list = (1 << REG_A) | (1 << REG_X) | (1 << REG_MBUF) | (1 << REG_MBUFLEN);

	for (pass = 0; pass < 2; pass++) {
		ins = prog;

		//if (fpkt || fmem) {
			push(emitm, &stream, reg_list);
		//}

		/* Create the procedure header. */
		if (fmem) {
			printf("fmem\n");

		//	PUSH(RBP);
		//	MOVrq(RSP, RBP);
		//	SUBib(BPF_MEMWORDS * sizeof(uint32_t), RSP);
		}
		if (flen) {
			printf("flen\n");
			mov_r(emitm, &stream, REG_MBUFLEN, ARM_R1);
		//	MOVrd2(ESI, R9D);
		}
		if (fpkt) {
			printf("fpkt\n");

			mov_r(emitm, &stream, REG_MBUF, ARM_R0);

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

				mov(emitm, &stream, ARM_R0, ins->k);
				//imm12 = imm8m(ins->k);
				//if (imm12 >= 0) {
				//	mov_i(emitm, &stream, ARM_R0, imm12);
				//} else {
				//	panic("implement me 1\n");
				//}

				if (fmem)
					panic("implement fmem");

				//MOVid(ins->k, EAX);
				//if (fmem)
				//	LEAVE();
				//RET();

				//if (fmem) {
					pop(emitm, &stream, reg_list);
				//}

				emitm(&stream, RET);

				break;

			case BPF_RET|BPF_A:
				/* accept A bytes */
				printf("BPF_RET|BPF_A\n");
				mov_r(emitm, &stream, ARM_R0, REG_A);
				if (fmem) {
					//LEAVE();
				}
				//RET();
				emitm(&stream, RET);
				break;

			case BPF_LD|BPF_W|BPF_ABS:
				/* A <- P[k:4] */
				printf("BPF_LD|BPF_W|BPF_ABS\n");

				/* Copy K value to R1 */
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load word from offset */
				ldr(emitm, &stream, ARM_R0, ARM_R0);

				/* Reverse as network packets are big-endian */
				rev(emitm, &stream, REG_A, ARM_R0);

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
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load half word from offset */
				ldrh(emitm, &stream, ARM_R0, ARM_R0);

				/* Reverse as network packets are big-endian */
				rev16(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					panic("implement LEAVE\n");
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
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load byte from offset */
				ldrb(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					panic("implement LEAVE 1\n");
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

				mov_r(emitm, &stream, REG_A, REG_MBUFLEN);

				//MOVrd3(R9D, EAX);
				break;

			case BPF_LDX|BPF_W|BPF_LEN:
				/* X <- len */
				printf("BPF_LDX|BPF_W|BPF_LEN\n");
				mov_r(emitm, &stream, REG_X, REG_MBUFLEN);
				//MOVrd3(R9D, EDX);
				break;

			case BPF_LD|BPF_W|BPF_IND:
				/* A <- P[X+k:4] */
				printf("BPF_LD|BPF_W|BPF_IND\n");

				/* Copy K value to R1 */
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Add X */
				add_r(emitm, &stream, ARM_R1, ARM_R1, REG_X);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load word from offset */
				ldr(emitm, &stream, ARM_R0, ARM_R0);

				/* Change byte order as network packets are big-endian */
				rev(emitm, &stream, REG_A, ARM_R0);

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
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Add X */
				add_r(emitm, &stream, ARM_R1, ARM_R1, REG_X);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load half word from offset */
				ldrh(emitm, &stream, ARM_R0, ARM_R0);

				/* Reverse as network packets are big-endian */
				rev16(emitm, &stream, REG_A, ARM_R0);

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
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Add X */
				add_r(emitm, &stream, ARM_R1, ARM_R1, REG_X);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load byte from offset */
				ldrb(emitm, &stream, REG_A, ARM_R0);

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
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load byte from offset */
				ldrb(emitm, &stream, ARM_R1, ARM_R0);

				and_i(emitm, &stream, ARM_R1, ARM_R1, 0xf);
				lsl(emitm, &stream, REG_X, ARM_R1, 2);

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
				mov(emitm, &stream, REG_A, ins->k);
				//MOVid(ins->k, EAX);
				break;

			case BPF_LDX|BPF_IMM:
				/* X <- k */
				printf("BPF_LDX|BPF_IMM\n");
				mov(emitm, &stream, REG_X, ins->k);
				//MOVid(ins->k, EDX);
				break;

			case BPF_LD|BPF_MEM:
				/* A <- M[k] */
				printf("BPF_LD|BPF_MEM\n");
				panic("implement me");
				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVobd(RSP, RSI, EAX);
				break;

			case BPF_LDX|BPF_MEM:
				/* X <- M[k] */
				printf("BPF_LDX|BPF_MEM\n");
				panic("implement me");
				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVobd(RSP, RSI, EDX);
				break;

			case BPF_ST:
				/* M[k] <- A */
				printf("BPF_ST\n");
				panic("implement me");
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
				printf("BPF_STX\n");
				panic("implement me");
				//MOVid(ins->k * sizeof(uint32_t), ESI);
				//MOVomd(EDX, RSP, RSI);
				break;

			case BPF_JMP|BPF_JA:
				/* pc += k */
				printf("BPF_JMP|BPF_JA\n");
				panic("implement me");
				//JUMP(ins->k);
				break;

			case BPF_JMP|BPF_JGT|BPF_K:
				/* pc += (A > k) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					panic("implement me: 11");
					//JUMP(ins->jt);
					break;
				}

				mov(emitm, &stream, ARM_R1, ins->k);

				cmp_r(emitm, &stream, REG_A, ARM_R1);

				jump(emitm, &stream, ins, COND_GT, COND_LE);

				//CMPid(ins->k, EAX);
				//JCC(JA, JBE);
				break;

			case BPF_JMP|BPF_JGE|BPF_K:
				/* pc += (A >= k) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_K\n");

				if (ins->jt == ins->jf) {
					//JUMP(ins->jt);
					break;
				}

				mov(emitm, &stream, ARM_R1, ins->k);
				cmp_r(emitm, &stream, REG_A, ARM_R1);
				jump(emitm, &stream, ins, COND_GE, COND_LT);

				//CMPid(ins->k, EAX);
				//JCC(JAE, JB);
				break;

			case BPF_JMP|BPF_JEQ|BPF_K:
				/* pc += (A == k) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					panic("implement jump\n");
					//JUMP(ins->jt);
					break;
				}

				//cmp_i(REG_A, ins->k);

				mov(emitm, &stream, ARM_R1, ins->k);
				cmp_r(emitm, &stream, REG_A, ARM_R1);

				//emitm(&stream, KERNEL_BREAKPOINT, 4);
				jump(emitm, &stream, ins, COND_EQ, COND_NE);

				//CMPid(ins->k, EAX);
				//JCC(JE, JNE);
				break;

			case BPF_JMP|BPF_JSET|BPF_K: //implement me for dst port 22
				/* pc += (A & k) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);

				if (ins->jt == ins->jf) {
					panic("implement jump 1\n");
					//JUMP(ins->jt);
					break;
				}
				//and(emitm, &stream, ARM_R1, REG_A, ins->k);
				tst(emitm, &stream, REG_A, ins->k);
				jump(emitm, &stream, ins, COND_NE, COND_EQ);
				//TESTid(ins->k, EAX);
				//JCC(JNE, JE);
				break;

			case BPF_JMP|BPF_JGT|BPF_X:
				/* pc += (A > X) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_X\n");
				panic("implement me");
				if (ins->jt == ins->jf) {
					//JUMP(ins->jt);
					break;
				}
				//CMPrd(EDX, EAX);
				//JCC(JA, JBE);
				break;

			case BPF_JMP|BPF_JGE|BPF_X:
				/* pc += (A >= X) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_X\n");
				panic("implement me");
				if (ins->jt == ins->jf) {
					//JUMP(ins->jt);
					break;
				}
				//CMPrd(EDX, EAX);
				//JCC(JAE, JB);
				break;

			case BPF_JMP|BPF_JEQ|BPF_X:
				/* pc += (A == X) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_X\n");
				panic("implement me");
				if (ins->jt == ins->jf) {
					//JUMP(ins->jt);
					break;
				}
				//CMPrd(EDX, EAX);
				//JCC(JE, JNE);
				break;

			case BPF_JMP|BPF_JSET|BPF_X:
				/* pc += (A & X) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_X\n");
				panic("implement me");
				if (ins->jt == ins->jf) {
					//JUMP(ins->jt);
					break;
				}
				//TESTrd(EDX, EAX);
				//JCC(JNE, JE);
				break;

			case BPF_ALU|BPF_ADD|BPF_X:
				/* A <- A + X */
				printf("BPF_ALU|BPF_ADD|BPF_X\n");

				add_r(emitm, &stream, REG_A, REG_A, REG_X);

				//ADDrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_SUB|BPF_X:
				/* A <- A - X */
				printf("BPF_ALU|BPF_SUB|BPF_X not tested: checkme\n");
				rsb_r(emitm, &stream, REG_A, REG_X, REG_A);
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

				printf("No div instruction implemented");
				return (0);

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
				rsb(emitm, &stream, REG_A, REG_A, ins->k);
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

				printf("No div instruction implemented");
				return (0);

				//MOVrd(EDX, ECX);
				//ZEROrd(EDX);
				//MOVid(ins->k, ESI);
				//DIVrd(ESI);
				//MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_AND|BPF_K:
				/* A <- A & k */
				printf("BPF_ALU|BPF_AND|BPF_K ins->k 0x%x\n", ins->k);
				and(emitm, &stream, REG_A, REG_A, ins->k);
				//ANDid(ins->k, EAX);
				break;

			case BPF_ALU|BPF_OR|BPF_K:
				/* A <- A | k */
				printf("BPF_ALU|BPF_OR|BPF_K\n");
				orr(emitm, &stream, REG_A, REG_A, ins->k);
				//ORid(ins->k, EAX);
				break;

			case BPF_ALU|BPF_LSH|BPF_K:
				/* A <- A << k */
				printf("BPF_ALU|BPF_LSH|BPF_K\n");
				lsl(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				//SHLib((ins->k) & 0xff, EAX);
				break;

			case BPF_ALU|BPF_RSH|BPF_K:
				/* A <- A >> k */
				printf("BPF_ALU|BPF_RSH|BPF_K ins->k %d\n", ins->k);
				lsr(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				//SHRib((ins->k) & 0xff, EAX);
				break;

			case BPF_ALU|BPF_NEG:
				/* A <- -A */
				printf("BPF_ALU|BPF_NEG\n");
				/* substruct from zero */
				rsb(emitm, &stream, REG_A, REG_A, 0);
				//NEGd(EAX);
				break;

			case BPF_MISC|BPF_TAX:
				/* X <- A */
				printf("BPF_MISC|BPF_TAX\n");

				mov_r(emitm, &stream, REG_X, REG_A);

				break;

			case BPF_MISC|BPF_TXA:
				/* A <- X */
				printf("BPF_MISC|BPF_TXA\n");

				mov_r(emitm, &stream, REG_A, REG_X);

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
		printf("compilation success: inst buf 0x%08x\n", (uint32_t)stream.ibuf);
		breakpoint();
	} else {
		printf("compilation failed\n");
	}
	return ((bpf_filter_func)stream.ibuf);
}
