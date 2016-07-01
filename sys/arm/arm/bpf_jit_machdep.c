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
		    stream->refs[stream->bpf_pc] - 4;
		//printf("offs 0x%08x\n", offs);
		branch(emitm, stream, cond1, offs);
	}

	if (ins->jf != 0) {
		offs = stream->refs[stream->bpf_pc + ins->jf] - \
		    stream->refs[stream->bpf_pc] - 4;
		//printf("offs 0x%08x\n", offs);
		branch(emitm, stream, cond2, offs);
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
			push(emitm, &stream, reg_list);
		}

		/* Create the procedure header. */
		if (fmem) {
			printf("fmem\n");
			/* Using stack for memory scratch space */
			sub(emitm, &stream, ARM_SP, ARM_SP,
			    BPF_MEMWORDS * sizeof(uint32_t));
		}
		if (flen) {
			printf("flen\n");
			mov_r(emitm, &stream, REG_MBUFLEN, ARM_R1);
		}
		if (fpkt) {
			printf("fpkt\n");
			mov_r(emitm, &stream, REG_MBUF, ARM_R0);
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

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				if (fpkt || flen || fmem) {
					pop(emitm, &stream, reg_list);
				}

				emitm(&stream, ARM_RET);

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
				mov(emitm, &stream, ARM_R1, ins->k);

				/* Get offset */
				add_r(emitm, &stream, ARM_R0, ARM_R1, REG_MBUF);

				/* Load word from offset */
				ldr(emitm, &stream, ARM_R0, ARM_R0, 0);

				/* Reverse as network packets are big-endian */
				rev(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

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
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

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
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LD|BPF_W|BPF_LEN:
				/* A <- len */
				printf("BPF_LD|BPF_W|BPF_LEN\n");
				mov_r(emitm, &stream, REG_A, REG_MBUFLEN);
				break;

			case BPF_LDX|BPF_W|BPF_LEN:
				/* X <- len */
				printf("BPF_LDX|BPF_W|BPF_LEN\n");
				mov_r(emitm, &stream, REG_X, REG_MBUFLEN);
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
				ldr(emitm, &stream, ARM_R0, ARM_R0, 0);

				/* Change byte order as network packets are big-endian */
				rev(emitm, &stream, REG_A, ARM_R0);

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

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

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

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

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}

				break;

			case BPF_LDX|BPF_MSH|BPF_B:
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

				if (fmem) {
					add(emitm, &stream, ARM_SP, ARM_SP,
					    BPF_MEMWORDS * sizeof(uint32_t));
				}
				break;

			case BPF_LD|BPF_IMM:
				/* A <- k */
				printf("BPF_LD|BPF_IMM\n");
				mov(emitm, &stream, REG_A, ins->k);
				break;

			case BPF_LDX|BPF_IMM:
				/* X <- k */
				printf("BPF_LDX|BPF_IMM\n");
				mov(emitm, &stream, REG_X, ins->k);
				break;

			case BPF_LD|BPF_MEM:
				/* A <- M[k] */
				printf("BPF_LD|BPF_MEM\n");
				ldr(emitm, &stream, REG_A, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_LDX|BPF_MEM:
				/* X <- M[k] */
				printf("BPF_LDX|BPF_MEM\n");
				ldr(emitm, &stream, REG_X, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_ST:
				/* M[k] <- A */
				printf("BPF_ST not tested\n");
				str(emitm, &stream, REG_A, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_STX:
				/* M[k] <- X */
				printf("BPF_STX not tested\n");
				str(emitm, &stream, REG_X, ARM_SP,
				    (ins->k * sizeof(uint32_t)));
				break;

			case BPF_JMP|BPF_JA:
				/* pc += k */
				printf("BPF_JMP|BPF_JA\n");
				branch(emitm, &stream, COND_AL, ins->k);
				break;

			case BPF_JMP|BPF_JGT|BPF_K:
				/* pc += (A > k) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					break;
				}
				mov(emitm, &stream, ARM_R1, ins->k);
				cmp_r(emitm, &stream, REG_A, ARM_R1);
				jcc(emitm, &stream, ins, COND_GT, COND_LE);
				break;

			case BPF_JMP|BPF_JGE|BPF_K:
				/* pc += (A >= k) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_K\n");
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					break;
				}
				mov(emitm, &stream, ARM_R1, ins->k);
				cmp_r(emitm, &stream, REG_A, ARM_R1);
				jcc(emitm, &stream, ins, COND_GE, COND_LT);
				break;

			case BPF_JMP|BPF_JEQ|BPF_K:
				/* pc += (A == k) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					break;
				}
				mov(emitm, &stream, ARM_R1, ins->k);
				cmp_r(emitm, &stream, REG_A, ARM_R1);
				jcc(emitm, &stream, ins, COND_EQ, COND_NE);
				break;

			case BPF_JMP|BPF_JSET|BPF_K:
				/* pc += (A & k) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				tst(emitm, &stream, REG_A, ins->k);
				jcc(emitm, &stream, ins, COND_NE, COND_EQ);
				break;

			case BPF_JMP|BPF_JGT|BPF_X:
				/* pc += (A > X) ? jt : jf */
				printf("BPF_JMP|BPF_JGT|BPF_X\n");
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					break;
				}
				tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_GT, COND_LE);
				break;

			case BPF_JMP|BPF_JGE|BPF_X:
				/* pc += (A >= X) ? jt : jf */
				printf("BPF_JMP|BPF_JGE|BPF_X\n");
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					break;
				}
				tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_GE, COND_LT);
				break;

			case BPF_JMP|BPF_JEQ|BPF_X:
				/* pc += (A == X) ? jt : jf */
				printf("BPF_JMP|BPF_JEQ|BPF_X\n");
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_EQ, COND_NE);
				break;

			case BPF_JMP|BPF_JSET|BPF_X:
				/* pc += (A & X) ? jt : jf */
				printf("BPF_JMP|BPF_JSET|BPF_X\n");
				if (ins->jt == ins->jf) {
					branch(emitm, &stream, COND_AL, ins->jt);
					//JUMP(ins->jt);
					break;
				}
				tst_r(emitm, &stream, REG_A, REG_X);
				jcc(emitm, &stream, ins, COND_NE, COND_EQ);
				break;

			case BPF_ALU|BPF_ADD|BPF_X:
				/* A <- A + X */
				printf("BPF_ALU|BPF_ADD|BPF_X\n");
				add_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_SUB|BPF_X:
				/* A <- A - X */
				printf("BPF_ALU|BPF_SUB|BPF_X not tested: checkme\n");
				rsb_r(emitm, &stream, REG_A, REG_X, REG_A);
				break;

			case BPF_ALU|BPF_MUL|BPF_X:
				/* A <- A * X */
				printf("BPF_ALU|BPF_MUL|BPF_X not tested\n");
				mul(emitm, &stream, REG_A, REG_A, REG_X, 0);
				break;

			case BPF_ALU|BPF_DIV|BPF_X:
				/* A <- A / X */
				printf("BPF_ALU|BPF_DIV|BPF_X\n");
				mov_r(emitm, &stream, ARM_R0, REG_A);
				mov_r(emitm, &stream, ARM_R1, REG_X);
				mov(emitm, &stream, ARM_R2, (uint32_t)jit_udiv);
				branch_lx(emitm, &stream, COND_AL, ARM_R2);
				mov_r(emitm, &stream, REG_A, ARM_R0);
				break;

			case BPF_ALU|BPF_AND|BPF_X:
				/* A <- A & X */
				printf("BPF_ALU|BPF_AND|BPF_X\n");
				and_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_OR|BPF_X:
				/* A <- A | X */
				printf("BPF_ALU|BPF_OR|BPF_X\n");
				orr_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_LSH|BPF_X:
				/* A <- A << X */
				printf("BPF_ALU|BPF_LSH|BPF_X\n");
				lsl_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_RSH|BPF_X:
				/* A <- A >> X */
				printf("BPF_ALU|BPF_RSH|BPF_X\n");
				lsr_r(emitm, &stream, REG_A, REG_A, REG_X);
				break;

			case BPF_ALU|BPF_ADD|BPF_K:
				/* A <- A + k */
				printf("BPF_ALU|BPF_ADD|BPF_K\n");
				add(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_SUB|BPF_K:
				/* A <- A - k */
				printf("BPF_ALU|BPF_SUB|BPF_K\n");
				rsb(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_MUL|BPF_K:
				/* A <- A * k */
				printf("BPF_ALU|BPF_MUL|BPF_K not tested\n");
				mov(emitm, &stream, ARM_R1, ins->k);
				mul(emitm, &stream, REG_A, REG_A, ARM_R1, 0);
				break;

			case BPF_ALU|BPF_DIV|BPF_K:
				/* A <- A / k */
				printf("BPF_ALU|BPF_DIV|BPF_K\n");
				mov_r(emitm, &stream, ARM_R0, REG_A);
				mov(emitm, &stream, ARM_R1, ins->k);
				mov(emitm, &stream, ARM_R2, (uint32_t)jit_udiv);
				branch_lx(emitm, &stream, COND_AL, ARM_R2);
				mov_r(emitm, &stream, REG_A, ARM_R0);
				break;

			case BPF_ALU|BPF_AND|BPF_K:
				/* A <- A & k */
				printf("BPF_ALU|BPF_AND|BPF_K ins->k 0x%x\n", ins->k);
				and(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_OR|BPF_K:
				/* A <- A | k */
				printf("BPF_ALU|BPF_OR|BPF_K\n");
				orr(emitm, &stream, REG_A, REG_A, ins->k);
				break;

			case BPF_ALU|BPF_LSH|BPF_K:
				/* A <- A << k */
				printf("BPF_ALU|BPF_LSH|BPF_K\n");
				lsl(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				break;

			case BPF_ALU|BPF_RSH|BPF_K:
				/* A <- A >> k */
				printf("BPF_ALU|BPF_RSH|BPF_K ins->k %d\n", ins->k);
				lsr(emitm, &stream, REG_A, REG_A, (ins->k) & 0xff);
				break;

			case BPF_ALU|BPF_NEG:
				/* A <- -A */
				printf("BPF_ALU|BPF_NEG\n");
				/* substruct from zero */
				rsb(emitm, &stream, REG_A, REG_A, 0);
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
