/*-
 * Copyright (C) 2002-2003 NetGroup, Politecnico di Torino (Italy)
 * Copyright (C) 2005-2009 Jung-uk Kim <jkim@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

/*
 * Emit routine to update the jump table.
 */
static void
emit_length(bpf_bin_stream *stream, __unused u_int value, u_int len)
{

	printf("%s\n", __func__);

	if (stream->refs != NULL)
		(stream->refs)[stream->bpf_pc] += len;
	stream->cur_ip += len;
}

/*
 * Emit routine to output the actual binary code.
 */
static void
emit_code(bpf_bin_stream *stream, u_int value, u_int len)
{

	printf("%s\n", __func__);

	switch (len) {
	case 1:
		stream->ibuf[stream->cur_ip] = (u_char)value;
		stream->cur_ip++;
		break;

	case 2:
		*((u_short *)(stream->ibuf + stream->cur_ip)) = (u_short)value;
		stream->cur_ip += 2;
		break;

	case 4:
		*((u_int *)(stream->ibuf + stream->cur_ip)) = value;
		stream->cur_ip += 4;
		break;
	}

	return;
}

static int16_t
imm8m(uint32_t x)
{
	uint32_t rot;

	for (rot = 0; rot < 16; rot++)
		if ((x & ~ror32(0xff, 2 * rot)) == 0)
			return (rol32(x, 2 * rot) | (rot << 8));

	return (-1);
}

static uint32_t
push(uint32_t reg_list)
{
	uint32_t instr;

	instr = (1 << 27);
	instr |= (ARM_SP << RN_S);
	instr |= (COND_AL << COND_S);
	instr |= (WRITE_BACK | PRE_INDEX);
	instr |= (reg_list);

	return (instr);
}

static uint32_t
pop(uint32_t reg_list)
{
	uint32_t instr;

	instr = (1 << 27);
	instr |= (ARM_SP << RN_S);
	instr |= (COND_AL << COND_S);
	instr |= (WRITE_BACK | POST_INDEX | UP_BIT | OP_LOAD);
	instr |= (reg_list);

	return (instr);
}

static uint32_t
branch(uint32_t cond, uint32_t offs)
{
	uint32_t instr;

	instr = (1 << 25) | (1 << 27);
	instr |= (cond << COND_S);
	instr |= (offs >> 2);

	return (instr);
}

static uint32_t
mov_i(uint32_t rd, uint32_t imm)
{
	uint32_t instr;

	instr = (OPCODE_MOV << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (imm << IMM_S);
	instr |= IMM_OP;	/* operand 2 is an immediate value */

	return (instr);
}

static uint32_t
mov_r(uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_MOV << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	return (instr);
}

static uint32_t
cmp_r(uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_CMP << OPCODE_S) | (COND_AL << COND_S);
	//instr |= (rd << RD_S) | (rm << RM_S);
	instr |= (rn << RN_S) | (rm << RM_S);
	instr |= COND_SET;

	return (instr);
}

static uint32_t
add_r(uint32_t rd, uint32_t rn, uint32_t rm)
{
	uint32_t instr;

	instr = (OPCODE_ADD << OPCODE_S) | (COND_AL << COND_S);
	instr |= (rn << RN_S) | (rm << RM_S);

	return (instr);
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
ldrb(uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 26);
	instr |= (COND_AL << COND_S) | BYTE_BIT | OP_LOAD;
	instr |= UP_BIT | PRE_INDEX;
	instr |= (rd << RD_S) | (rm << RM_S);
	//instr |= IMM_OP;	/* 1 = offset is a register */

	return (instr);
}

#define	SH_S		5
#define	SH_SWP		0	/* SWP instruction */
#define	SH_UH		1	/* Unsigned halfwords */
#define	SH_SB		2	/* Signed byte */
#define	SH_SH		3	/* Signed halfwords */

static uint32_t
ldrh(uint32_t rd, uint32_t rn)
{
	uint32_t instr;

	instr = (1 << 4) | (1 << 7);
	instr |= (COND_AL << COND_S) | OP_LOAD;
	instr |= (BYTE_BIT | UP_BIT | PRE_INDEX);
	instr |= (SH_UH << SH_S);
	instr |= (rd << RD_S) | (rn << RN_S);

	return (instr);
}

static uint32_t
rev16(uint32_t rd, uint32_t rm)
{
	uint32_t instr;

	instr = (1 << 23) | (1 << 25) | (1 << 26);
	instr |= (1 << 20) | (1 << 21);
	instr |= (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19);
	instr |= (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);
	instr |= (1 << 7);
	instr |= (1 << 4) | (1 << 5);

	instr |= (COND_AL << COND_S);
	instr |= (rd << RD_S) | (rm << RM_S);

	return (instr);
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
	uint32_t instr;
	uint32_t offs;
	int imm12;

#define	REG_A		ARM_R4
#define	REG_X		ARM_R5
#define	REG_MBUF	ARM_R6

	reg_list = (1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 6);

	for (pass = 0; pass < 2; pass++) {
		ins = prog;

		//if (fpkt || fmem) {
			instr = push(reg_list);
			emitm(&stream, instr, 4);
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
		//	MOVrd2(ESI, R9D);
		}
		if (fpkt) {
			printf("fpkt\n");

			instr = mov_r(REG_MBUF, ARM_R0);
			emitm(&stream, instr, 4);

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
				printf("BPF_RET|BPF_K, ins->k 0x%08x\n", ins->k);

				imm12 = imm8m(ins->k);
				if (imm12 >= 0) {
					instr = mov_i(ARM_R0, imm12);
					emitm(&stream, instr, 4);
				} else {
					panic("implement me 1\n");
				}

				if (fmem)
					panic("implement fmem");

				//MOVid(ins->k, EAX);
				//if (fmem)
				//	LEAVE();
				//RET();

				//if (fmem) {
					instr = pop(reg_list);
					emitm(&stream, instr, 4);
				//}

				// BX LR
				emitm(&stream, 0xe12fff1e, 4);

				break;

			case BPF_RET|BPF_A:
				printf("BPF_RET|BPF_A\n");
				if (fmem) {
					LEAVE();
				}
				RET();
				break;

			case BPF_LD|BPF_W|BPF_ABS:
				printf("BPF_LD|BPF_W|BPF_ABS\n");
				MOVid(ins->k, ESI);
				CMPrd(EDI, ESI);
				JAb(12);
				MOVrd(EDI, ECX);
				SUBrd(ESI, ECX);
				CMPid(sizeof(int32_t), ECX);
				if (fmem) {
					JAEb(4);
					ZEROrd(EAX);
					LEAVE();
				} else {
					JAEb(3);
					ZEROrd(EAX);
				}
				RET();
				MOVrq3(R8, RCX);
				MOVobd(RCX, RSI, EAX);
				BSWAP(EAX);
				break;

			case BPF_LD|BPF_H|BPF_ABS:
				printf("BPF_LD|BPF_H|BPF_ABS: ins->k 0x%x\n", ins->k);

				/* Copy K value to R1 */
				instr = mov_i(ARM_R1, ins->k);
				emitm(&stream, instr, 4);

				/* Get offset */
				instr = add_r(ARM_R0, ARM_R1, REG_MBUF);
				emitm(&stream, instr, 4);

				/* Load half word from offset */
				instr = ldrh(ARM_R0, ARM_R0);
				emitm(&stream, instr, 4);

				/* Reverse as network packets are big-endian */
				instr = rev16(REG_A, ARM_R0);
				emitm(&stream, instr, 4);

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
				printf("BPF_LD|BPF_B|BPF_ABS: ins->k 0x%x\n", ins->k);

				/* Copy K value to R1 */
				instr = mov_i(ARM_R1, ins->k);
				emitm(&stream, instr, 4);

				/* Get offset */
				instr = add_r(ARM_R0, ARM_R1, REG_MBUF);
				emitm(&stream, instr, 4);

				/* Load byte from offset */
				instr = ldrb(REG_A, ARM_R0);
				emitm(&stream, instr, 4);

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
				printf("BPF_LD|BPF_W|BPF_LEN\n");
				MOVrd3(R9D, EAX);
				break;

			case BPF_LDX|BPF_W|BPF_LEN:
				printf("BPF_LDX|BPF_W|BPF_LEN\n");
				MOVrd3(R9D, EDX);
				break;

			case BPF_LD|BPF_W|BPF_IND:
				printf("BPF_LD|BPF_W|BPF_IND\n");
				CMPrd(EDI, EDX);
				JAb(27);
				MOVid(ins->k, ESI);
				MOVrd(EDI, ECX);
				SUBrd(EDX, ECX);
				CMPrd(ESI, ECX);
				JBb(14);
				ADDrd(EDX, ESI);
				MOVrd(EDI, ECX);
				SUBrd(ESI, ECX);
				CMPid(sizeof(int32_t), ECX);
				if (fmem) {
					JAEb(4);
					ZEROrd(EAX);
					LEAVE();
				} else {
					JAEb(3);
					ZEROrd(EAX);
				}
				RET();
				MOVrq3(R8, RCX);
				MOVobd(RCX, RSI, EAX);
				BSWAP(EAX);
				break;

			case BPF_LD|BPF_H|BPF_IND:
				printf("BPF_LD|BPF_H|BPF_IND\n");
				ZEROrd(EAX);
				CMPrd(EDI, EDX);
				JAb(27);
				MOVid(ins->k, ESI);
				MOVrd(EDI, ECX);
				SUBrd(EDX, ECX);
				CMPrd(ESI, ECX);
				JBb(14);
				ADDrd(EDX, ESI);
				MOVrd(EDI, ECX);
				SUBrd(ESI, ECX);
				CMPid(sizeof(int16_t), ECX);
				if (fmem) {
					JAEb(2);
					LEAVE();
				} else
					JAEb(1);
				RET();
				MOVrq3(R8, RCX);
				MOVobw(RCX, RSI, AX);
				SWAP_AX();
				break;

			case BPF_LD|BPF_B|BPF_IND:
				printf("BPF_LD|BPF_B|BPF_IND\n");
				ZEROrd(EAX);
				CMPrd(EDI, EDX);
				JAEb(13);
				MOVid(ins->k, ESI);
				MOVrd(EDI, ECX);
				SUBrd(EDX, ECX);
				CMPrd(ESI, ECX);
				if (fmem) {
					JAb(2);
					LEAVE();
				} else
					JAb(1);
				RET();
				MOVrq3(R8, RCX);
				ADDrd(EDX, ESI);
				MOVobb(RCX, RSI, AL);
				break;

			case BPF_LDX|BPF_MSH|BPF_B:
				printf("BPF_LDX|BPF_MSH|BPF_B\n");
				MOVid(ins->k, ESI);
				CMPrd(EDI, ESI);
				if (fmem) {
					JBb(4);
					ZEROrd(EAX);
					LEAVE();
				} else {
					JBb(3);
					ZEROrd(EAX);
				}
				RET();
				ZEROrd(EDX);
				MOVrq3(R8, RCX);
				MOVobb(RCX, RSI, DL);
				ANDib(0x0f, DL);
				SHLib(2, EDX);
				break;

			case BPF_LD|BPF_IMM:
				printf("BPF_LD|BPF_IMM\n");
				MOVid(ins->k, EAX);
				break;

			case BPF_LDX|BPF_IMM:
				printf("BPF_LDX|BPF_IMM\n");
				MOVid(ins->k, EDX);
				break;

			case BPF_LD|BPF_MEM:
				printf("BPF_LD|BPF_MEM\n");
				MOVid(ins->k * sizeof(uint32_t), ESI);
				MOVobd(RSP, RSI, EAX);
				break;

			case BPF_LDX|BPF_MEM:
				printf("BPF_LDX|BPF_MEM\n");
				MOVid(ins->k * sizeof(uint32_t), ESI);
				MOVobd(RSP, RSI, EDX);
				break;

			case BPF_ST:
				printf("BPF_ST\n");
				/*
				 * XXX this command and the following could
				 * be optimized if the previous instruction
				 * was already of this type
				 */
				MOVid(ins->k * sizeof(uint32_t), ESI);
				MOVomd(EAX, RSP, RSI);
				break;

			case BPF_STX:
				printf("BPF_STX\n");
				MOVid(ins->k * sizeof(uint32_t), ESI);
				MOVomd(EDX, RSP, RSI);
				break;

			case BPF_JMP|BPF_JA:
				printf("BPF_JMP|BPF_JA\n");
				JUMP(ins->k);
				break;

			case BPF_JMP|BPF_JGT|BPF_K:
				printf("BPF_JMP|BPF_JGT|BPF_K\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				CMPid(ins->k, EAX);
				JCC(JA, JBE);
				break;

			case BPF_JMP|BPF_JGE|BPF_K:
				printf("BPF_JMP|BPF_JGE|BPF_K\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				CMPid(ins->k, EAX);
				JCC(JAE, JB);
				break;

			case BPF_JMP|BPF_JEQ|BPF_K:
				printf("BPF_JMP|BPF_JEQ|BPF_K ins->jt 0x%x ins->jf 0x%x ins->k 0x%x\n",
				    ins->jt, ins->jf, ins->k);
				if (ins->jt == ins->jf) {
					panic("implement jump\n");
					//JUMP(ins->jt);
					break;
				}

				//cmp_i(REG_A, ins->k);
				imm12 = imm8m(ins->k);
				if (imm12 >= 0) {
					instr = mov_i(ARM_R1, imm12);
					emitm(&stream, instr, 4);
				} else {
					//instr = ARM_MOVW(ARM_R1, ins->k);
					//emitm(&stream, instr, 4);

					if (ins->k > 0xffff) {
						instr = ARM_MOVT(ARM_R1, (ins->k >> 16));
						emitm(&stream, instr, 4);
					}
				}

				instr = cmp_r(REG_A, ARM_R1);
				emitm(&stream, instr, 4);

				//emitm(&stream, KERNEL_BREAKPOINT, 4);

				//instr = pop(reg_list);
				//emitm(&stream, instr, 4);

				if (ins->jt != 0 && ins->jf != 0) {
					offs = stream.refs[stream.bpf_pc + ins->jt] - stream.refs[stream.bpf_pc] - 4;
					printf("offs 0x%08x\n", offs);

					instr = branch(COND_EQ, offs);
					emitm(&stream, instr, 4);

				} else if (ins->jt != 0) {
					offs = stream.refs[stream.bpf_pc + ins->jt] - stream.refs[stream.bpf_pc] - 4;
					printf("offs 0x%08x\n", offs);

					instr = branch(COND_EQ, offs);
					emitm(&stream, instr, 4);

				} else if (ins->jf != 0) {
					offs = stream.refs[stream.bpf_pc + ins->jf] - stream.refs[stream.bpf_pc] - 4;
					printf("offs 0x%08x\n", offs);

					instr = branch(COND_NE, offs);
					emitm(&stream, instr, 4);
				}

				//CMPid(ins->k, EAX);
				//JCC(JE, JNE);
				break;

			case BPF_JMP|BPF_JSET|BPF_K:
				printf("BPF_JMP|BPF_JSET|BPF_K\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				TESTid(ins->k, EAX);
				JCC(JNE, JE);
				break;

			case BPF_JMP|BPF_JGT|BPF_X:
				printf("BPF_JMP|BPF_JGT|BPF_X\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				CMPrd(EDX, EAX);
				JCC(JA, JBE);
				break;

			case BPF_JMP|BPF_JGE|BPF_X:
				printf("BPF_JMP|BPF_JGE|BPF_X\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				CMPrd(EDX, EAX);
				JCC(JAE, JB);
				break;

			case BPF_JMP|BPF_JEQ|BPF_X:
				printf("BPF_JMP|BPF_JEQ|BPF_X\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				CMPrd(EDX, EAX);
				JCC(JE, JNE);
				break;

			case BPF_JMP|BPF_JSET|BPF_X:
				printf("BPF_JMP|BPF_JSET|BPF_X\n");
				if (ins->jt == ins->jf) {
					JUMP(ins->jt);
					break;
				}
				TESTrd(EDX, EAX);
				JCC(JNE, JE);
				break;

			case BPF_ALU|BPF_ADD|BPF_X:
				printf("BPF_ALU|BPF_ADD|BPF_X\n");
				ADDrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_SUB|BPF_X:
				printf("BPF_ALU|BPF_SUB|BPF_X\n");
				SUBrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_MUL|BPF_X:
				printf("BPF_ALU|BPF_MUL|BPF_X\n");
				MOVrd(EDX, ECX);
				MULrd(EDX);
				MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_DIV|BPF_X:
				printf("BPF_ALU|BPF_DIV|BPF_X\n");
				TESTrd(EDX, EDX);
				if (fmem) {
					JNEb(4);
					ZEROrd(EAX);
					LEAVE();
				} else {
					JNEb(3);
					ZEROrd(EAX);
				}
				RET();
				MOVrd(EDX, ECX);
				ZEROrd(EDX);
				DIVrd(ECX);
				MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_AND|BPF_X:
				printf("BPF_ALU|BPF_AND|BPF_X\n");
				ANDrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_OR|BPF_X:
				printf("BPF_ALU|BPF_OR|BPF_X\n");
				ORrd(EDX, EAX);
				break;

			case BPF_ALU|BPF_LSH|BPF_X:
				printf("BPF_ALU|BPF_LSH|BPF_X\n");
				MOVrd(EDX, ECX);
				SHL_CLrb(EAX);
				break;

			case BPF_ALU|BPF_RSH|BPF_X:
				printf("BPF_ALU|BPF_RSH|BPF_X\n");
				MOVrd(EDX, ECX);
				SHR_CLrb(EAX);
				break;

			case BPF_ALU|BPF_ADD|BPF_K:
				printf("BPF_ALU|BPF_ADD|BPF_K\n");
				ADD_EAXi(ins->k);
				break;

			case BPF_ALU|BPF_SUB|BPF_K:
				printf("BPF_ALU|BPF_SUB|BPF_K\n");
				SUB_EAXi(ins->k);
				break;

			case BPF_ALU|BPF_MUL|BPF_K:
				printf("BPF_ALU|BPF_MUL|BPF_K\n");
				MOVrd(EDX, ECX);
				MOVid(ins->k, EDX);
				MULrd(EDX);
				MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_DIV|BPF_K:
				printf("BPF_ALU|BPF_DIV|BPF_K\n");
				MOVrd(EDX, ECX);
				ZEROrd(EDX);
				MOVid(ins->k, ESI);
				DIVrd(ESI);
				MOVrd(ECX, EDX);
				break;

			case BPF_ALU|BPF_AND|BPF_K:
				printf("BPF_ALU|BPF_AND|BPF_K\n");
				ANDid(ins->k, EAX);
				break;

			case BPF_ALU|BPF_OR|BPF_K:
				printf("BPF_ALU|BPF_OR|BPF_K\n");
				ORid(ins->k, EAX);
				break;

			case BPF_ALU|BPF_LSH|BPF_K:
				printf("BPF_ALU|BPF_LSH|BPF_K\n");
				SHLib((ins->k) & 0xff, EAX);
				break;

			case BPF_ALU|BPF_RSH|BPF_K:
				printf("BPF_ALU|BPF_RSH|BPF_K\n");
				SHRib((ins->k) & 0xff, EAX);
				break;

			case BPF_ALU|BPF_NEG:
				printf("BPF_ALU|BPF_NEG\n");
				NEGd(EAX);
				break;

			case BPF_MISC|BPF_TAX:
				printf("BPF_MISC|BPF_TAX\n");
				MOVrd(EAX, EDX);
				break;

			case BPF_MISC|BPF_TXA:
				printf("BPF_MISC|BPF_TXA\n");
				MOVrd(EDX, EAX);
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
