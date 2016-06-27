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

#ifndef _BPF_JIT_MACHDEP_H_
#define _BPF_JIT_MACHDEP_H_

/*
 * ARMv8 registers
 */
#define	ARM_R0	0
#define	ARM_R1	1
#define	ARM_R2	2
#define	ARM_R3	3
#define	ARM_R4	4
#define	ARM_R5	5
#define	ARM_R6	6
#define	ARM_R7	7
#define	ARM_R8	8
#define	ARM_R9	9
#define	ARM_R10	10
#define	ARM_FP	11
#define	ARM_IP	12
#define	ARM_SP	13
#define	ARM_LR	14
#define	ARM_PC	15

#define	A64_R(x)	(x)
#define	A64_FP		A64_R(29)
#define	A64_LR		A64_R(30)
#define	A64_SP		A64_R(31)

#define rol32(i32, n) ((i32) << (n) | (i32) >> (32 - (n)))
#define ror32(i32, n) ((i32) >> (n) | (i32) << (32 - (n)))

#define	ARM_RET		0xe12fff1e	/* bx lr */
#define	ARM_LSL_I	0x01a00000	/* shift left by imm */
#define	ARM_LSL_R	0x01a00010	/* shift left by reg */
#define	ARM_LSR_I	0x01a00020	/* shirt right by imm */
#define	ARM_LSR_R	0x01a00030	/* shift right by reg */
#define	ARM_REV		0x06bf0f30	/* reverse word */
#define	ARM_REV16	0x06bf0fb0	/* reverse half word */
#define	ARM_MOVW	0x03000000	/* copy bottom half word */
#define	ARM_MOVT	0x03400000	/* copy top half word */

/* ---- MUL ---- */
#define	MUL_ACCUMULATE	(1 << 21)	/* multiply and accumulate */
#define	RS_S		8		/* operand register */

/* ---- MOV, ADD, CMP ---- */
//#define	RD_S		12		/* Destination register */
//#define	RN_S		16		/* 1st operand register */
#define	COND_SET	(1 << 20)	/* Set condition codes */
#define	OPCODE_S	21		/* Operation Code */
#define	IMM_OP		(1 << 25)	/* Immediate Operand */
#define	COND_S		28		/* Condition field */

/* IMM_OP == 0 */
//#define	RM_S		0		/* 2nd operand register */
#define	RM_SHIFT_S	4		/* shift applied to Rm */

/* IMM_OP == 1 */
#define	IMM_S		0		/* Unsigned 8 bit immediate value */
#define	ROTATE_S	8		/* shift applied to Imm */

/* ---- LDR, STR (Single Data Transfer) ---- */
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

/* ---- Halfword and Signed Data Transfer ---- */
#define	SH_S	5	/* SH shift */
#define	SH_SWP	0	/* SWP instruction */
#define	SH_UH	1	/* Unsigned halfwords */
#define	SH_SB	2	/* Signed byte */
#define	SH_SH	3	/* Signed halfwords */

#define	OPCODE_AND	0b0000
#define	OPCODE_ADD	0b0100
#define	OPCODE_TST	0b1000
#define	OPCODE_SUB	0b0010
#define	OPCODE_MOV	0b1101
#define	OPCODE_CMP	0b1010
#define	OPCODE_RSB	0b0011
#define	OPCODE_ORR	0b1100

#define	COND_EQ		0b0000
#define	COND_NE		0b0001
#define	COND_CS		0b0010
#define	COND_CC		0b0011
#define	COND_GT		0b1100
#define	COND_GE		0b1010
#define	COND_LE		0b1101
#define	COND_LT		0b1011
#define	COND_AL		0b1110	/* Always */

/* Optimization flags */
#define	BPF_JIT_FRET	0x01
#define	BPF_JIT_FPKT	0x02
#define	BPF_JIT_FMEM	0x04
#define	BPF_JIT_FJMP	0x08
#define	BPF_JIT_FLEN	0x10

#define	BPF_JIT_FLAG_ALL	\
    (BPF_JIT_FPKT | BPF_JIT_FMEM | BPF_JIT_FJMP | BPF_JIT_FLEN)

/* A stream of native binary code */
typedef struct bpf_bin_stream {
	/* Current native instruction pointer. */
	int		cur_ip;

	/*
	 * Current BPF instruction pointer, i.e. position in
	 * the BPF program reached by the jitter.
	 */
	int		bpf_pc;

	/* Instruction buffer, contains the generated native code. */
	char		*ibuf;

	/* Jumps reference table. */
	u_int		*refs;
} bpf_bin_stream;

/*
 * Prototype of the emit functions.
 *
 * Different emit functions are used to create the reference table and
 * to generate the actual filtering code. This allows to have simpler
 * instruction macros.
 * The first parameter is the stream that will receive the data.
 * The second one is a variable containing the data.
 */
typedef void (*emit_func)(bpf_bin_stream *stream, u_int value);

#endif /* _BPF_JIT_MACHDEP_H_ */
