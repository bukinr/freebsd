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
#define	A64_R(x)	(x)
#define	A64_FP		A64_R(29)
#define	A64_LR		A64_R(30)
#define	A64_SP		A64_R(31)

/*
 * Instructions assembly parts
 */
#define	OPC_S		30
#define	OPC_LDP		0b10
#define	OPC_STP		0b10
#define	RT2_S		10
#define	RT1_S		0

#define	RM_S		16
#define	RD_S		0
#define	RT_S		0
#define	RA_S		10	/* Addend shift */
#define	RN_S		5
#define	IMM6_S		10
#define	IMM7_S		15
#define	IMM9_S		12
#define	IMM12_S		10
#define	IMM16_S		5
#define	IMM19_S		5
#define	IMM26_S		0
#define	IMMR_S		16
#define	IMMS_S		10
#define	IMM_N		(1 << 22)

#define	MOVE_WIDE_OP_S	29
#define	MOVE_WIDE_OP_N	0
#define	MOVE_WIDE_OP_Z	2
#define	MOVE_WIDE_OP_K	3
#define	HW_S		21

#define	SHIFT_LSL	0
#define	SHIFT_LSR	1
#define	SHIFT_ASR	10
#define	SHIFT_S		22

/* Condition codes */
#define	COND_S		0
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
