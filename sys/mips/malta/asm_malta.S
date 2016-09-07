/*-
 * Copyright (c) 2004-2010 Juli Mallett <jmallett@FreeBSD.org>
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

#include <machine/asm.h>

	.set noreorder

#ifdef SMP
/*
 * This function must be implemented in assembly because it is called early
 * in AP boot without a valid stack.
 */
#if 1
LEAF(platform_processor_id)
	.set push
	//.set mips32r2
	mfc0	v0, $15, 1
	andi	v0, 0xf
	jr	ra
	nop
	nop
	nop
	nop
	.set pop
END(platform_processor_id)
#endif

/*
 * Called on APs to wait until they are told to launch.
 */
LEAF(malta_ap_wait)
//1:
//	j	1b
//	nop

	li	v0, 1
1:	ll	t0, malta_ap_boot
	bne	v0, t0, 1b
	nop

	move	t0, zero
	sc	t0, malta_ap_boot

	j	mpentry
	nop

#if 0
	jal	platform_processor_id
	nop

1:	ll	t0, malta_ap_boot
	bne	v0, t0, 1b
	nop

	move	t0, zero
	sc	t0, malta_ap_boot

	beqz	t0, 1b
	nop

	j	mpentry
	nop
#endif
END(malta_ap_wait)
#endif
