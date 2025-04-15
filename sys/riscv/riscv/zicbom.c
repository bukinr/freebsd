/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/zicbom.h>

static int cache_line;

static void
flush_dcache_range(vm_offset_t start, vm_size_t len)
{
	vm_offset_t addr;

	start &= ~(cache_line - 1);
	for (addr = start; addr < start + len; addr += cache_line)
		__asm __volatile("cbo.flush 0(%[addr])\n" :: [addr] "r"(addr));
}

static void
zicbom_cpu_dcache_wbinv_range(vm_offset_t va, vm_size_t len)
{

	flush_dcache_range(va, len);
}

static void
zicbom_cpu_dcache_inv_range(vm_offset_t va, vm_size_t len)
{

	flush_dcache_range(va, len);
}

static void
zicbom_cpu_dcache_wb_range(vm_offset_t va, vm_size_t len)
{

	flush_dcache_range(va, len);
}

void
zicbom_setup_cache(int cbom_block_size)
{
	struct riscv_cache_ops zicbom_ops;

	cache_line = cbom_block_size;

	zicbom_ops.dcache_wbinv_range = zicbom_cpu_dcache_wbinv_range;
	zicbom_ops.dcache_inv_range = zicbom_cpu_dcache_inv_range;
	zicbom_ops.dcache_wb_range = zicbom_cpu_dcache_wb_range;
	riscv_cache_install_hooks(&zicbom_ops, cbom_block_size);
}
