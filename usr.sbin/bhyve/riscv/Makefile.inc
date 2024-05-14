SRCS+=	\
	fdt.c		\
	rtc_pl031.c	\
	uart_pl011.c

.PATH:  ${BHYVE_SYSDIR}/sys/riscv/vmm
SRCS+=	vmm_instruction_emul.c

BHYVE_FDT_SUPPORT=
