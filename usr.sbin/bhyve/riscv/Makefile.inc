SRCS+=

.PATH:  ${BHYVE_SYSDIR}/sys/riscv/vmm
SRCS+=	vmm_instruction_emul.c

# CFLAGS.kernemu_dev.c+=	-I${SRCTOP}/sys/amd64

# SUBDIR+=	kbdlayout
