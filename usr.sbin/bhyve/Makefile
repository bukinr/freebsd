#
#

.include <src.opts.mk>

PROG=	bhyve
PACKAGE=	bhyve

MAN=	bhyve.8 bhyve_config.5

BHYVE_SYSDIR?=${SRCTOP}

.PATH:	${.CURDIR}/${MACHINE_CPUARCH}	\
	${SRCTOP}/sys/libkern		\
	${SRCTOP}/sys/cam/ctl

SRCS=	\
	audio.c			\
	bhyvegc.c		\
	bhyverun.c		\
	bootrom.c		\
	config.c		\
	console.c		\
	crc16.c			\
	ctl_scsi_all.c		\
	ctl_util.c		\
	iov.c			\
	mem.c			\
	mevent.c		\
	smbiostbl.c		\
	sockstream.c		\
	uart_backend.c		\
	uart_emul.c		\
	usb_emul.c		\
	riscv/bhyverun_machdep.c\
	usb_mouse.c

.if ${MK_BHYVE_SNAPSHOT} != "no"
SRCS+=	snapshot.c
.endif

.include "${MACHINE_CPUARCH}/Makefile.inc"

.if defined(BHYVE_GDB_SUPPORT)
SRCS+=	gdb.c
CFLAGS+= -DBHYVE_GDB
.ifdef GDB_LOG
CFLAGS+=-DGDB_LOG
.endif
SUBDIR+= gdb
.endif

CFLAGS+=-I${.CURDIR}		\
	-I${.CURDIR}/../../contrib/lib9p \
	-I${SRCTOP}/sys

LIBADD=	vmmapi md nv pthread z util sbuf cam 9p

.if ${MK_BHYVE_SNAPSHOT} != "no"
LIBADD+= ucl xo
.endif

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+=-DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DINET6
.endif
.if ${MK_NETGRAPH_SUPPORT} != "no"
# SRCS+=	net_backend_netgraph.c
# LIBADD+=	netgraph
.endif
.if ${MK_OPENSSL} == "no"
CFLAGS+=-DNO_OPENSSL
.else
LIBADD+=	crypto
CFLAGS+=-DOPENSSL_API_COMPAT=0x10100000L
.endif

CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/e1000
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/mii
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/usb/controller
.if ${MK_BHYVE_SNAPSHOT} != "no"
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
CFLAGS+= -DBHYVE_SNAPSHOT
.endif

# Disable thread safety analysis since it only finds very simple bugs and
# yields many false positives.
NO_WTHREAD_SAFETY=

NO_WCAST_ALIGN=

.include <bsd.prog.mk>
