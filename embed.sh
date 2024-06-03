sh ./sys/tools/embed_mfs.sh /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel /home/br/dev/freebsd/mdroot.img

riscv64-unknown-freebsd15.0-objcopy -O binary /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel.bin
