sh ./sys/tools/embed_mfs.sh /usr/obj/usr/home/br/dev/freebsd/sys/GENERIC/kernel /home/br/dev/freebsd/mdroot.img

riscv64-unknown-freebsd15.0-objcopy -O binary /usr/obj/usr/home/br/dev/freebsd/sys/GENERIC/kernel /usr/obj/usr/home/br/dev/freebsd/sys/GENERIC/kernel.bin
