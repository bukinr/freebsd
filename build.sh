make -j24 TARGET=riscv buildkernel || exit 1

cp /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel /tftpboot/codasip_vcu118/

riscv64-unknown-freebsd15.0-objcopy -O binary /tftpboot/codasip_vcu118/kernel /tftpboot/codasip_vcu118/kernel.bin

echo "setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.93; tftp 0x82000000 codasip_vcu118/kernel.bin; go 0x82000000 0 \$fdt_addr"

echo fatload mmc 0 0x82000000 loader_lua.efi
