A=CONF
if [ "$1" = "fast" ]; then
        A=FAST
else
    make -j24 TARGET=riscv KERN${A}=GENERIC cleankernel
fi

make -j24 TARGET=riscv KERN${A}=GENERIC buildkernel || exit 1

sh embed.sh || exit 2

ADDR=`sh call_hyp.sh | awk '{print $1}'`
echo until pc 0 ${ADDR}
echo until pc 0 0x0000000100000000
echo bhyve -o bootrom=/bin/ls test
echo bhyve -o bootrom=/kernel.bin test
echo bhyve -m 256 -o bootrom=/kernel.bin test
echo bhyve -m 256 -o bootrom=/kernel.bin -o console=stdio test
echo bhyve -m 256 -o bootrom=/kernel.bin -o console=stdio -s 4,virtio-blk,/bin/ls test
echo bhyve -m 2560 -o bootrom=/kernel.bin -o console=stdio -s 4,ahci-hd,/bin/ls test
echo bhyve -c 8 -m 2560 -o bootrom=/kernel.bin -o console=stdio -s 4,ahci-hd,/bin/ls test
echo bhyve -c 8 -m 256 -o bootrom=/kernel.bin -o console=stdio test
echo bhyve -c 2 -m 256 -o bootrom=/kernel.bin -o console=stdio test
echo bhyve -m 256 -o bootrom=/kernel.bin -o console=stdio test
echo "while true; do find /; done"
echo bhyve -m 256 -o bootrom=/u-boot.bin -o console=stdio test

echo bhyve -c 8 -m 256 -o bootrom=/u-boot.bin -o console=stdio -s 4,virtio-blk,/disk.img test

echo bhyve -c 8 -m 256 -o bootrom=/u-boot.bin -o console=stdio -s 3:0,virtio-rnd -s 4,virtio-blk,/dev/da0 test

echo fatload virtio 0 0x10a000000 kernel.bin

echo Startup cmd
echo bhyve -c 8 -m 256 -o bootrom=/u-boot.bin -o console=stdio -s 4,virtio-blk,/dev/da0 test
echo bootefi bootmgr

# fatload virtio  1 0x10a000000 loader.efi
# bootefi 0x10a000000

