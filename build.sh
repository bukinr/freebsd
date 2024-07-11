A=CONF
if [ "$1" = "fast" ]; then
        A=FAST
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
echo bhyve -c 8 -m 256 -o bootrom=/kernel.bin -o console=stdio test
echo bhyve -c 2 -m 256 -o bootrom=/kernel.bin -o console=stdio test
echo bhyve -m 256 -o bootrom=/kernel.bin -o console=stdio test
