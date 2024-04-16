A=CONF
if [ "$1" = "fast" ]; then
        A=FAST
fi

make -j24 TARGET=riscv KERN${A}=GENERIC buildkernel || exit 1

sh embed.sh || exit 2

ADDR=`sh call_hyp.sh | awk '{print $1}'`
echo until pc 0 ${ADDR}
echo bhyve -o bootrom=/bin/ls test
echo bhyve -o bootrom=/kernel.bin test
