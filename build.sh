A=CONF
if [ "$1" = "fast" ]; then
        A=FAST
fi

make -j24 TARGET=riscv KERN${A}=GENERIC buildkernel || exit 1

sh embed.sh
