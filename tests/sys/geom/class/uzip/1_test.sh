#!/bin/sh
# $FreeBSD$

testsdir=$(dirname $0)
. $testsdir/conf.sh

# Check host endianness
endian=$(echo I | tr -d "[:space:]" | od -to2 | head -n1 | awk '{print $2}' | cut -c6)
if [ $endian -eq 0 ]; then
	UUE=$testsdir/1_eb.img.uzip.uue
else
	UUE=$testsdir/1.img.uzip.uue
fi

echo "1..1"

uudecode $UUE
us0=$(attach_md -f $(basename $UUE .uue)) || exit 1
sleep 1

mount -o ro /dev/${us0}.uzip "${mntpoint}" || exit 1

#cat "${mntpoint}/etalon.txt"
diff -I '\$FreeBSD.*\$' -u $testsdir/etalon/etalon.txt "${mntpoint}/etalon.txt"
if [ $? -eq 0 ]; then
	echo "ok 1"
else
	echo "not ok 1"
fi
