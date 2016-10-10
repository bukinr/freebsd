/*	$NetBSD: flt_rounds.c,v 1.5 2005/12/24 23:10:08 perry Exp $	*/

/*
 * Written by J.T. Conklin, Apr 11, 1995
 * Public domain.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: flt_rounds.c,v 1.5 2005/12/24 23:10:08 perry Exp $");
#endif /* LIBC_SCCS and not lint */

#include <fenv.h>
#include <float.h>

//#include <machine/float.h>

#include "softfloat-for-gcc.h"
#include "milieu.h"
#include "softfloat.h"

#if 0
static const int map[] = {
	1,	/* round to nearest */
	0,	/* round to zero */
	2,	/* round to positive infinity */
	3	/* round to negative infinity */
};
#endif

int
__flt_rounds()
{
	int mode;

	mode = __softfloat_float_rounding_mode;

        switch (mode) {
        case FE_TOWARDZERO:
                return (0);
        case FE_TONEAREST:
                return (1);
        case FE_UPWARD:
                return (2);
        case FE_DOWNWARD:
                return (3);
        }
        return (-1);


	//int x;
	//__asm("cfc1 %0,$31" : "=r" (x));
	//return map[x & 0x03];
}
