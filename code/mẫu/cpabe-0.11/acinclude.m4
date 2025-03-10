dnl Check for GNU MP (at least version 4.0) and set GMP_CFLAGS and

dnl GMP_LIBS appropriately.

AC_DEFUN([GMP_4_0_CHECK],
[

AC_MSG_CHECKING(for GMP version >= 4.0.0 or later)

AC_ARG_WITH(
  gmp-include,
  AC_HELP_STRING(
    [--with-gmp-include=DIR],
    [look for the header gmp.h in DIR rather than the default search path]),
  [GMP_CFLAGS="-I$withval"], [GMP_CFLAGS=""])

AC_ARG_WITH(
  gmp-lib,
  AC_HELP_STRING([--with-gmp-lib=DIR],
    [look for libgmp.so in DIR rather than the default search path]),
  [
    case $withval in
      /* ) true;;
      *  ) AC_MSG_ERROR([

You must specify an absolute path for --with-gmp-lib.
]) ;;
    esac
    GMP_LIBS="-L$withval -Wl,-rpath $withval -Wl,-rpath /usr/local/lib -lgmp"
  ], [GMP_LIBS="-Wl,-rpath /usr/local/lib -lgmp"])

BACKUP_CFLAGS=${CFLAGS}
BACKUP_LIBS=${LIBS}

CFLAGS="${CFLAGS} ${GMP_CFLAGS}"
LIBS="${LIBS} ${GMP_LIBS}"

AC_TRY_LINK(
  [#include <gmp.h>],
  [mpz_t a; mpz_init (a);],
  [
    AC_TRY_RUN(
      [
#include <gmp.h>
int main() { if (__GNU_MP_VERSION < 4) return -1; else return 0; }
],
      [
        AC_MSG_RESULT(found)
        AC_SUBST(GMP_CFLAGS)
        AC_SUBST(GMP_LIBS)
        AC_DEFINE(HAVE_GMP,1,[Defined if GMP is installed])
      ],
      [
        AC_MSG_RESULT(old version)
        AC_MSG_ERROR([

Your version of the GNU Multiple Precision library (libgmp) is too
old! Please install a more recent version from http://gmplib.org/ and
try again. If more than one version is installed, try specifying a
particular version with

  ./configure --with-gmp-include=DIR --with-gmp-lib=DIR

See ./configure --help for more information.
])
      ])
  ],
  [
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR([

The GNU Multiple Precision library (libgmp) was not found on your
system! Please obtain it from http://gmplib.org/ and install it before
trying again. If libgmp is already installed in a non-standard
location, try again with

  ./configure --with-gmp-include=DIR --with-gmp-lib=DIR

If you already specified those arguments, double check that gmp.h can
be found in the first path and libgmp.a can be found in the second.

See ./configure --help for more information.
])
  ])

CFLAGS=${BACKUP_CFLAGS}
LIBS=${BACKUP_LIBS}

])

dnl Check for librelic and set RELIC_CFLAGS and RELIC_LIBS appropriately.

AC_DEFUN([RELIC_CHECK],
[

AC_MSG_CHECKING(for the RELIC library)

AC_ARG_WITH(
  relic-include,
  AC_HELP_STRING(
    [--with-relic-include=DIR],
    [look for the header relic.h in DIR rather than the default search path]),
  [RELIC_CFLAGS="-I$withval"], [RELIC_CFLAGS="-I/usr/local/include/relic"])

AC_ARG_WITH(
  relic-lib,
  AC_HELP_STRING(
    [--with-relic-lib=DIR],
    [look for librelic.so in DIR rather than the default search path]),
  [
    case $withval in
      /* ) true;;
      *  ) AC_MSG_ERROR([

You must specify an absolute path for --with-relic-lib.
]) ;;
    esac
    RELIC_LIBS="-L$withval -Wl,-rpath $withval -Wl,-rpath /usr/local/lib -lrelic"
  ], [RELIC_LIBS="-Wl,-rpath /usr/local/lib -lrelic"])

BACKUP_CFLAGS=${CFLAGS}
BACKUP_LIBS=${LIBS}

CFLAGS="${CFLAGS} ${RELIC_CFLAGS} ${GMP_CFLAGS}"
LIBS="${LIBS} ${RELIC_LIBS} ${GMP_LIBS}"

AC_TRY_LINK(
  [#include <relic.h>],
  [bn_t x; bn_null(x); bn_new(x); bn_free(x);],
  [
    AC_MSG_RESULT(found)
    AC_SUBST(RELIC_CFLAGS)
    AC_SUBST(RELIC_LIBS)
    AC_DEFINE(HAVE_RELIC,1,[Defined if RELIC is installed])
  ],
  [
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR([

The RELIC library was not found on your system! Please obtain it from

  https://github.com/relic-toolkit/relic

and install it before trying again. If librelic is already installed
in a non-standard location, try again with

  ./configure --with-relic-include=DIR --with-relic-lib=DIR

See ./configure --help for more information.
])
  ])

CFLAGS=${BACKUP_CFLAGS}
LIBS=${BACKUP_LIBS}

])

dnl Check for libbswabe and set BSWABE_CFLAGS and BSWABE_LIBS appropriately.

AC_DEFUN([BSWABE_CHECK],
[

AC_MSG_CHECKING(for libbswabe)

AC_ARG_WITH(
  bswabe-include,
  AC_HELP_STRING([--with-bswabe-include=DIR], [Path to BSWABE headers]),
  [BSWABE_CFLAGS="-I$withval"],
  [BSWABE_CFLAGS="-I/usr/local/include"]
)

AC_ARG_WITH(
  bswabe-lib,
  AC_HELP_STRING([--with-bswabe-lib=DIR], [Path to BSWABE libraries]),
  [BSWABE_LIBS="-L$withval -lbswabe"],
  [BSWABE_LIBS="-L/usr/local/lib -lbswabe"]
)

BACKUP_CFLAGS=${CFLAGS}
BACKUP_LIBS=${LIBS}

CFLAGS="${CFLAGS} ${BSWABE_CFLAGS}"
LIBS="${LIBS} ${BSWABE_LIBS}"

AC_TRY_LINK(
  [#include <bswabe.h>],
  [bswabe_pub_t* p = NULL; bswabe_pub_free(p);],
  [
    AC_MSG_RESULT(found)
    AC_SUBST(BSWABE_CFLAGS)
    AC_SUBST(BSWABE_LIBS)
    AC_DEFINE(HAVE_BSWABE,1,[Defined if libbswabe is installed])
  ],
  [
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR([libbswabe was not found. Please install it and try again.])
  ]
)

CFLAGS=${BACKUP_CFLAGS}
LIBS=${BACKUP_LIBS}

])
