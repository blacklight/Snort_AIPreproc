#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Snort_AI_preproc], [0.1], [blacklight@autistici.org])
AM_INIT_AUTOMAKE([1.10 -Wall no-define])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT

case "$host" in
  *-openbsd2.6|*-openbsd2.5|*-openbsd2.4|*-openbsd2.3*)
    AC_DEFINE([OPENBSD],[1],[Define if OpenBSD])
    AC_DEFINE([BROKEN_SIOCGIFMTU],[1],[Define if BROKEN_SIOCGIFMTU])

    ;;
  *-openbsd*)
    AC_DEFINE([OPENBSD],[1],[Define if OpenBSD < 2.3])

    ;;
  *-sgi-irix5*)
    AC_DEFINE([IRIX],[1],[Define if Irix 5])
    no_libsocket="yes"
    no_libnsl="yes"
    if test -z "$GCC"; then
      sgi_cc="yes"
    fi
    LDFLAGS="${LDFLAGS} -L/usr/local/lib"
    extra_incl="-I/usr/local/include"
    ;;
  *-sgi-irix6*)
    AC_DEFINE([IRIX],[1],[Define if Irix 6])
    no_libsocket="yes"
    no_libnsl="yes"
    if test -z "$GCC"; then
      sgi_cc="yes"
    fi
    LDFLAGS="${LDFLAGS} -L/usr/local/lib"
    extra_incl="-I/usr/local/include"
    ;;
  *-solaris*)
    AC_DEFINE([SOLARIS],[1],[Define if Solaris])
    CPPFLAGS="${CPPFLAGS} -DBSD_COMP -D_REENTRANT"
    rt_nanosleep="yes"
    ;;
  *-sunos*)
    AC_DEFINE([SUNOS],[1],[Define if SunOS])
    sunos4="yes"
    ;;
  *-linux*)
    linux="yes"
    AC_DEFINE([LINUX],[1],[Define if Linux])
    # libpcap doesn't even LOOK at the timeout you give it under Linux
    AC_DEFINE([PCAP_TIMEOUT_IGNORED],[1],[Define if pcap timeout is ignored])
    AC_SUBST(extra_incl)
    extra_incl="-I/usr/include/pcap"
    ;;
  *-hpux10*|*-hpux11*)
    AC_DEFINE([HPUX],[1],[Define if HP-UX 10 or 11])
    AC_DEFINE([WORDS_BIGENDIAN],[1],[Define if words are big endian])
    AC_SUBST(extra_incl)
    extra_incl="-I/usr/local/include"
    ;;

  *-freebsd*)
    AC_DEFINE([FREEBSD],[1],[Define if FreeBSD])

    ;;
  *-bsdi*)
    AC_DEFINE([BSDI],[1],[Define if BSDi])
    ;;
  *-aix*)
    AC_DEFINE([AIX],[1],[Define if AIX])
    ;;
  *-osf4*)
    AC_DEFINE([OSF1],[1],[Define if OSF-4])
    ;;
  *-osf5.1*)
    AC_DEFINE([OSF1],[1],[Define if OSF-5.1])
    ;;
  *-tru64*)
    AC_DEFINE([OSF1],[1],[Define if Tru64])
    ;;
# it is actually <platform>-apple-darwin1.2 or <platform>-apple-rhapsody5.x but lets stick with this for the moment    
  *-apple*)
    AC_DEFINE([MACOS],[1],[Define if MacOS])
    AC_DEFINE([BROKEN_SIOCGIFMTU],[1],[Define if broken SIOCGIFMTU])
    LDFLAGS="${LDFLAGS} -L/sw/lib"
    extra_incl="-I/sw/include"
esac

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Check for optional features
AC_ARG_WITH(mysql,
	AS_HELP_STRING([--with-mysql],
		[Enable support for MySQL alert logs @<:@default=no@:>@]),
	[with_mysql=yes],
	[with_mysql=no])

# Checks for libraries.
AS_IF([test "x$with_mysql" != xno],
	[AC_CHECK_LIB([mysqlclient], [mysql_query],
		[AC_SUBST([MYSQL], ["-lmysqlclient"])
		AC_DEFINE(ENABLE_MYSQL, 1, [Define if you want to use MySQL])
		AC_DEFINE(ENABLE_DB, 1, [Define if you want to enable database support])
	],
	[if test "x$with_mysql" != xno; then
		AC_MSG_FAILURE([--with-mysql option used, but libmysqlclient was not found])
	fi],
	-lmysqlclient)])

#AC_CHECK_LIB([mysqlclient], [mysql_query])
AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([inttypes.h limits.h stddef.h stdlib.h string.h unistd.h wchar.h])

# Check for int types
AC_CHECK_TYPES([u_int8_t,u_int16_t,u_int32_t,u_int64_t,uint8_t,uint16_t,uint32_t,uint64_t])
AC_CHECK_TYPES([int8_t,int16_t,int32_t,int64_t])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memmove memset regcomp strcasecmp strdup strstr strtol strtoul])

AC_DEFINE([VERSION], ["0.1.0"], [Module version])
AC_DEFINE([PACKAGE], ["sf_ai_preprocessor"], [Package name])
AC_DEFINE([PACKAGE_BUGREPORT], ["blacklight@autistici.org"], [Bug report address])
AC_DEFINE([PACKAGE_NAME], ["sf_ai_preprocessor"], [Package full name])
AC_DEFINE([PACKAGE_STRING], ["Snort AI preprocessor"], [Package string])
AC_DEFINE([PACKAGE_TARNAME], ["sf_ai_preprocessor"], [Package tarname])
AC_DEFINE([PACKAGE_VERSION], ["0.1.0"], [Package version])
AC_DEFINE([SUP_IP6], [], [Use SUP_IP6])

AC_DEFINE([HAVE_VISIBILITY], [1], [Check if the compiler supports visibility])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

