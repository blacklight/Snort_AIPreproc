#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([Snort_AI_preproc], [0.1], [blacklight@autistici.org])
AM_INIT_AUTOMAKE([1.10 -Wall no-define])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT

AC_PREFIX_DEFAULT(/usr)
test "$prefix" = "NONE" && prefix=/usr

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
	# Use Fink.
	if test -f "/sw/etc/fink.conf"; then
		LDFLAGS="${LDFLAGS} -L/sw/lib"
    	extra_incl="-I/sw/include"
	# Use MacPorts
	else
		LDFLAGS="${LDFLAGS} -L/opt/local/lib"
    	extra_incl="-I/opt/local/include"
	fi
    AC_DEFINE([MACOS],[1],[Define if MacOS])
    AC_DEFINE([BROKEN_SIOCGIFMTU],[1],[Define if broken SIOCGIFMTU])
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

AC_ARG_WITH(graphviz,
	AS_HELP_STRING([--without-graphviz],
		[Disable Graphviz support for rendering correlated alerts as a PNG graph @<:@default=yes@:>@]),
	[],
	[with_graphviz=yes])

# Checks for libraries.
AS_IF([test "x$with_mysql" != xno],
	[AC_CHECK_LIB([mysqlclient], [mysql_query],,
		[AC_MSG_FAILURE([--with-mysql option used, but libmysqlclient was not found - do not use --with-mysql, or, on a Debian-based system, install libmysqlclient-dev])])])

AS_IF([test "x$with_graphviz" != xno],
	[AC_CHECK_LIB([gvc], [agread],,
	[AC_MSG_FAILURE([libgraphviz support required but the library was not found - use --without-graphviz if you do not want to enable the support for it, or, on a Debian-based system, install libgraphviz-dev])])])

AC_CHECK_LIB([xml2], [xmlReaderForFile],, AC_MSG_FAILURE(libxml2 not found on the system))
AC_CHECK_LIB([pthread], [pthread_create],, AC_MSG_FAILURE(libpthread not found on the system))
AC_CHECK_LIB([m], [sqrt],, AC_MSG_FAILURE(libm not found on the system))

AS_IF([test "x$prefix" == x/usr],
	[AC_SUBST([CORR_RULES_PREFIX], ["/etc/snort/corr_rules"])],
	[AC_SUBST([CORR_RULES_PREFIX], ["${prefix}/etc/corr_rules"])])

AC_SUBST([DOC_PREFIX], ["${prefix}/doc/snort_ai_preprocessor"])
AC_SUBST([SHARE_PREFIX], ["${prefix}/share/snort_ai_preprocessor"])

# Checks for header files.

AS_IF([test ! -z "`pkg-config --cflags libxml-2.0 2> /dev/null`"],
	[AC_SUBST([LIBXML2_INCLUDES], ["$(pkg-config --cflags libxml-2.0 2> /dev/null)"])],
	[AC_MSG_FAILURE([libxml2 not found, okr pkg-config not working])])

AS_IF([test "x$with_graphviz" != xno],
	[AS_IF([test ! -z "`pkg-config --cflags libgraph 2> /dev/null`"],
		[AC_SUBST([LIBGRAPH_INCLUDES], ["$(pkg-config --cflags libgraph 2> /dev/null)"])],
		[AC_MSG_FAILURE([libgraphviz support enabled, but the library was not found or pkg-config is not working])])])

AS_IF([test "x$with_graphviz" != xno],
	[AC_DEFINE([HAVE_BOOLEAN], [1], [Check if the boolean type is defined])])

AC_FUNC_ALLOCA
AC_CHECK_HEADERS([inttypes.h limits.h stddef.h stdlib.h string.h unistd.h wchar.h math.h],,AC_MSG_ERROR(At least one of the required headers was not found))

# Check for int types
AC_CHECK_TYPES([u_int8_t,u_int16_t,u_int32_t,u_int64_t,uint8_t,uint16_t,uint32_t,uint64_t])
AC_CHECK_TYPES([int8_t,int16_t,int32_t,int64_t,boolean])

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
AC_CHECK_FUNCS([memmove memset regcomp strcasecmp strdup strstr strtol strtoul],,AC_MSG_ERROR(At least one of the required functions was not found))

AC_DEFINE([VERSION], ["0.1.0"], [Module version])
AC_DEFINE([PACKAGE], ["sf_ai_preprocessor"], [Package name])
AC_DEFINE([PACKAGE_BUGREPORT], ["blacklight@autistici.org"], [Bug report address])
AC_DEFINE([PACKAGE_NAME], ["sf_ai_preprocessor"], [Package full name])
AC_DEFINE([PACKAGE_STRING], ["Snort AI preprocessor"], [Package string])
AC_DEFINE([PACKAGE_TARNAME], ["snort_ai_preproc"], [Package tarname])
AC_DEFINE([PACKAGE_VERSION], ["0.1.0"], [Package version])
AC_DEFINE([SUP_IP6], [], [Use SUP_IP6])

AC_DEFINE([HAVE_VISIBILITY], [1], [Check if the compiler supports visibility])
AC_DEFINE_UNQUOTED([PREFIX], "${prefix}", [Installation prefix])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

