## Process this file with automake for generating Makefile.in

AUTOMAKE_OPTIONS=foreign no-dependencies

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor
lib_LTLIBRARIES = libsf_ai_preproc.la
libsf_ai_preproc_la_CFLAGS   = -I./uthash -I./include ${LIBXML2_INCLUDES} ${LIBGRAPH_INCLUDES} -DDYNAMIC_PLUGIN -D_XOPEN_SOURCE -D_GNU_SOURCE -fvisibility=hidden -fno-strict-aliasing -Wall -pedantic -pedantic-errors -std=c99 -fstack-protector
libsf_ai_preproc_la_LDFLAGS  = -module -export-dynamic

BUILT_SOURCES = \
include/sf_dynamic_preproc_lib.c \
include/sfPolicyUserData.c

nodist_libsf_ai_preproc_la_SOURCES = \
include/sf_dynamic_preproc_lib.c \
include/sfPolicyUserData.c

libsf_ai_preproc_la_SOURCES = \
alert_history.c \
alert_parser.c \
bayesian.c \
cluster.c \
correlation.c \
db.c \
mysql.c \
outdb.c \
postgresql.c \
regex.c \
spp_ai.c \
stream.c \
webserv.c

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = README INSTALL ChangeLog AUTHORS COPYING Doxyfile NEWS TODO doc etc include uthash corr_rules *.h

corr_rulesdir = ${CORR_RULES_PREFIX}
corr_rules_DATA = corr_rules/*

sharedir = ${SHARE_PREFIX}
share_DATA = README INSTALL AUTHORS COPYING NEWS TODO ChangeLog

doc:
	if test ! -z "${DOC_PREFIX}"; then \
	doxygen; \
fi

doc-install:
	if test ! -z "${DOC_PREFIX}"; then \
	mkdir -p "${DOC_PREFIX}"; \
	cp -r doc/* "${DOC_PREFIX}"; \
fi

