## Process this file with automake for generating Makefile.in

AUTOMAKE_OPTIONS=foreign no-dependencies

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor
lib_LTLIBRARIES = libsf_ai_preproc.la
libsf_ai_preproc_la_CFLAGS   = -I./uthash -I./base64 -I./fsom -I./include ${LIBXML2_INCLUDES} ${LIBGRAPH_INCLUDES} -DDYNAMIC_PLUGIN -D_XOPEN_SOURCE -D_GNU_SOURCE -fvisibility=hidden -fno-strict-aliasing -Wall -pedantic -pedantic-errors -std=c99 -fstack-protector
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
base64/base64.c \
base64/cdecode.c \
base64/cencode.c \
bayesian.c \
cluster.c \
correlation.c \
db.c \
fkmeans/kmeans.c \
fsom/fsom.c \
geo.c \
modules.c \
mysql.c \
neural.c \
neural_cluster.c \
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

install-data-hook:
	if test ! -z "${PWD}/doc"; then \
	mkdir -p "${SHARE_PREFIX}/doc"; \
	cp -r "${PWD}/doc/"* "${SHARE_PREFIX}/doc"; \
fi
	mkdir -p "${SHARE_PREFIX}/htdocs"
	mkdir -p "${SHARE_PREFIX}/htdocs/js"
	mkdir -p "${SHARE_PREFIX}/schemas"
	mkdir -p "${SHARE_PREFIX}/corr_modules"
	cp -rf "${PWD}/corr_modules/"* "${SHARE_PREFIX}/corr_modules"
	install -m 0644 "${PWD}/htdocs/index.html" "${SHARE_PREFIX}/htdocs"
	install -m 0644 "${PWD}/htdocs/manual_correlations.dtd" "${SHARE_PREFIX}/htdocs"
	install -m 0644 "${PWD}/htdocs/neural_clusters.dtd" "${SHARE_PREFIX}/htdocs"
	install -m 0644 "${PWD}/htdocs/manual_correlations.xml" "${SHARE_PREFIX}/htdocs"
	install -m 0644 "${PWD}/htdocs/manual_uncorrelations.xml" "${SHARE_PREFIX}/htdocs"
	install -m 0755 "${PWD}/htdocs/pcap.cgi" "${SHARE_PREFIX}/htdocs"
	install -m 0755 "${PWD}/htdocs/correlate.cgi" "${SHARE_PREFIX}/htdocs"
	install -m 0755 "${PWD}/htdocs/default.xsl" "${SHARE_PREFIX}/htdocs"
	install -m 0644 "${PWD}/htdocs/js/Curry-1.0.1.js" "${SHARE_PREFIX}/htdocs/js"
	install -m 0644 "${PWD}/htdocs/js/dracula_algorithms.js" "${SHARE_PREFIX}/htdocs/js"
	install -m 0644 "${PWD}/htdocs/js/dracula_graffle.js" "${SHARE_PREFIX}/htdocs/js"
	install -m 0644 "${PWD}/htdocs/js/dracula_graph.js" "${SHARE_PREFIX}/htdocs/js"
	install -m 0644 "${PWD}/htdocs/js/raphael.js" "${SHARE_PREFIX}/htdocs/js"
	install -m 0644 "${PWD}/htdocs/js/seedrandom.js" "${SHARE_PREFIX}/htdocs/js"
	install -m 0644 "${PWD}/schemas/mysql.sql" "${SHARE_PREFIX}/schemas"
	install -m 0644 "${PWD}/schemas/postgresql.sql" "${SHARE_PREFIX}/schemas"
	install -m 0644 "${PWD}/schemas/database_ER.png" "${SHARE_PREFIX}/schemas"
