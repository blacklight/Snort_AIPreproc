## Process this file with automake for generating Makefile.in

AUTOMAKE_OPTIONS=foreign no-dependencies

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor
lib_LTLIBRARIES = libsf_ai_preproc.la
libsf_ai_preproc_la_CFLAGS   = -I./uthash -I./include -DDYNAMIC_PLUGIN -D_XOPEN_SOURCE -D_GNU_SOURCE -fvisibility=hidden -fno-strict-aliasing -Wall -fstack-protector
libsf_ai_preproc_la_LDFLAGS  = -module -export-dynamic

BUILT_SOURCES = \
include/sf_dynamic_preproc_lib.c \
include/sfPolicyUserData.c

nodist_libsf_ai_preproc_la_SOURCES = \
include/sf_dynamic_preproc_lib.c \
include/sfPolicyUserData.c

libsf_ai_preproc_la_SOURCES = \
alert_parser.c \
cluster.c \
db.c \
mysql.c \
regex.c \
spp_ai.c \
stream.c

ACLOCAL_AMFLAGS = -I m4

