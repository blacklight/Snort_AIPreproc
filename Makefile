# Path to your Snort preprocess directory (default: /usr/lib/snort_dynamicpreprocessor)
# CHANGE THIS LINE IF YOU INSTALLED SNORT SOMEWHERE ELSE!!!!!!!!!!
PREPROC_PATH=/home/blacklight/local/snort/lib/snort_dynamicpreprocessor

INCLUDES=-I. -I../../.. -I../include -I./uthash
DEFINES=-D_GNU_SOURCE -D_XOPEN_SOURCE -DDYNAMIC_PLUGIN -DSUP_IP6 -DENABLE_MYSQL -DHAVE_CONFIG_H
CMDLINE=-g -O2 -fvisibility=hidden -fno-strict-aliasing -Wall -fstack-protector
LIBPATH=-L/usr/lib
LDLINKS=-lpthread
LIBTOOL=./libtool --tag=CC 
OUTPUT=libsf_ai_preproc.la
LDOPTIONS=-export-dynamic -rpath ${PREPROC_PATH}

OBJECTS=\
sf_dynamic_preproc_lib.lo \
sfPolicyUserData.lo \
spp_ai.lo \
stream.lo \
alert_parser.lo \
regex.lo \
cluster.lo

all:
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o sf_dynamic_preproc_lib.lo sf_dynamic_preproc_lib.c
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o sfPolicyUserData.lo sfPolicyUserData.c
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o alert_parser.lo alert_parser.c
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o regex.lo regex.c
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o stream.lo stream.c
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o spp_ai.lo spp_ai.c
	/bin/sh ${LIBTOOL} --mode=compile gcc ${CMDLINE} ${INCLUDES} ${DEFINES} -c -o cluster.lo cluster.c
	/bin/sh ${LIBTOOL} --mode=link gcc ${CMDLINE} ${LDOPTIONS} ${LIBPATH} -o ${OUTPUT} ${OBJECTS} ${LDLINKS}

clean:
	rm -rf .libs _libs
	test -z "${OUTPUT}" || rm -f ${OUTPUT}
	rm -f "./so_locations"
	rm -f *.o
	rm -f *.lo

