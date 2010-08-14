#!/bin/sh

OUTDIR=${HOME}/local/snort/lib/snort_dynamicpreprocessor
LIBSF=libsf_ai_preproc

make clean
make
chmod +x ./${LIBSF}.la
cp ./${LIBSF}.la ${OUTDIR}
cp .libs/${LIBSF}.a ${OUTDIR}
cp .libs/${LIBSF}.so.0.0.0 ${OUTDIR}
cd ${OUTDIR}

if [ ! -f ${LIBSF}.so.0 ]; then
	ln -sf ${LIBSF}.so.0.0.0 ${LIBSF}.so.0
fi

if [ ! -f ${LIBSF}.so ]; then
	ln -sf ${LIBSF}.so.0.0.0 ${LIBSF}.so
fi

