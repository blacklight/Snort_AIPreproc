/*
 * =====================================================================================
 *
 *       Filename:  libsf_ai_corr_example.c
 *
 *    Description:  Sample correlation module for two alerts
 *
 *        Version:  0.1
 *        Created:  26/10/2010 14:23:24
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#include	"spp_ai.h"

/** Function that, given two alerts, returns a correlation index in [0,1] */

double
AI_corr_index ( const AI_snort_alert *a, const AI_snort_alert *b )
{
	return 0.5;
}

/** Function that returns the weight of this index */

double
AI_corr_index_weight ()
{
	return 0.0;
}

