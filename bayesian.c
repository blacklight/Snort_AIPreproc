/*
 * =====================================================================================
 *
 *       Filename:  bayesian.c
 *
 *    Description:  Module for managing bayesian not supervised correlation
 *
 *        Version:  0.1
 *        Created:  28/09/2010 19:37:08
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

#include	<math.h>
#include	<time.h>

/** \defgroup correlation Module for the correlation of hyperalerts
 * @{ */

/** Key for the bayesian correlation table */
typedef struct  {
	/** Snort ID of the first alert */
	AI_alert_event_key a;

	/** Snort ID of the second alert */
	AI_alert_event_key b;
} AI_bayesian_correlation_key;


/** Bayesian alert correlation hash table */
typedef struct  {
	/** Key for the hash table */
	AI_bayesian_correlation_key   key;

	/** Correlation value */
	double                        correlation;

	/** Timestamp of the last acquired correlation value */
	time_t                        latest_computation_time;

	/** Make the struct 'hashable' */
	UT_hash_handle                hh;
} AI_bayesian_correlation;

PRIVATE AI_bayesian_correlation  *bayesian_cache    = NULL;
PRIVATE double                   k_exp_value        = 0.0;

/**
 * \brief  Function used for computing the correlation probability A->B of two alerts (A,B) given their timestamps: f(ta, tb) = exp ( -(tb - ta)^2 / k )
 * \param  ta 	Timestamp of A
 * \param  tb 	Timestamp of B
 * \return The correlation probability A->B
 */

PRIVATE double
__AI_bayesian_correlation_function ( time_t ta, time_t tb )
{
	if ( k_exp_value == 0.0 )
		k_exp_value = - (double) (config->bayesianCorrelationInterval * config->bayesianCorrelationInterval) / log ( CUTOFF_Y_VALUE );

	return exp ( -((ta - tb) * (ta - tb)) / k_exp_value );
}		/* -----  end of function __AI_bayesian_correlation_function  ----- */

/**
 * \brief  Compute the correlation between two alerts, A -> B: p[A|B] = p[Corr(A,B)] / P[B]
 * \param  a  First alert
 * \param  b  Second alert
 * \return A real coefficient representing p[A|B] using the historical information
 */

double
AI_alert_bayesian_correlation ( const AI_snort_alert *a, const AI_snort_alert *b )
{
	double                corr         = 0.0;
	unsigned int          corr_count   = 0,
					  corr_count_a = 0;

	BOOL                         is_a_correlated = false;
	AI_bayesian_correlation_key  bayesian_key;
	AI_bayesian_correlation      *found  = NULL;

	AI_alert_event_key           key_a,
					         key_b;

	AI_alert_event               *events_a  = NULL,
					         *events_b  = NULL;

	AI_alert_event               *events_iterator_a,
					         *events_iterator_b;

	if ( !a || !b )
		return 0.0;

	key_a.gid = a->gid;
	key_a.sid = a->sid;
	key_a.rev = a->rev;

	key_b.gid = b->gid;
	key_b.sid = b->sid;
	key_b.rev = b->rev;

	/* Check if this correlation value is already in our cache */
	bayesian_key.a = key_a;
	bayesian_key.b = key_b;
	HASH_FIND ( hh, bayesian_cache, &bayesian_key, sizeof ( bayesian_key ), found );

	if ( found )
	{
		/* Ok, the abs() is not needed until the time starts running backwards, but it's better going safe... */
		if ( abs ( time ( NULL ) - found->latest_computation_time ) <= config->bayesianCorrelationCacheValidity )
			/* If our alert couple is there, just return it */
			return found->correlation;
	}

	if ( !( events_a = (AI_alert_event*) AI_get_alert_events_by_key ( key_a )) ||
			!( events_b = (AI_alert_event*) AI_get_alert_events_by_key ( key_b )))
		return 0.0;

	for ( events_iterator_a = events_a; events_iterator_a; events_iterator_a = events_iterator_a->next )
	{
		is_a_correlated = false;

		for ( events_iterator_b = events_b; events_iterator_b; events_iterator_b = events_iterator_b->next )
		{
			if ( abs ( events_iterator_a->timestamp - events_iterator_b->timestamp ) <= config->bayesianCorrelationInterval )
			{
				is_a_correlated = true;
				corr_count++;
				corr += __AI_bayesian_correlation_function ( events_iterator_a->timestamp, events_iterator_b->timestamp );
			}
		}

		if ( is_a_correlated )
			corr_count_a++;
	}

	corr /= (double) corr_count;
	corr -= ( events_a->count - corr_count_a ) / events_a->count;

	if ( found )
	{
		found->correlation = corr;
		found->latest_computation_time = time ( NULL );
	} else {
		if ( !( found = ( AI_bayesian_correlation* ) malloc ( sizeof ( AI_bayesian_correlation ))))
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

		found->key = bayesian_key;
		found->correlation = corr;
		found->latest_computation_time = time ( NULL );
	}

	return corr;
}		/* -----  end of function AI_alert_bayesian_correlation  ----- */

/** @} */

