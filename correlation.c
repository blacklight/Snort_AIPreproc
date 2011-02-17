/*
 * =====================================================================================
 *
 *       Filename:  correlation.c
 *
 *    Description:  Runs the correlation algorithm of the alerts
 *
 *        Version:  0.1
 *        Created:  07/09/2010 22:04:27
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

#include	<alloca.h>
#include	<math.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<time.h>

#ifdef 	HAVE_LIBGVC
	#include	<gvc.h>
#endif

#ifdef HAVE_LIBPYTHON2_6
/*******************************************/
/* Avoid conflicts with Snort header files */
#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#ifdef _XOPEN_C_SOURCE
#undef _XOPEN_C_SOURCE
#endif

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#endif
/*******************************************/

#include	<Python.h>
#endif

/** \defgroup correlation Module for the correlation of security alerts
 * @{ */

PRIVATE AI_snort_alert           *alerts                = NULL;
PRIVATE AI_alert_correlation     *correlation_table     = NULL;
PRIVATE pthread_mutex_t          mutex;

/**
 * \brief  Clean up the correlation hash table
 */

PRIVATE void
__AI_correlation_table_cleanup ()
{
	AI_alert_correlation *current;

	while ( correlation_table )
	{
		current = correlation_table;
		HASH_DEL ( correlation_table, current );
		free ( current );
	}
}		/* -----  end of function __AI_correlation_table_cleanup  ----- */

/**
 * \brief  Recursively write a flow of correlated alerts to a .dot file, ready for being rendered as graph
 * \param  corr 	Correlated alerts
 * \param  fp       File pointer
 */

PRIVATE void
__AI_correlated_alerts_to_dot ( AI_alert_correlation *corr, FILE *fp )
{
	char  src_addr1[INET_ADDRSTRLEN],
		 dst_addr1[INET_ADDRSTRLEN],
		 src_addr2[INET_ADDRSTRLEN],
		 dst_addr2[INET_ADDRSTRLEN],
		 src_port1[10],
		 dst_port1[10],
		 src_port2[10],
		 dst_port2[10];

	char *time1 = NULL,
		*time2 = NULL;

	if ( !corr )
		return;

	inet_ntop ( AF_INET, &(corr->key.a->ip_src_addr), src_addr1, INET_ADDRSTRLEN );
	inet_ntop ( AF_INET, &(corr->key.a->ip_dst_addr), dst_addr1, INET_ADDRSTRLEN );

	snprintf ( src_port1, sizeof ( src_port1 ), "%d", ntohs ( corr->key.a->tcp_src_port ));
	snprintf ( dst_port1, sizeof ( dst_port1 ), "%d", ntohs ( corr->key.a->tcp_dst_port ));

	inet_ntop ( AF_INET, &(corr->key.b->ip_src_addr), src_addr2, INET_ADDRSTRLEN );
	inet_ntop ( AF_INET, &(corr->key.b->ip_dst_addr), dst_addr2, INET_ADDRSTRLEN );

	snprintf ( src_port2, sizeof ( src_port2 ), "%d", ntohs ( corr->key.b->tcp_src_port ));
	snprintf ( dst_port2, sizeof ( dst_port2 ), "%d", ntohs ( corr->key.b->tcp_dst_port ));

	time1 = strdup ( ctime ( &(corr->key.a->timestamp )) );
	time2 = strdup ( ctime ( &(corr->key.b->timestamp )) );
	time1[strlen(time1)-1] = 0;
	time2[strlen(time2)-1] = 0;

	fprintf ( fp,
		"\t\"[%d.%d.%d] %s\\n"
		"%s:%s -> %s:%s\\n"
		"starting from %s\n"
		"(%d alerts grouped)\" -> "

		"\"[%d.%d.%d] %s\\n"
		"%s:%s -> %s:%s\\n"
		"starting from %s\n"
		"(%d alerts grouped)\";\n",

		corr->key.a->gid, corr->key.a->sid, corr->key.a->rev, corr->key.a->desc,
		src_addr1, src_port1, dst_addr1, dst_port1,
		time1,
		corr->key.a->grouped_alerts_count,

		corr->key.b->gid, corr->key.b->sid, corr->key.b->rev, corr->key.b->desc,
		src_addr2, src_port2, dst_addr2, dst_port2,
		time2,
		corr->key.b->grouped_alerts_count
	);
}		/* -----  end of function __AI_correlated_alerts_to_dot  ----- */

/**
 * \brief  Recursively write the flow of correlated alerts to a .json file, ready for being rendered in the web interface
 */

PRIVATE void
__AI_correlated_alerts_to_json ()
{
	AI_snort_alert  *alert_iterator = NULL;
	struct pkt_info *pkt_iterator   = NULL;
	FILE *fp;

	unsigned int i = 0,
			   pkt_len = 0;

	char *strtime = NULL,
		*encoded_pkt = NULL,
		json_file[1040] = { 0 },
		srcip[INET_ADDRSTRLEN] = { 0 },
		dstip[INET_ADDRSTRLEN] = { 0 },
		srcport[10] = { 0 },
		dstport[10] = { 0 };

	/* If there is no directory configured for the web interface, just exit */
	if ( strlen ( config->webserv_dir ) == 0 )
		return;

	snprintf ( json_file, sizeof ( json_file ), "%s/correlation_graph.json", config->webserv_dir );

	if ( !( fp = fopen ( json_file, "w" )))
	{
		AI_fatal_err ( "Unable to write on correlated_graph.json in htdocs directory", __FILE__, __LINE__ );
	}

	fprintf ( fp, "[\n" );

	for ( alert_iterator = alerts; alert_iterator; alert_iterator = alert_iterator->next )
	{
		strtime = ctime ( &(alert_iterator->timestamp ));
		strtime[ strlen(strtime) - 1 ] = 0;
		inet_ntop ( AF_INET, &(alert_iterator->ip_src_addr), srcip, INET_ADDRSTRLEN );
		inet_ntop ( AF_INET, &(alert_iterator->ip_dst_addr), dstip, INET_ADDRSTRLEN );
		snprintf ( srcport, sizeof ( srcport ), "%d", htons ( alert_iterator->tcp_src_port ));
		snprintf ( dstport, sizeof ( dstport ), "%d", htons ( alert_iterator->tcp_dst_port ));

		fprintf ( fp, "{\n"
			"\t\"id\": %lu,\n"
			"\t\"snortSID\": \"%u\",\n"
			"\t\"snortGID\": \"%u\",\n"
			"\t\"snortREV\": \"%u\",\n"
			"\t\"label\": \"%s\",\n"
			"\t\"date\": \"%s\",\n"
			"\t\"clusteredAlertsCount\": %u,\n"
			"\t\"from\": \"%s:%s\",\n"
			"\t\"to\": \"%s:%s\",\n"
			"\t\"latitude\": \"%f\",\n"
			"\t\"longitude\": \"%f\"",
			alert_iterator->alert_id,
			alert_iterator->sid,
			alert_iterator->gid,
			alert_iterator->rev,
			alert_iterator->desc,
			strtime,
			alert_iterator->grouped_alerts_count,
			srcip, srcport, dstip, dstport,
			alert_iterator->geocoord[0],
			alert_iterator->geocoord[1]
		);

		if ( alert_iterator->stream )
		{
			fprintf ( fp, ",\n"
					"\t\"packets\": [\n" );

			for ( pkt_iterator = alert_iterator->stream; pkt_iterator; pkt_iterator = pkt_iterator->next )
			{
				encoded_pkt = NULL;
				pkt_len = pkt_iterator->pkt->pcap_header->len + pkt_iterator->pkt->payload_size;

				if ( !( encoded_pkt = (char*) calloc ( 4*pkt_len + 1, sizeof ( char ))))
				{
					AI_fatal_err ( "Fatal dynamic memory allocation", __FILE__, __LINE__ );
				}

				base64_encode (
					(const char*) pkt_iterator->pkt->pkt_data,
					pkt_len,
					&encoded_pkt
				);

				fprintf ( fp, "\t\t\"%s\"%s\n",
						encoded_pkt, ((pkt_iterator->next) ? "," : ""));

				free ( encoded_pkt );
				encoded_pkt = NULL;
			}

			fprintf ( fp, "\t]" );
		}

		for ( i=1; i < alert_iterator->grouped_alerts_count; i++ )
		{
			if ( i == 1 )
			{
				fprintf ( fp, ",\n\t\"clusteredAlerts\": [\n" );
			}

			if ( alert_iterator->grouped_alerts )
			{
				if ( alert_iterator->grouped_alerts[i] )
				{
					strtime = ctime ( &(alert_iterator->grouped_alerts[i]->timestamp ));
					strtime[ strlen ( strtime ) - 1 ] = 0;
					inet_ntop ( AF_INET, &(alert_iterator->grouped_alerts[i]->ip_src_addr), srcip, INET_ADDRSTRLEN );
					inet_ntop ( AF_INET, &(alert_iterator->grouped_alerts[i]->ip_dst_addr), dstip, INET_ADDRSTRLEN );
					snprintf ( srcport, sizeof ( srcport ), "%d", htons ( alert_iterator->grouped_alerts[i]->tcp_src_port ));
					snprintf ( dstport, sizeof ( dstport ), "%d", htons ( alert_iterator->grouped_alerts[i]->tcp_dst_port ));

					fprintf ( fp, "\t\t{\n"
						"\t\t\t\"id\": %lu,\n"
						"\t\t\t\"label\": \"%s\",\n"
						"\t\t\t\"date\": \"%s\",\n"
						"\t\t\t\"from\": \"%s:%s\",\n"
						"\t\t\t\"to\": \"%s:%s\",\n"
						"\t\t\t\"latitude\": \"%f\",\n"
						"\t\t\t\"longitude\": \"%f\"%s",
						alert_iterator->grouped_alerts[i]->alert_id,
						alert_iterator->grouped_alerts[i]->desc,
						strtime,
						srcip, srcport, dstip, dstport,
						alert_iterator->grouped_alerts[i]->geocoord[0],
						alert_iterator->grouped_alerts[i]->geocoord[1],
						(( alert_iterator->grouped_alerts[i]->stream ) ? ",\n" : "\n" )
					);

					if ( alert_iterator->grouped_alerts[i]->stream )
					{
						fprintf ( fp, "\t\t\t\"packets\": [\n" );

						for ( pkt_iterator = alert_iterator->grouped_alerts[i]->stream; pkt_iterator; pkt_iterator = pkt_iterator->next )
						{
							if ( !pkt_iterator->pkt->ip4_header )
							{
								pkt_len = pkt_iterator->pkt->pcap_header->len +
									pkt_iterator->pkt->tcp_options_length +
									pkt_iterator->pkt->payload_size;
							} else {
								pkt_len = pkt_iterator->pkt->ip4_header->data_length;
							}

							if ( !( encoded_pkt = (char*) malloc ( 4*pkt_len + 1 )))
							{
								AI_fatal_err ( "Fatal dynamic memory allocation", __FILE__, __LINE__ );
							}

							memset ( encoded_pkt, 0, 4*pkt_len + 1  );

							base64_encode (
								(const char*) pkt_iterator->pkt->pkt_data,
								pkt_len,
								&encoded_pkt
							);

							fprintf ( fp, "\t\t\t\t\"%s\"%s\n",
									encoded_pkt, ((pkt_iterator->next) ? "," : ""));
						}

						fprintf ( fp, "\t\t\t]\n" );
					}

					fprintf ( fp,
						"\t\t}%s\n",
						(( i < alert_iterator->grouped_alerts_count - 1 ) ? "," : "" ));
				}
			}

			if ( i == alert_iterator->grouped_alerts_count - 1 )
			{
				fprintf ( fp, "\t]" );
			}
		}

		for ( i=0; i < alert_iterator->n_derived_alerts; i++ )
		{
			if ( i == 0 )
			{
				fprintf ( fp, ",\n\t\"connectedTo\": [\n" );
			}

			fprintf ( fp, "\t\t{ \"id\": %lu }%s\n",
				alert_iterator->derived_alerts[i]->alert_id,
				((i < alert_iterator->n_derived_alerts - 1) ? "," : ""));

			if ( i == alert_iterator->n_derived_alerts - 1 )
			{
				fprintf ( fp, "\t]" );
			}
		}

		fprintf ( fp, "\n}%s\n",
			(alert_iterator->next ? "," : ""));
	}

	fprintf ( fp, "]\n" );
	fclose ( fp );
	chmod ( json_file, 0644 );
}		/* -----  end of function __AI_correlated_alerts_to_json  ----- */

/**
 * \brief  Thread for correlating clustered alerts
 */

void*
AI_alert_correlation_thread ( void *arg )
{
	int                       i;
	struct stat               st;

	char                      corr_dot_file[4096]   = { 0 };

#ifdef HAVE_LIBGVC
	char                      corr_ps_file [4096]   = { 0 };
#endif

	double                    avg_correlation       = 0.0,
						 std_deviation         = 0.0,
						 corr_threshold        = 0.0,
						 kb_correlation        = 0.0,
						 bayesian_correlation  = 0.0,
						 neural_correlation    = 0.0;

	size_t                    n_correlations        = 0,
						 n_corr_functions      = 0,
						 n_corr_weights        = 0;

	FILE                      *fp                   = NULL;

	AI_alert_correlation_key  corr_key;
	AI_alert_correlation      *corr                 = NULL;

	AI_alert_type_pair_key    pair_key;
	AI_alert_type_pair        *pair                 = NULL,
						 *unpair               = NULL;

	AI_snort_alert            *alert_iterator       = NULL,
					      *alert_iterator2      = NULL;

	pthread_t                 manual_corr_thread;

	#ifdef                    HAVE_LIBGVC
	char                      corr_png_file[4096]   = { 0 };
	GVC_t                     *gvc                  = NULL;
	graph_t                   *g                    = NULL;
	#endif

	double (**corr_functions)( const AI_snort_alert*, const AI_snort_alert* ) = NULL;
	double (**corr_weights)() = NULL;

	#ifdef HAVE_LIBPYTHON2_6
	PyObject *pyA = NULL,
		    *pyB = NULL;

	PyObject *pArgs = NULL,
		    *pRet  = NULL;

	PyObject **py_corr_functions   = NULL;
	PyObject **py_weight_functions = NULL;

	size_t   n_py_corr_functions   = 0;
	size_t   n_py_weight_functions = 0;

	double   py_value  = 0.0,
		    py_weight = 0.0;

	py_corr_functions = AI_get_py_functions ( &n_py_corr_functions );
	py_weight_functions = AI_get_py_weights ( &n_py_weight_functions );
	#endif

	corr_functions = AI_get_corr_functions ( &n_corr_functions );
	corr_weights   = AI_get_corr_weights ( &n_corr_weights );

	pthread_mutex_init ( &mutex, NULL );

	/* Start the thread for parsing manual correlations from XML */
	if ( pthread_create ( &manual_corr_thread, NULL, AI_manual_correlations_parsing_thread, NULL ) != 0 )
	{
		AI_fatal_err ( "Failed to create the manual correlations parsing thread", __FILE__, __LINE__ );
	}

	while ( 1 )
	{
		sleep ( config->correlationGraphInterval );

		if ( stat ( config->corr_rules_dir, &st ) < 0 )
		{
			_dpd.errMsg ( "AIPreproc: Correlation rules directory '%s' not found, the correlation thread won't be active\n",
					config->corr_rules_dir );
			pthread_exit (( void* ) 0 );
			return ( void* ) 0;
		}

		/* Set the lock flag to true, and keep it this way until I've done with correlating alerts */
		pthread_mutex_lock ( &mutex );

		if ( alerts )
		{
			AI_free_alerts ( alerts );
			alerts = NULL;
		}

		if ( !( alerts = AI_get_clustered_alerts() ))
		{
			pthread_mutex_unlock ( &mutex );
			continue;
		}

		if ( config->use_knowledge_base_correlation_index != 0 )
		{
			AI_kb_index_init ( alerts );
		}

		__AI_correlation_table_cleanup();
		correlation_table = NULL;

		/* Fill the table of correlated alerts */
		for ( alert_iterator = alerts; alert_iterator; alert_iterator = alert_iterator->next )
		{
			for ( alert_iterator2 = alerts; alert_iterator2; alert_iterator2 = alert_iterator2->next )
			{
				if ( alert_iterator != alert_iterator2 && ! (
					alert_iterator->gid == alert_iterator2->gid &&
					alert_iterator->sid == alert_iterator2->sid &&
					alert_iterator->rev == alert_iterator2->rev ))
				{
					if ( !( corr = ( AI_alert_correlation* ) malloc ( sizeof ( AI_alert_correlation ))))
						AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

					corr_key.a = alert_iterator;
					corr_key.b = alert_iterator2;
					corr->key  = corr_key;
					corr->correlation = 0.0;
					n_correlations = 0;

					kb_correlation = AI_kb_correlation_coefficient ( corr_key.a, corr_key.b );
					bayesian_correlation = AI_alert_bayesian_correlation ( corr_key.a, corr_key.b );
					neural_correlation = AI_alert_neural_som_correlation ( corr_key.a, corr_key.b );

					/* Use the correlation indexes for which we have a value */
					if ( bayesian_correlation != 0.0 && config->bayesianCorrelationInterval != 0 )
					{
						corr->correlation += AI_bayesian_correlation_weight() * bayesian_correlation;
						n_correlations++;
					}

					if ( kb_correlation != 0.0 && config->use_knowledge_base_correlation_index )
					{
						corr->correlation += kb_correlation;
						n_correlations++;
					}

					if ( neural_correlation != 0.0 && config->neuralNetworkTrainingInterval != 0 )
					{
						corr->correlation += AI_neural_correlation_weight() * neural_correlation;
						n_correlations++;
					}

					/* Get the correlation indexes from extra correlation modules */
					if (( corr_functions ))
					{
						for ( i=0; i < n_corr_functions; i++ )
						{
							if ( corr_weights[i]() != 0.0 )
							{
								corr->correlation += corr_weights[i]() * corr_functions[i] ( corr_key.a, corr_key.b );
								n_correlations++;
							}
						}
					}

					#ifdef HAVE_LIBPYTHON2_6
					if (( py_corr_functions ))
					{
						pyA = AI_alert_to_pyalert ( corr_key.a );
						pyB = AI_alert_to_pyalert ( corr_key.b );

						if ( pyA && pyB )
						{
							for ( i=0; i < n_py_corr_functions; i++ )
							{
								if ( !( pArgs = Py_BuildValue ( "(OO)", pyA, pyB )))
								{
									PyErr_Print();
									AI_fatal_err ( "Could not initialize the Python arguments for the call", __FILE__, __LINE__ );
								}

								if ( !( pRet = PyEval_CallObject ( py_corr_functions[i], pArgs )))
								{
									PyErr_Print();
									AI_fatal_err ( "Could not call the correlation function from the Python module", __FILE__, __LINE__ );
								}

								if ( !( PyArg_Parse ( pRet, "d", &py_value )))
								{
									PyErr_Print();
									AI_fatal_err ( "Could not parse the correlation value out of the Python correlation function", __FILE__, __LINE__ );
								}

								Py_DECREF ( pRet );
								Py_DECREF ( pArgs );

								if ( !( pRet = PyEval_CallObject ( py_weight_functions[i], (PyObject*) NULL )))
								{
									PyErr_Print();
									AI_fatal_err ( "Could not call the correlation function from the Python module", __FILE__, __LINE__ );
								}

								if ( !( PyArg_Parse ( pRet, "d", &py_weight )))
								{
									PyErr_Print();
									AI_fatal_err ( "Could not parse the correlation weight out of the Python correlation function", __FILE__, __LINE__ );
								}

								Py_DECREF ( pRet );

								if ( py_weight != 0.0 )
								{
									corr->correlation += py_weight * py_value;
									n_correlations++;
								}
							}

							Py_DECREF ( pyA ); Py_DECREF ( pyB );
							/* free ( pyA ); free ( pyB ); */
							pyA = NULL; pyB = NULL;
						}
					}
					#endif

					if ( n_correlations != 0 )
					{
						corr->correlation /= (double) n_correlations;
					}

					HASH_ADD ( hh, correlation_table, key, sizeof ( AI_alert_correlation_key ), corr );
				}
			}
		}

		if ( HASH_COUNT ( correlation_table ) > 0 )
		{
			avg_correlation = 0.0;
			std_deviation   = 0.0;

			/* Compute the average correlation coefficient */
			for ( corr = correlation_table; corr; corr = ( AI_alert_correlation* ) corr->hh.next )
			{
				avg_correlation += corr->correlation;
			}

			avg_correlation /= (double) HASH_COUNT ( correlation_table );

			/* Compute the standard deviation */
			for ( corr = correlation_table; corr; corr = ( AI_alert_correlation* ) corr->hh.next )
			{
				std_deviation += ( corr->correlation - avg_correlation ) * ( corr->correlation - avg_correlation );
			}

			std_deviation = sqrt ( std_deviation / (double) HASH_COUNT ( correlation_table ));
			corr_threshold = avg_correlation + ( config->correlationThresholdCoefficient * std_deviation );
			snprintf ( corr_dot_file, sizeof ( corr_dot_file ), "%s/correlated_alerts.dot", config->corr_alerts_dir );
			
			if ( stat ( config->corr_alerts_dir, &st ) < 0 )
			{
				if ( mkdir ( config->corr_alerts_dir, 0755 ) < 0 )
				{
					AI_fatal_err ( "Unable to create directory the correlated alerts directory", __FILE__, __LINE__ );
				}
			} else if ( !S_ISDIR ( st.st_mode )) {
				AI_fatal_err ( "The specified directory for correlated alerts is not a directory", __FILE__, __LINE__ );
			}

			if ( !( fp = fopen ( corr_dot_file, "w" )))
				AI_fatal_err ( "Could not write on the correlated alerts .dot file", __FILE__, __LINE__ );
			fprintf ( fp, "digraph G  {\n" );

			/* Find correlated alerts */
			for ( corr = correlation_table; corr; corr = ( AI_alert_correlation* ) corr->hh.next )
			{
				pair_key.from_sid = corr->key.a->sid;
				pair_key.from_gid = corr->key.a->gid;
				pair_key.from_rev = corr->key.a->rev;
				pair_key.to_sid = corr->key.b->sid;
				pair_key.to_gid = corr->key.b->gid;
				pair_key.to_rev = corr->key.b->rev;

				HASH_FIND ( hh, manual_correlations, &pair_key, sizeof ( pair_key ), pair );
				HASH_FIND ( hh, manual_uncorrelations, &pair_key, sizeof ( pair_key ), unpair );

				/* Yes, BlackLight wrote this line of code in a pair of minutes and immediately
				 * compiled it without a single error */
				if ( !unpair && ( pair || (
						corr->correlation >= corr_threshold &&
						corr_threshold != 0.0 &&
						corr->key.a->timestamp <= corr->key.b->timestamp && ! (
						corr->key.a->gid == corr->key.b->gid &&
						corr->key.a->sid == corr->key.b->sid &&
						corr->key.a->rev == corr->key.b->rev ) && (
							corr->key.a->ip_src_addr == corr->key.b->ip_src_addr || (
								(corr->key.a->h_node[src_addr] && corr->key.b->h_node[src_addr]) ?
									( corr->key.a->h_node[src_addr]->max_val == corr->key.b->h_node[src_addr]->max_val &&
									corr->key.a->h_node[src_addr]->min_val == corr->key.b->h_node[src_addr]->min_val ) : 0
							)) && (
							corr->key.a->ip_dst_addr == corr->key.b->ip_dst_addr || (
								(corr->key.a->h_node[dst_addr] && corr->key.b->h_node[dst_addr]) ?
									( corr->key.a->h_node[dst_addr]->max_val == corr->key.b->h_node[dst_addr]->max_val &&
									corr->key.a->h_node[dst_addr]->min_val == corr->key.b->h_node[dst_addr]->min_val ) : 0
							))
						)
					)
				)  {
					if ( !( corr->key.a->derived_alerts = ( AI_snort_alert** ) realloc ( corr->key.a->derived_alerts,
									(++corr->key.a->n_derived_alerts) * sizeof ( AI_snort_alert* ))))
						AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

					if ( !( corr->key.b->parent_alerts = ( AI_snort_alert** ) realloc ( corr->key.b->parent_alerts,
									(++corr->key.b->n_parent_alerts) * sizeof ( AI_snort_alert* ))))
						AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

					corr->key.a->derived_alerts[ corr->key.a->n_derived_alerts - 1 ] = corr->key.b;
					corr->key.b->parent_alerts [ corr->key.b->n_parent_alerts  - 1 ] = corr->key.a;
					__AI_correlated_alerts_to_dot ( corr, fp );

					if ( config->outdbtype != outdb_none )
					{
						AI_store_correlation_to_db ( corr );
					}
				}
			}

			fprintf ( fp, "}\n" );
			fclose ( fp );

			#ifdef HAVE_LIBGVC
				snprintf ( corr_png_file, sizeof ( corr_png_file ), "%s/correlated_alerts.png", config->corr_alerts_dir );
				snprintf ( corr_ps_file , sizeof ( corr_ps_file  ), "%s/correlated_alerts.ps" , config->corr_alerts_dir );

				if ( !( gvc = gvContext() ))
				{
					pthread_mutex_unlock ( &mutex );
					continue;
				}

				if ( !( fp = fopen ( corr_dot_file, "r" )))
				{
					pthread_mutex_unlock ( &mutex );
					continue;
				}

				if ( !( g = agread ( fp )))
				{
					pthread_mutex_unlock ( &mutex );
					continue;
				}

				gvLayout ( gvc, g, "dot" );
				gvRenderFilename ( gvc, g, "png", corr_png_file );
				gvRenderFilename ( gvc, g, "ps" , corr_ps_file  );

				gvFreeLayout ( gvc, g );
				agclose ( g );
				fclose ( fp );
			#endif

			/* If no database output is defined, then the alerts have no alert_id, so we cannot use the
			 * web interface for correlating them, as they have no unique identifier */
			if ( config->outdbtype != outdb_none )
			{
				if ( strlen ( config->webserv_dir ) != 0 )
				{
					__AI_correlated_alerts_to_json ();
				}
			}
		}

		pthread_mutex_unlock ( &mutex );
	}

	pthread_exit (( void* ) 0 );
	return (void*) 0;
}		/* -----  end of function AI_alert_correlation_thread  ----- */

/** @} */

