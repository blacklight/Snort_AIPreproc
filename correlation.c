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
#include	<libxml/xmlreader.h>
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

/** \defgroup correlation Module for the correlation of hyperalerts
 * @{ */

#ifndef 	LIBXML_READER_ENABLED
#error 	"libxml2 reader not enabled\n"
#endif

/** Enumeration for the types of hyperalert XML tags */
enum  { inHyperAlert, inSnortIdTag, inPreTag, inPostTag, HYP_TAG_NUM };

/** Enumeration for the types of manual correlations XML tags */
enum  { inCorrelation, inCorrelations, inFromTag, inToTag, MAN_TAG_NUM };

typedef struct  {
	int from_gid;
	int from_sid;
	int from_rev;
	int to_gid;
	int to_sid;
	int to_rev;
} AI_alert_type_pair_key;

typedef struct  {
	AI_alert_type_pair_key   key;
	enum  { manuallyNone, manuallyCorrelated, manuallyNotCorrelated } corr_type;
	UT_hash_handle             hh;
} AI_alert_type_pair;

PRIVATE AI_hyperalert_info       *hyperalerts           = NULL;
PRIVATE AI_snort_alert           *alerts                = NULL;
PRIVATE AI_alert_correlation     *correlation_table     = NULL;
PRIVATE AI_alert_type_pair       *manual_correlations   = NULL;
PRIVATE AI_alert_type_pair       *manual_uncorrelations = NULL;
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

	fprintf ( fp,
		"\t\"[%d.%d.%d] %s\\n"
		"%s:%s -> %s:%s\\n"
		"(%d alerts grouped)\" -> "

		"\"[%d.%d.%d] %s\\n"
		"%s:%s -> %s:%s\\n"
		"(%d alerts grouped)\";\n",

		corr->key.a->gid, corr->key.a->sid, corr->key.a->rev, corr->key.a->desc,
		src_addr1, src_port1, dst_addr1, dst_port1,
		corr->key.a->grouped_alerts_count,

		corr->key.b->gid, corr->key.b->sid, corr->key.b->rev, corr->key.b->desc,
		src_addr2, src_port2, dst_addr2, dst_port2,
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
			"\t\"to\": \"%s:%s\"",
			alert_iterator->alert_id,
			alert_iterator->sid,
			alert_iterator->gid,
			alert_iterator->rev,
			alert_iterator->desc,
			strtime,
			alert_iterator->grouped_alerts_count,
			srcip, srcport, dstip, dstport
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
						"\t\t\t\"to\": \"%s:%s\"%s",
						alert_iterator->grouped_alerts[i]->alert_id,
						alert_iterator->grouped_alerts[i]->desc,
						strtime,
						srcip, srcport, dstip, dstport,
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
 * \brief  Get the name of the function called by a pre-condition or post-condition predicate
 * \param  orig_stmt 	Statement representing a pre-condition or post-condition
 * \return The name of the function called by that statement
 */

PRIVATE char*
__AI_get_function_name ( const char *orig_stmt )
{
	int parenthesis_pos, function_name_len;
	char function_name[4096];
	char *stmt = NULL;

	if ( !( stmt = (char*) alloca ( strlen ( orig_stmt ))))
		return NULL;
	strcpy ( stmt, orig_stmt );

	memset ( function_name, 0, sizeof ( function_name ));

	if ( !( parenthesis_pos = (int) strstr ( stmt, "(" )))
		return NULL;

	parenthesis_pos -= (int) stmt;
	function_name_len = ( parenthesis_pos < sizeof ( function_name )) ? parenthesis_pos : sizeof ( function_name );
	strncpy ( function_name, stmt, function_name_len );

	return strdup(function_name);
}		/* -----  end of function __AI_get_function_name  ----- */


/**
 * \brief  Get the arguments passed to a function predicate in a pre-condition or post-condition (comma-separated values)
 * \param  orig_stmt 	Statement representing a pre-condition or post-condition
 * \param  n_args 		Reference to an integer that will contain the number of arguments read
 * \return An array of strings containing the arguments of the function
 */

PRIVATE char**
__AI_get_function_arguments ( char *orig_stmt, int *n_args )
{
	char **args  = NULL;
	char *tok    = NULL;
	char *stmt   = NULL;
	int  par_pos = 0;
	     *n_args = 0;

	if ( !( stmt = (char*) alloca ( strlen ( orig_stmt ))))
		return NULL;
	strcpy ( stmt, orig_stmt );

	if ( !( par_pos = (int) strstr ( stmt, "(" )))
		return NULL;
	
	par_pos -= (int) stmt;
	stmt += par_pos + 1;

	if ( stmt [ strlen(stmt) - 1 ] == ')' )
		stmt[ strlen(stmt) - 1 ] = 0;

	tok = (char*) strtok ( stmt, "," );

	while ( tok )  {
		if ( !( args = (char**) realloc ( args, (++(*n_args)) * sizeof ( char* ))))
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

		args [ (*n_args) - 1 ] = strdup ( tok );
		tok = (char*) strtok ( NULL, " " );
	}

	if ( !(*n_args) )
		return NULL;

	return args;
}		/* -----  end of function __AI_get_function_arguments  ----- */


/**
 * \brief  Compute the correlation coefficient between two alerts, as #INTERSECTION(pre(B), post(A)) / #UNION(pre(B), post(A)), on the basis of preconditions and postconditions in the knowledge base's correlation rules
 * \param  a 	Alert a
 * \param  b   Alert b
 * \return The correlation coefficient between A and B as coefficient in [0,1]
 */

PRIVATE double
__AI_kb_correlation_coefficient ( AI_snort_alert *a, AI_snort_alert *b )
{
	unsigned int i, j, k, l,
			   n_intersection = 0,
			   n_union = 0;

	char         **args1         = NULL,
			   **args2         = NULL,
			   **matches       = NULL,
			   *function_name1 = NULL,
			   *function_name2 = NULL,
			   new_stmt1[4096] = {0},
			   new_stmt2[4096] = {0};

	int          n_args1   = 0,
			   n_args2   = 0,
			   n_matches = 0,
			   min_addr  = 0,
			   max_addr  = 0,
			   ipaddr    = 0,
			   netmask   = 0;

	if ( !a->hyperalert || !b->hyperalert )
		return 0.0;

	if ( a->hyperalert->n_postconds == 0 || b->hyperalert->n_preconds == 0 )
		return 0.0;

	n_union = a->hyperalert->n_postconds + b->hyperalert->n_preconds;

	for ( i=0; i < a->hyperalert->n_postconds; i++ )
	{
		for ( j=0; j < b->hyperalert->n_preconds; j++ )
		{
			if ( !strcasecmp ( a->hyperalert->postconds[i], b->hyperalert->preconds[j] ))
			{
				n_intersection += 2;
			} else {
				/* Check if the predicates are the same, have the same number of arguments, and
				 * substitute possible occurrencies of +ANY_ADDR+ and +ANY_PORT+ or IP netmasks */
				function_name1 = __AI_get_function_name ( a->hyperalert->postconds[i] );
				function_name2 = __AI_get_function_name ( b->hyperalert->preconds[j] );

				if ( !strcasecmp ( function_name1, function_name2 ))
				{
					args1 = __AI_get_function_arguments ( a->hyperalert->postconds[i], &n_args1 );
					args2 = __AI_get_function_arguments ( b->hyperalert->preconds[j] , &n_args2 );

					if ( args1 && args2 )
					{
						if ( n_args1 == n_args2 )
						{
							memset ( new_stmt1, 0, sizeof ( new_stmt1 ));
							memset ( new_stmt2, 0, sizeof ( new_stmt2 ));

							for ( k=0; k < n_args1; k++ )
							{
								/* If any occurrence of +ANY_ADDR+ or +ANY_PORT+ is found in any of the arguments,
								 * substitute that occurrence with the associated value */
								if ( !strcasecmp ( args1[k], "+ANY_ADDR+" ) || !strcasecmp ( args1[k], "+ANY_PORT+" ))
								{
									free ( args1[k] );
									args1[k] = args2[k];
								}

								if ( !strcasecmp ( args2[k], "+ANY_ADDR+" ) || !strcasecmp ( args2[k], "+ANY_PORT+" ))
								{
									free ( args2[k] );
									args2[k] = args1[k];
								}

								/* Substitute any occurrence of an IP netmask in any of the two arguments with
								 * the associated IP value */
								if ( preg_match ( "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/([0-9]{1,2})$", args1[k], &matches, &n_matches ))
								{
									if ( preg_match ( "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", args2[k], NULL, NULL ))
									{
										if (( netmask = strtol ( matches[1], NULL, 10 )) > 32 )
											AI_fatal_err ( "Invalid IP netmask value in configuration", __FILE__, __LINE__ );

										if (( min_addr = inet_addr ( matches[0] )) == INADDR_NONE )
											AI_fatal_err ( "Invalid base IP address in configuration", __FILE__, __LINE__ );

										ipaddr = inet_addr ( args2[k] );
										
										if ( ipaddr == INADDR_NONE )
											AI_fatal_err ( "Invalid base IP address in configuration", __FILE__, __LINE__ );

										netmask = 1 << (( 8*sizeof ( uint32_t )) - netmask );
										min_addr = ntohl ( min_addr ) & (~(netmask - 1));
										max_addr = min_addr | (netmask - 1);
										ipaddr   = ntohl ( ipaddr );

										if ( ipaddr >= min_addr && ipaddr <= max_addr )
										{
											free ( args1[k] );
											args1[k] = args2[k];
										}
									}

									for ( l=0; l < n_matches; l++ )
										free ( matches[l] );
									free ( matches );
								}

								if ( preg_match ( "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/([0-9]{1,2})$", args2[k], &matches, &n_matches ))
								{
									if ( preg_match ( "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", args1[k], NULL, NULL ))
									{
										if (( netmask = strtol ( matches[1], NULL, 10 )) > 32 )
											AI_fatal_err ( "Invalid IP netmask value in configuration", __FILE__, __LINE__ );

										if (( min_addr = inet_addr ( matches[0] )) == INADDR_NONE )
											AI_fatal_err ( "Invalid base IP address in configuration", __FILE__, __LINE__ );

										ipaddr = inet_addr ( args1[k] );

										if ( ipaddr == INADDR_NONE )
											AI_fatal_err ( "Invalid base IP address in configuration", __FILE__, __LINE__ );

										netmask = 1 << (( 8*sizeof ( uint32_t )) - netmask );
										min_addr = ntohl ( min_addr ) & (~(netmask - 1));
										max_addr = min_addr | (netmask - 1);
										ipaddr   = ntohl ( ipaddr );

										if ( ipaddr >= min_addr && ipaddr <= max_addr )
										{
											free ( args2[k] );
											args2[k] = args1[k];
										}
									}

									for ( l=0; l < n_matches; l++ )
										free ( matches[l] );
									free ( matches );
								}
							}

							snprintf ( new_stmt1, sizeof ( new_stmt1 ), "%s(", function_name1 );
							snprintf ( new_stmt2, sizeof ( new_stmt2 ), "%s(", function_name2 );

							for ( k=0; k < n_args1; k++ )
							{
								if ( strlen ( new_stmt1 ) + strlen ( args1[k] ) + 1 < sizeof ( new_stmt1 ))
									sprintf ( new_stmt1, "%s%s%s", new_stmt1, args1[k], ( k < n_args1 - 1 ) ? "," : ")" );
								
								if ( strlen ( new_stmt2 ) + strlen ( args2[k] ) + 1 < sizeof ( new_stmt2 ))
									sprintf ( new_stmt2, "%s%s%s", new_stmt2, args2[k], ( k < n_args2 - 1 ) ? "," : ")" );
							}

							if ( !strcmp ( new_stmt1, new_stmt2 ))
							{
								n_intersection += 2;
							}
						}

						for ( k=0; k < n_args1; k++ )
						{
							if ( args1[k] )
							{
								free ( args1[k] );
								args1[k] = NULL;
							}
						}

						if ( args1 )
						{
							free ( args1 );
							args1 = NULL;
						}

						for ( k=0; k < n_args2; k++ )
						{
							if ( args2[k] )
							{
								/* free ( args2[k] ); */
								args2[k] = NULL;
							}
						}

						if ( args2 )
						{
							free ( args2 );
							args2 = NULL;
						}
					}
				}

				if ( function_name1 )
				{
					free ( function_name1 );
					function_name1 = NULL;
				}

				if ( function_name2 )
				{
					free ( function_name2 );
					function_name2 = NULL;
				}
			}
		}
	}

	return (double) ((double) n_intersection / (double) n_union );
}		/* -----  end of function __AI_kb_correlation_coefficient  ----- */


/**
 * \brief  Parse the manual specified correlations from XML file(s) and fills the hash table
 */

PRIVATE void*
__AI_manual_correlations_parsing_thread ( void *arg )
{
	unsigned int            i = 0;
	char                    manual_correlations_xml[1060]   = { 0 },
					    manual_uncorrelations_xml[1060] = { 0 };
	struct stat             st;
	xmlTextReaderPtr        xml;
	const xmlChar           *tagname;
	AI_alert_type_pair_key  key;
	AI_alert_type_pair      *pair  = NULL,
					    *found = NULL;
	BOOL                    xml_flags[MAN_TAG_NUM] = { false };

	while ( 1 )
	{
		/* Cleanup tables */
		while ( manual_correlations )
		{
			pair = manual_correlations;
			HASH_DEL ( manual_correlations, pair );
			free ( pair );
		}

		while ( manual_uncorrelations )
		{
			pair = manual_uncorrelations;
			HASH_DEL ( manual_uncorrelations, pair );
			free ( pair );
		}

		pair = NULL;
		memset ( &key, 0, sizeof ( key ));

		snprintf ( manual_correlations_xml,
				sizeof ( manual_correlations_xml ),
				"%s/manual_correlations.xml", config->webserv_dir );

		snprintf ( manual_uncorrelations_xml,
				sizeof ( manual_uncorrelations_xml ),
				"%s/manual_uncorrelations.xml", config->webserv_dir );

		if ( stat ( manual_correlations_xml, &st ) < 0 )
		{
			pthread_exit ((void*) 0);
			return (void*) 0;
		}

		if ( stat ( manual_uncorrelations_xml, &st ) < 0 )
		{
			pthread_exit ((void*) 0);
			return (void*) 0;
		}

		LIBXML_TEST_VERSION

		/* Check manual correlations */
		if ( !( xml = xmlReaderForFile ( manual_correlations_xml, NULL, 0 )))
		{
			pthread_exit ((void*) 0);
			return (void*) 0;
		}

		while ( xmlTextReaderRead ( xml ))
		{
			if ( !( tagname = xmlTextReaderConstName ( xml )))
				continue;

			if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_ELEMENT )
			{
				if ( !strcasecmp ((const char*) tagname, "correlations" ))
				{
					if ( xml_flags[inCorrelations] )
					{
						AI_fatal_err ( "Tag 'correlations' opened twice in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelations] = true;
					}
				} else if ( !strcasecmp ((const char*) tagname, "correlation" )) {
					if ( xml_flags[inCorrelation] )
					{
						AI_fatal_err ( "Tag 'correlation' opened twice in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelation] = true;
					}
				} else if ( !strcasecmp ((const char*) tagname, "from" )) {
					xml_flags[inFromTag] = true;

					key.from_gid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" ), NULL, 10 ) : 0;
					key.from_sid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" ), NULL, 10 ) : 0;
					key.from_rev = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" ), NULL, 10 ) : 0;

					/* If this is a new pair, allocate the memory */
					if ( pair == NULL )
					{
						if ( !( pair = ( AI_alert_type_pair* ) malloc ( sizeof ( AI_alert_type_pair ))))
						{
							AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
						}

						pair->corr_type = manuallyCorrelated;
					} else {
						/* Otherwise, add the pair to the hash, if it's not already there */
						pair->key = key;
						HASH_FIND ( hh, manual_correlations, &key, sizeof ( key ), found );

						if ( !found )
						{
							HASH_ADD ( hh, manual_correlations, key, sizeof ( key ), pair );
						}

						pair = NULL;
						memset ( &key, 0, sizeof ( key ));
					}
				} else if ( !strcasecmp ((const char*) tagname, "to" )) {
					xml_flags[inToTag] = true;

					key.to_gid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" ), NULL, 10 ) : 0;
					key.to_sid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" ), NULL, 10 ) : 0;
					key.to_rev = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" ), NULL, 10 ) : 0;

					/* If this is a new pair, allocate the memory */
					if ( pair == NULL )
					{
						if ( !( pair = ( AI_alert_type_pair* ) malloc ( sizeof ( AI_alert_type_pair ))))
						{
							AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
						}

						pair->corr_type = manuallyCorrelated;
					} else {
						/* Otherwise, add the pair to the hash, if it's not already there */
						pair->key = key;
						HASH_FIND ( hh, manual_correlations, &key, sizeof ( key ), found );

						if ( !found )
						{
							HASH_ADD ( hh, manual_correlations, key, sizeof ( key ), pair );
						}

						pair = NULL;
						memset ( &key, 0, sizeof ( key ));
					}
				} else {
					AI_fatal_err ( "Unrecognized tag in manual correlations XML file", __FILE__, __LINE__ );
				}
			} else if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_END_ELEMENT ) {
				if ( !strcasecmp ((const char*) tagname, "correlations" ))
				{
					if ( !xml_flags[inCorrelations] )
					{
						AI_fatal_err ( "Tag 'correlations' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelations] = false;
					}
				} else if ( !strcasecmp ((const char*) tagname, "correlation" )) {
					if ( !xml_flags[inCorrelation] )
					{
						AI_fatal_err ( "Tag 'correlation' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelation] = false;
					}
				} else if ( !strcasecmp ((const char*) tagname, "from" )) {
					if ( !xml_flags[inFromTag] )
					{
						AI_fatal_err ( "Tag 'from' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inFromTag] = false;
					}
				} else if ( !strcasecmp ((const char*) tagname, "to" )) {
					if ( !xml_flags[inToTag] )
					{
						AI_fatal_err ( "Tag 'to' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inToTag] = false;
					}
				} else {
					AI_fatal_err ( "Unrecognized tag in manual correlations XML file", __FILE__, __LINE__ );
				}
			}
		}

		xmlFreeTextReader ( xml );
		xmlCleanupParser();

		for ( i=0; i < MAN_TAG_NUM; i++ )
		{
			xml_flags[i] = false;
		}

		/* Check manual un-correlations */
		if ( !( xml = xmlReaderForFile ( manual_uncorrelations_xml, NULL, 0 )))
		{
			pthread_exit ((void*) 0);
			return (void*) 0;
		}

		while ( xmlTextReaderRead ( xml ))
		{
			if ( !( tagname = xmlTextReaderConstName ( xml )))
				continue;

			if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_ELEMENT )
			{
				if ( !strcasecmp ((const char*) tagname, "correlations" ))
				{
					if ( xml_flags[inCorrelations] )
					{
						AI_fatal_err ( "Tag 'correlations' opened twice in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelations] = true;
					}
				} else if ( !strcasecmp ((const char*) tagname, "correlation" )) {
					if ( xml_flags[inCorrelation] )
					{
						AI_fatal_err ( "Tag 'correlation' opened twice in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelation] = true;
					}
				} else if ( !strcasecmp ((const char*) tagname, "from" )) {
					xml_flags[inFromTag] = true;

					key.from_gid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" ), NULL, 10 ) : 0;
					key.from_sid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" ), NULL, 10 ) : 0;
					key.from_rev = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" ), NULL, 10 ) : 0;

					/* If this is a new pair, allocate the memory */
					if ( pair == NULL )
					{
						if ( !( pair = ( AI_alert_type_pair* ) malloc ( sizeof ( AI_alert_type_pair ))))
						{
							AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
						}

						pair->corr_type = manuallyNotCorrelated;
					} else {
						/* Otherwise, add the pair to the hash, if it's not already there */
						pair->key = key;
						HASH_FIND ( hh, manual_uncorrelations, &key, sizeof ( key ), found );

						if ( !found )
						{
							HASH_ADD ( hh, manual_uncorrelations, key, sizeof ( key ), pair );
						}

						pair = NULL;
						memset ( &key, 0, sizeof ( key ));
					}
				} else if ( !strcasecmp ((const char*) tagname, "to" )) {
					xml_flags[inToTag] = true;

					key.to_gid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" ), NULL, 10 ) : 0;
					key.to_sid = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" ), NULL, 10 ) : 0;
					key.to_rev = (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" )) ?
						strtol (( const char* ) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" ), NULL, 10 ) : 0;

					/* If this is a new pair, allocate the memory */
					if ( pair == NULL )
					{
						if ( !( pair = ( AI_alert_type_pair* ) malloc ( sizeof ( AI_alert_type_pair ))))
						{
							AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
						}

						pair->corr_type = manuallyNotCorrelated;
					} else {
						/* Otherwise, add the pair to the hash, if it's not already there */
						pair->key = key;
						HASH_FIND ( hh, manual_uncorrelations, &key, sizeof ( key ), found );

						if ( !found )
						{
							HASH_ADD ( hh, manual_uncorrelations, key, sizeof ( key ), pair );
						}

						pair = NULL;
						memset ( &key, 0, sizeof ( key ));
					}
				} else {
					AI_fatal_err ( "Unrecognized tag in manual correlations XML file", __FILE__, __LINE__ );
				}
			} else if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_END_ELEMENT ) {
				if ( !strcasecmp ((const char*) tagname, "correlations" ))
				{
					if ( !xml_flags[inCorrelations] )
					{
						AI_fatal_err ( "Tag 'correlations' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelations] = false;
					}
				} else if ( !strcasecmp ((const char*) tagname, "correlation" )) {
					if ( !xml_flags[inCorrelation] )
					{
						AI_fatal_err ( "Tag 'correlation' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inCorrelation] = false;
					}
				} else if ( !strcasecmp ((const char*) tagname, "from" )) {
					if ( !xml_flags[inFromTag] )
					{
						AI_fatal_err ( "Tag 'from' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inFromTag] = false;
					}
				} else if ( !strcasecmp ((const char*) tagname, "to" )) {
					if ( !xml_flags[inToTag] )
					{
						AI_fatal_err ( "Tag 'to' closed but never opened in manual correlations XML file", __FILE__, __LINE__ );
					} else {
						xml_flags[inToTag] = false;
					}
				} else {
					AI_fatal_err ( "Unrecognized tag in manual correlations XML file", __FILE__, __LINE__ );
				}
			}
		}

		xmlFreeTextReader ( xml );
		xmlCleanupParser();
		sleep ( config->manualCorrelationsParsingInterval );
	}

	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function __AI_manual_correlations_parsing_thread  ----- */


/**
 * \brief  Substitute the macros in hyperalert pre-conditions and post-conditions with their associated values
 * \param  alert 	Reference to the hyperalert to work on
 */

PRIVATE void
__AI_macro_subst ( AI_snort_alert **alert )
{
	/*
	 * Recognized macros:
	 * +SRC_ADDR+, +DST_ADDR+, +SRC_PORT+, +DST_PORT+, +ANY_ADDR+, +ANY_PORT+
	 */

	int  i;
	char src_addr[INET_ADDRSTRLEN], dst_addr[INET_ADDRSTRLEN];
	char src_port[10], dst_port[10];
	char *tmp;

	for ( i=0; i < (*alert)->hyperalert->n_preconds; i++ )
	{
		tmp = (*alert)->hyperalert->preconds[i];
		(*alert)->hyperalert->preconds[i] = str_replace_all ( (*alert)->hyperalert->preconds[i], " ", "" );
		free ( tmp );

		if ( strstr ( (*alert)->hyperalert->preconds[i], "+SRC_ADDR+" ))
		{
			inet_ntop ( AF_INET, &((*alert)->ip_src_addr), src_addr, INET_ADDRSTRLEN );
			tmp = (*alert)->hyperalert->preconds[i];
			(*alert)->hyperalert->preconds[i] = str_replace ( (*alert)->hyperalert->preconds[i], "+SRC_ADDR+", src_addr );
			free ( tmp );
		}
		
		if ( strstr ( (*alert)->hyperalert->preconds[i], "+DST_ADDR+" )) {
			inet_ntop ( AF_INET, &((*alert)->ip_dst_addr), dst_addr, INET_ADDRSTRLEN );
			tmp = (*alert)->hyperalert->preconds[i];
			(*alert)->hyperalert->preconds[i] = str_replace ( (*alert)->hyperalert->preconds[i], "+DST_ADDR+", dst_addr );
			free ( tmp );
		}
		
		if ( strstr ( (*alert)->hyperalert->preconds[i], "+SRC_PORT+" )) {
			snprintf ( src_port, sizeof ( src_port ), "%d", ntohs ((*alert)->tcp_src_port) );
			tmp = (*alert)->hyperalert->preconds[i];
			(*alert)->hyperalert->preconds[i] = str_replace ( (*alert)->hyperalert->preconds[i], "+SRC_PORT+", src_port );
			free ( tmp );
		}
		
		if ( strstr ( (*alert)->hyperalert->preconds[i], "+DST_PORT+" )) {
			snprintf ( dst_port, sizeof ( dst_port ), "%d", ntohs ((*alert)->tcp_dst_port) );
			tmp = (*alert)->hyperalert->preconds[i];
			(*alert)->hyperalert->preconds[i] = str_replace ( (*alert)->hyperalert->preconds[i], "+DST_PORT+", dst_port );
			free ( tmp );
		}
	}

	for ( i=0; i < (*alert)->hyperalert->n_postconds; i++ )
	{
		tmp = (*alert)->hyperalert->postconds[i];
		(*alert)->hyperalert->postconds[i] = str_replace_all ( (*alert)->hyperalert->postconds[i], " ", "" );
		free ( tmp );

		if ( strstr ( (*alert)->hyperalert->postconds[i], "+SRC_ADDR+" ))
		{
			inet_ntop ( AF_INET, &((*alert)->ip_src_addr), src_addr, INET_ADDRSTRLEN );
			tmp = (*alert)->hyperalert->postconds[i];
			(*alert)->hyperalert->postconds[i] = str_replace ( (*alert)->hyperalert->postconds[i], "+SRC_ADDR+", src_addr );
			free ( tmp );
		}
		
		if ( strstr ( (*alert)->hyperalert->postconds[i], "+DST_ADDR+" )) {
			inet_ntop ( AF_INET, &((*alert)->ip_dst_addr), dst_addr, INET_ADDRSTRLEN );
			tmp = (*alert)->hyperalert->postconds[i];
			(*alert)->hyperalert->postconds[i] = str_replace ( (*alert)->hyperalert->postconds[i], "+DST_ADDR+", dst_addr );
			free ( tmp );
		}
		
		if ( strstr ( (*alert)->hyperalert->postconds[i], "+SRC_PORT+" )) {
			snprintf ( src_port, sizeof ( src_port ), "%d", ntohs ((*alert)->tcp_src_port) );
			tmp = (*alert)->hyperalert->postconds[i];
			(*alert)->hyperalert->postconds[i] = str_replace ( (*alert)->hyperalert->postconds[i], "+SRC_PORT+", src_port );
			free ( tmp );
		}
		
		if ( strstr ( (*alert)->hyperalert->postconds[i], "+DST_PORT+" )) {
			snprintf ( dst_port, sizeof ( dst_port ), "%d", ntohs ((*alert)->tcp_dst_port) );
			tmp = (*alert)->hyperalert->postconds[i];
			(*alert)->hyperalert->postconds[i] = str_replace ( (*alert)->hyperalert->postconds[i], "+DST_PORT+", dst_port );
			free ( tmp );
		}
	}
}		/* -----  end of function __AI_macro_subst  ----- */

/**
 * \brief  Parse info about a hyperalert from a correlation XML file, if it exists
 * \param  key 	Key (gid, sid, rev) identifying the alert
 * \return A hyperalert structure containing the info about the current alert, if the XML file was found
 */

PRIVATE AI_hyperalert_info*
__AI_hyperalert_from_XML ( AI_hyperalert_key key )
{
	char                  hyperalert_file[1024] = {0};
	char                  snort_id[1024]        = {0};
	BOOL                  xmlFlags[HYP_TAG_NUM]     = { false };
	struct stat           st;
	xmlTextReaderPtr      xml;
	const xmlChar         *tagname, *tagvalue;
	AI_hyperalert_info    *hyp;

	if ( !( hyp = ( AI_hyperalert_info* ) malloc ( sizeof ( AI_hyperalert_info ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	memset ( hyp, 0, sizeof ( AI_hyperalert_info ));
	memset ( hyperalert_file, 0, sizeof ( hyperalert_file ));
	
	hyp->key = key;
	snprintf ( hyperalert_file, sizeof ( hyperalert_file ), "%s/%d-%d-%d.xml",
			config->corr_rules_dir, key.gid, key.sid, key.rev );

	if ( stat ( hyperalert_file, &st ) < 0 )
		return NULL;

	LIBXML_TEST_VERSION

	if ( !( xml = xmlReaderForFile ( hyperalert_file, NULL, 0 )))
		return NULL;

	while ( xmlTextReaderRead ( xml ))
	{
		if ( !( tagname = xmlTextReaderConstName ( xml )))
			continue;

		if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_ELEMENT )
		{
			if ( !strcasecmp ((const char*) tagname, "hyperalert" ))
			{
				if ( xmlFlags[inHyperAlert] )
					AI_fatal_err ( "Error in XML correlation rules: the hyperalert tag was opened twice", __FILE__, __LINE__ );
				else
					xmlFlags[inHyperAlert] = true;
			} else if ( !strcasecmp ((const char*) tagname, "snort-id" )) {
				if ( xmlFlags[inSnortIdTag] )
					AI_fatal_err ( "Error in XML correlation rules: 'snort-id' tag open inside of another 'snort-id' tag", __FILE__, __LINE__ );
				else if ( !xmlFlags[inHyperAlert] )
					AI_fatal_err ( "Error in XML correlation rules: 'snort-id' tag open outside of 'hyperalert' tag", __FILE__, __LINE__ );
				else
					xmlFlags[inSnortIdTag] = true;
			} else if ( !strcasecmp ((const char*) tagname, "pre" )) {
				if ( xmlFlags[inPreTag] )
					AI_fatal_err ( "Error in XML correlation rules: 'pre' tag open inside of another 'pre' tag", __FILE__, __LINE__ );
				else if ( !xmlFlags[inHyperAlert] )
					AI_fatal_err ( "Error in XML correlation rules: 'pre' tag open outside of 'hyperalert' tag", __FILE__, __LINE__ );
				else
					xmlFlags[inPreTag] = true;
			} else if ( !strcasecmp ((const char*) tagname, "post" )) {
				if ( xmlFlags[inPostTag] )
					AI_fatal_err ( "Error in XML correlation rules: 'post' tag open inside of another 'post' tag", __FILE__, __LINE__ );
				else if ( !xmlFlags[inHyperAlert] )
					AI_fatal_err ( "Error in XML correlation rules: 'post' tag open outside of 'hyperalert' tag", __FILE__, __LINE__ );
				else
					xmlFlags[inPostTag] = true;
			} else if ( !strcasecmp ((const char*) tagname, "desc" )) {}
			  else {
				AI_fatal_err ( "Unrecognized tag in XML correlation rules", __FILE__, __LINE__ );
			}
		} else if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_END_ELEMENT ) {
			if ( !strcasecmp ((const char*) tagname, "hyperalert" ))
			{
				if ( !xmlFlags[inHyperAlert] )
					AI_fatal_err ( "Error in XML correlation rules: hyperalert tag closed but never opend", __FILE__, __LINE__ );
				else
					xmlFlags[inHyperAlert] = false;
			} else if ( !strcasecmp ((const char*) tagname, "snort-id" )) {
				if ( !xmlFlags[inSnortIdTag] )
					AI_fatal_err ( "Error in XML correlation rules: snort-id tag closed but never opend", __FILE__, __LINE__ );
				else
					xmlFlags[inSnortIdTag] = false;
			} else if ( !strcasecmp ((const char*) tagname, "pre" )) {
				if ( !xmlFlags[inPreTag] )
					AI_fatal_err ( "Error in XML correlation rules: pre tag closed but never opend", __FILE__, __LINE__ );
				else
					xmlFlags[inPreTag] = false;
			} else if ( !strcasecmp ((const char*) tagname, "post" )) {
				if ( !xmlFlags[inPostTag] )
					AI_fatal_err ( "Error in XML correlation rules: post tag closed but never opend", __FILE__, __LINE__ );
				else
					xmlFlags[inPostTag] = false;
			} else if ( !strcasecmp ((const char*) tagname, "desc" )) {}
			  else {
				AI_fatal_err ( "Unrecognized tag in XML correlation rules", __FILE__, __LINE__ );
			}
		} else if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_TEXT ) {
			if ( !( tagvalue = xmlTextReaderConstValue ( xml )))
				continue;

			if ( xmlFlags[inSnortIdTag] )
			{
				snprintf ( snort_id, sizeof ( snort_id ), "%d.%d.%d",
						key.gid, key.sid, key.rev );

				if ( strcmp ( snort_id, (const char*) tagvalue ))
				{
					_dpd.errMsg ( "AIPreproc: Found the file associated to hyperalert: '%s', "
						"but the 'snort-id' field in there has a different value\n",
						hyperalert_file );
					return NULL;
				}
			} else if ( xmlFlags[inPreTag] ) {
				if ( !( hyp->preconds = (char**) realloc ( hyp->preconds, (++hyp->n_preconds)*sizeof(char*) )))
					AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

				hyp->preconds[hyp->n_preconds-1] = strdup ((const char*) tagvalue );
			} else if ( xmlFlags[inPostTag] ) {
				if ( !( hyp->postconds = (char**) realloc ( hyp->postconds, (++hyp->n_postconds)*sizeof(char*) )))
					AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

				hyp->postconds[hyp->n_postconds-1] = strdup ((const char*) tagvalue );
			}
		}
	}

	xmlFreeTextReader ( xml );
	xmlCleanupParser();
	return hyp;
}		/* -----  end of function __AI_hyperalert_from_XML  ----- */

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

	AI_hyperalert_key         key;
	AI_hyperalert_info        *hyp                  = NULL;

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

	corr_functions = AI_get_corr_functions( &n_corr_functions );
	corr_weights   = AI_get_corr_weights ( &n_corr_weights );

	pthread_mutex_init ( &mutex, NULL );

	/* Start the thread for parsing manual correlations from XML */
	if ( pthread_create ( &manual_corr_thread, NULL, __AI_manual_correlations_parsing_thread, NULL ) != 0 )
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

		/* Set the lock flag to true, and keep it this way until I've done with generating the new hyperalerts */
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

		for ( alert_iterator = alerts; alert_iterator; alert_iterator = alert_iterator->next )
		{
			/* Check if my hash table of hyperalerts already contains info about this alert */
			key.gid = alert_iterator->gid;
			key.sid = alert_iterator->sid;
			key.rev = alert_iterator->rev;
			HASH_FIND ( hh, hyperalerts, &key, sizeof ( AI_hyperalert_key ), hyp );

			/* If not, try to read info from the XML file, if it exists */
			if ( !hyp )
			{
				/* If there is no hyperalert knowledge on XML for this alert, ignore it and get the next one */
				if ( !( hyp = __AI_hyperalert_from_XML ( key )))
					continue;

				/* If the XML file exists and it's valid, add the hypertalert to the hash table */
				HASH_ADD ( hh, hyperalerts, key, sizeof ( AI_hyperalert_key ), hyp );
			}

			/* Fill the hyper alert info for the current alert */
			if ( !( alert_iterator->hyperalert = ( AI_hyperalert_info* ) malloc ( sizeof ( AI_hyperalert_info ))))
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			
			alert_iterator->hyperalert->key         = hyp->key;
			alert_iterator->hyperalert->n_preconds  = hyp->n_preconds;
			alert_iterator->hyperalert->n_postconds = hyp->n_postconds;
			
			if ( !( alert_iterator->hyperalert->preconds = ( char** ) malloc ( alert_iterator->hyperalert->n_preconds * sizeof ( char* ))))
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			
			for ( i=0; i < alert_iterator->hyperalert->n_preconds; i++ )
				alert_iterator->hyperalert->preconds[i] = strdup ( hyp->preconds[i] );

			if ( !( alert_iterator->hyperalert->postconds = ( char** ) malloc ( alert_iterator->hyperalert->n_postconds * sizeof ( char* ))))
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			
			for ( i=0; i < alert_iterator->hyperalert->n_postconds; i++ )
				alert_iterator->hyperalert->postconds[i] = strdup ( hyp->postconds[i] );

			__AI_macro_subst ( &alert_iterator );
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

					kb_correlation = __AI_kb_correlation_coefficient ( corr_key.a, corr_key.b );
					bayesian_correlation = AI_alert_bayesian_correlation ( corr_key.a, corr_key.b );
					neural_correlation = AI_alert_neural_som_correlation ( corr_key.a, corr_key.b );

					/* Use the correlation indexes for which we have a value */
					if ( bayesian_correlation != 0.0 && config->bayesianCorrelationInterval != 0 )
					{
						corr->correlation += AI_bayesian_correlation_weight() * bayesian_correlation;
						n_correlations++;
					}

					if ( kb_correlation != 0.0 )
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
					if ( !( corr->key.a->derived_alerts = ( AI_snort_alert** ) realloc ( corr->key.a->derived_alerts, (++corr->key.a->n_derived_alerts) * sizeof ( AI_snort_alert* ))))
						AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

					if ( !( corr->key.b->parent_alerts = ( AI_snort_alert** ) realloc ( corr->key.b->parent_alerts, (++corr->key.b->n_parent_alerts) * sizeof ( AI_snort_alert* ))))
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
					continue;

				if ( !( fp = fopen ( corr_dot_file, "r" )))
					continue;

				if ( !( g = agread ( fp )))
					continue;

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

