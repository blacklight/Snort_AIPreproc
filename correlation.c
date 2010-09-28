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

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<time.h>
#include	<math.h>
#include	<alloca.h>
#include	<sys/stat.h>
#include 	<pthread.h>
#include	<libxml/xmlreader.h>

#ifdef 	HAVE_LIBGVC
	#include	<gvc.h>
#endif

/** \defgroup correlation Module for the correlation of hyperalerts
 * @{ */

#ifndef 	LIBXML_READER_ENABLED
#error 	"libxml2 reader not enabled\n"
#endif

/** Enumeration for the types of XML tags */
enum  { inHyperAlert, inSnortIdTag, inPreTag, inPostTag, TAG_NUM };

/** Key for the correlation hash table */
typedef struct  {
	/** First alert */
	AI_snort_alert *a;

	/** Second alert */
	AI_snort_alert *b;
} AI_alert_correlation_key;


/** Struct representing the correlation between all the couples of alerts */
typedef struct  {
	/** Hash key */
	AI_alert_correlation_key  key;

	/** Correlation coefficient */
	double                    correlation;

	/** Make the struct 'hashable' */
	UT_hash_handle            hh;
} AI_alert_correlation;


PRIVATE AI_hyperalert_info       *hyperalerts       = NULL;
PRIVATE AI_snort_alert           *alerts            = NULL;
PRIVATE AI_alert_correlation     *correlation_table = NULL;
PRIVATE pthread_mutex_t          mutex;


/**
 * \brief  Clean up the correlation hash table
 */

PRIVATE void
_AI_correlation_table_cleanup ()
{
	AI_alert_correlation *current;

	while ( correlation_table )
	{
		current = correlation_table;
		HASH_DEL ( correlation_table, current );
		free ( current );
	}
}		/* -----  end of function _AI_correlation_table_cleanup  ----- */

/**
 * \brief  Recursively write a flow of correlated alerts to a .dot file, ready for being rendered as graph
 * \param  corr 	Correlated alerts
 * \param  fp       File pointer
 */

PRIVATE void
_AI_print_correlated_alerts ( AI_alert_correlation *corr, FILE *fp )
{
	char  src_addr1[INET_ADDRSTRLEN],
		 dst_addr1[INET_ADDRSTRLEN],
		 src_addr2[INET_ADDRSTRLEN],
		 dst_addr2[INET_ADDRSTRLEN],
		 src_port1[10],
		 dst_port1[10],
		 src_port2[10],
		 dst_port2[10],
		 timestamp1[40],
		 timestamp2[40];

	struct tm *t1, *t2;

	if ( !corr )
		return;

	inet_ntop ( AF_INET, &(corr->key.a->ip_src_addr), src_addr1, INET_ADDRSTRLEN );
	inet_ntop ( AF_INET, &(corr->key.a->ip_dst_addr), dst_addr1, INET_ADDRSTRLEN );

	snprintf ( src_port1, sizeof ( src_port1 ), "%d", ntohs ( corr->key.a->tcp_src_port ));
	snprintf ( dst_port1, sizeof ( dst_port1 ), "%d", ntohs ( corr->key.a->tcp_dst_port ));

	t1 = localtime ( &(corr->key.a->timestamp ));
	strftime ( timestamp1, sizeof ( timestamp1 ), "%a %b %d %Y, %H:%M:%S", t1 );

	inet_ntop ( AF_INET, &(corr->key.b->ip_src_addr), src_addr2, INET_ADDRSTRLEN );
	inet_ntop ( AF_INET, &(corr->key.b->ip_dst_addr), dst_addr2, INET_ADDRSTRLEN );

	snprintf ( src_port2, sizeof ( src_port2 ), "%d", ntohs ( corr->key.b->tcp_src_port ));
	snprintf ( dst_port2, sizeof ( dst_port2 ), "%d", ntohs ( corr->key.b->tcp_dst_port ));

	t2 = localtime ( &(corr->key.b->timestamp ));
	strftime ( timestamp2, sizeof ( timestamp2 ), "%a %b %d %Y, %H:%M:%S", t2 );

	fprintf ( fp,
		"\t\"[%d.%d.%d] %s\\n"
		"%s:%s -> %s:%s\\n"
		"%s\\n"
		"(%d alerts grouped)\" -> "

		"\"[%d.%d.%d] %s\\n"
		"%s:%s -> %s:%s\\n"
		"%s\\n"
		"(%d alerts grouped)\";\n",

		corr->key.a->gid, corr->key.a->sid, corr->key.a->rev, corr->key.a->desc,
		src_addr1, src_port1, dst_addr1, dst_port1,
		timestamp1,
		corr->key.a->grouped_alerts_count,

		corr->key.b->gid, corr->key.b->sid, corr->key.b->rev, corr->key.b->desc,
		src_addr2, src_port2, dst_addr2, dst_port2,
		timestamp2,
		corr->key.b->grouped_alerts_count
	);
}		/* -----  end of function _AI_correlation_flow_to_file  ----- */


/**
 * \brief  Get the name of the function called by a pre-condition or post-condition predicate
 * \param  orig_stmt 	Statement representing a pre-condition or post-condition
 * \return The name of the function called by that statement
 */

PRIVATE char*
_AI_get_function_name ( const char *orig_stmt )
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
}		/* -----  end of function _AI_get_function_name  ----- */


/**
 * \brief  Get the arguments passed to a function predicate in a pre-condition or post-condition (comma-separated values)
 * \param  orig_stmt 	Statement representing a pre-condition or post-condition
 * \param  n_args 		Reference to an integer that will contain the number of arguments read
 * \return An array of strings containing the arguments of the function
 */

PRIVATE char**
_AI_get_function_arguments ( char *orig_stmt, int *n_args )
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
			_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );

		args [ (*n_args) - 1 ] = strdup ( tok );
		tok = (char*) strtok ( NULL, " " );
	}

	if ( !(*n_args) )
		return NULL;

	return args;
}		/* -----  end of function _AI_get_function_arguments  ----- */


/**
 * \brief  Compute the correlation coefficient between two alerts, as #INTERSECTION(pre(B), post(A)) / #UNION(pre(B), post(A)), on the basis of preconditions and postconditions in the knowledge base's correlation rules
 * \param  a 	Alert a
 * \param  b   Alert b
 * \return The correlation coefficient between A and B as coefficient in [0,1]
 */

PRIVATE double
_AI_kb_correlation_coefficient ( AI_snort_alert *a, AI_snort_alert *b )
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
				function_name1 = _AI_get_function_name ( a->hyperalert->postconds[i] );
				function_name2 = _AI_get_function_name ( b->hyperalert->preconds[j] );

				if ( !strcasecmp ( function_name1, function_name2 ))
				{
					args1 = _AI_get_function_arguments ( a->hyperalert->postconds[i], &n_args1 );
					args2 = _AI_get_function_arguments ( b->hyperalert->preconds[j] , &n_args2 );

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
											_dpd.fatalMsg ( "AIPreproc: Invalid netmask value in '%s'\n", args1[k] );

										if (( min_addr = inet_addr ( matches[0] )) == INADDR_NONE )
											_dpd.fatalMsg ( "AIPreproc: Invalid base IP address in '%s'\n", args1[k] );

										ipaddr = inet_addr ( args2[k] );
										
										if ( ipaddr == INADDR_NONE )
											_dpd.fatalMsg ( "AIPreproc: Invalid base IP address in '%s'\n", args2[k] );

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
											_dpd.fatalMsg ( "AIPreproc: Invalid netmask value in '%s'\n", args2[k] );

										if (( min_addr = inet_addr ( matches[0] )) == INADDR_NONE )
											_dpd.fatalMsg ( "AIPreproc: Invalid base IP address in '%s'\n", args2[k] );

										ipaddr = inet_addr ( args1[k] );

										if ( ipaddr == INADDR_NONE )
											_dpd.fatalMsg ( "AIPreproc: Invalid base IP address in '%s'\n", args1[k] );

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
}		/* -----  end of function _AI_kb_correlation_coefficient  ----- */


/**
 * \brief  Substitute the macros in hyperalert pre-conditions and post-conditions with their associated values
 * \param  alert 	Reference to the hyperalert to work on
 */

PRIVATE void
_AI_macro_subst ( AI_snort_alert **alert )
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
}		/* -----  end of function _AI_macro_subst  ----- */

/**
 * \brief  Parse info about a hyperalert from a correlation XML file, if it exists
 * \param  key 	Key (gid, sid, rev) identifying the alert
 * \return A hyperalert structure containing the info about the current alert, if the XML file was found
 */

PRIVATE AI_hyperalert_info*
_AI_hyperalert_from_XML ( AI_hyperalert_key key )
{
	char                  hyperalert_file[1024] = {0};
	char                  snort_id[1024]        = {0};
	BOOL                  xmlFlags[TAG_NUM]     = { false };
	struct stat           st;
	xmlTextReaderPtr      xml;
	const xmlChar         *tagname, *tagvalue;
	AI_hyperalert_info    *hyp;

	if ( !( hyp = ( AI_hyperalert_info* ) malloc ( sizeof ( AI_hyperalert_info ))))
	{
		_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );
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
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': the hyperalert tag was opened twice\n", hyperalert_file );
				else
					xmlFlags[inHyperAlert] = true;
			} else if ( !strcasecmp ((const char*) tagname, "snort-id" )) {
				if ( xmlFlags[inSnortIdTag] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': 'snort-id' tag open inside of another 'snort-id' tag\n", hyperalert_file );
				else if ( !xmlFlags[inHyperAlert] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': 'snort-id' tag open outside of 'hyperalert' tag\n", hyperalert_file );
				else
					xmlFlags[inSnortIdTag] = true;
			} else if ( !strcasecmp ((const char*) tagname, "pre" )) {
				if ( xmlFlags[inPreTag] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': 'pre' tag open inside of another 'pre' tag\n", hyperalert_file );
				else if ( !xmlFlags[inHyperAlert] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': 'pre' tag open outside of 'hyperalert' tag\n", hyperalert_file );
				else
					xmlFlags[inPreTag] = true;
			} else if ( !strcasecmp ((const char*) tagname, "post" )) {
				if ( xmlFlags[inPostTag] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': 'post' tag open inside of another 'post' tag\n", hyperalert_file );
				else if ( !xmlFlags[inHyperAlert] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': 'post' tag open outside of 'hyperalert' tag\n", hyperalert_file );
				else
					xmlFlags[inPostTag] = true;
			} else if ( !strcasecmp ((const char*) tagname, "desc" )) {}
			  else {
				_dpd.fatalMsg ( "AIPreproc: Unrecognized tag '%s' in XML file '%s'\n", tagname, hyperalert_file );
			}
		} else if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_END_ELEMENT ) {
			if ( !strcasecmp ((const char*) tagname, "hyperalert" ))
			{
				if ( !xmlFlags[inHyperAlert] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': hyperalert tag closed but never opend\n", hyperalert_file );
				else
					xmlFlags[inHyperAlert] = false;
			} else if ( !strcasecmp ((const char*) tagname, "snort-id" )) {
				if ( !xmlFlags[inSnortIdTag] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': snort-id tag closed but never opend\n", hyperalert_file );
				else
					xmlFlags[inSnortIdTag] = false;
			} else if ( !strcasecmp ((const char*) tagname, "pre" )) {
				if ( !xmlFlags[inPreTag] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': pre tag closed but never opend\n", hyperalert_file );
				else
					xmlFlags[inPreTag] = false;
			} else if ( !strcasecmp ((const char*) tagname, "post" )) {
				if ( !xmlFlags[inPostTag] )
					_dpd.fatalMsg ( "AIPreproc: Error in XML file '%s': post tag closed but never opend\n", hyperalert_file );
				else
					xmlFlags[inPostTag] = false;
			} else if ( !strcasecmp ((const char*) tagname, "desc" )) {}
			  else {
				_dpd.fatalMsg ( "AIPreproc: Unrecognized tag '%s' in XML file '%s'\n", tagname, hyperalert_file );
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
					_dpd.fatalMsg ( "AIPreproc: Fatal allocation memory error at %s:%d\n",
						__FILE__, __LINE__ );

				hyp->preconds[hyp->n_preconds-1] = strdup ((const char*) tagvalue );
			} else if ( xmlFlags[inPostTag] ) {
				if ( !( hyp->postconds = (char**) realloc ( hyp->postconds, (++hyp->n_postconds)*sizeof(char*) )))
					_dpd.fatalMsg ( "AIPreproc: Fatal allocation memory error at %s:%d\n",
						__FILE__, __LINE__ );

				hyp->postconds[hyp->n_postconds-1] = strdup ((const char*) tagvalue );
			}
		}
	}

	xmlFreeTextReader ( xml );
	xmlCleanupParser();
	return hyp;
}		/* -----  end of function _AI_hyperalert_from_XML  ----- */

/**
 * \brief  Thread for correlating clustered alerts
 */

void*
AI_alert_correlation_thread ( void *arg )
{
	int                       i;
	struct stat               st;
	char                      corr_dot_file[4096]   = { 0 },
						 corr_ps_file [4096]   = { 0 };

	double                    avg_correlation       = 0.0,
						 std_deviation         = 0.0,
						 corr_threshold        = 0.0,
						 kb_correlation        = 0.0,
						 bayesian_correlation  = 0.0;

	FILE                      *fp                   = NULL;

	AI_alert_correlation_key  corr_key;
	AI_alert_correlation      *corr                 = NULL;

	AI_hyperalert_key         key;
	AI_hyperalert_info        *hyp                  = NULL;

	AI_snort_alert            *alert_iterator       = NULL,
					      *alert_iterator2      = NULL;

	#ifdef                    HAVE_LIBGVC
	char                      corr_png_file[4096]   = { 0 };
	GVC_t                     *gvc                  = NULL;
	graph_t                   *g                    = NULL;
	#endif

	pthread_mutex_init ( &mutex, NULL );

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
				if ( !( hyp = _AI_hyperalert_from_XML ( key )))
					continue;

				/* If the XML file exists and it's valid, add the hypertalert to the hash table */
				HASH_ADD ( hh, hyperalerts, key, sizeof ( AI_hyperalert_key ), hyp );
			}

			/* Fill the hyper alert info for the current alert */
			if ( !( alert_iterator->hyperalert = ( AI_hyperalert_info* ) malloc ( sizeof ( AI_hyperalert_info ))))
				_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );
			
			alert_iterator->hyperalert->key         = hyp->key;
			alert_iterator->hyperalert->n_preconds  = hyp->n_preconds;
			alert_iterator->hyperalert->n_postconds = hyp->n_postconds;
			
			if ( !( alert_iterator->hyperalert->preconds = ( char** ) malloc ( alert_iterator->hyperalert->n_preconds * sizeof ( char* ))))
				_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );
			
			for ( i=0; i < alert_iterator->hyperalert->n_preconds; i++ )
				alert_iterator->hyperalert->preconds[i] = strdup ( hyp->preconds[i] );

			if ( !( alert_iterator->hyperalert->postconds = ( char** ) malloc ( alert_iterator->hyperalert->n_postconds * sizeof ( char* ))))
				_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );
			
			for ( i=0; i < alert_iterator->hyperalert->n_postconds; i++ )
				alert_iterator->hyperalert->postconds[i] = strdup ( hyp->postconds[i] );

			_AI_macro_subst ( &alert_iterator );
		}

		_AI_correlation_table_cleanup();
		correlation_table = NULL;

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
						_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );

					corr_key.a = alert_iterator;
					corr_key.b = alert_iterator2;

					corr->key  = corr_key;
					kb_correlation = _AI_kb_correlation_coefficient ( corr_key.a, corr_key.b );
					bayesian_correlation = AI_alert_bayesian_correlation ( corr_key.a, corr_key.b );

					if ( bayesian_correlation == 0.0 || config->bayesianCorrelationInterval == 0 )
						corr->correlation = kb_correlation;
					else if ( kb_correlation == 0.0 )
						corr->correlation = bayesian_correlation;
					else
						corr->correlation = ( kb_correlation + bayesian_correlation ) / 2;

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
					_dpd.fatalMsg ( "AIPreproc: Unable to create directory '%s'\n", config->corr_alerts_dir );
				}
			} else if ( !S_ISDIR ( st.st_mode )) {
				_dpd.fatalMsg ( "AIPreproc: '%s' found but it's not a directory\n", config->corr_alerts_dir );
			}

			if ( !( fp = fopen ( corr_dot_file, "w" )))
				_dpd.fatalMsg ( "AIPreproc: Could not write on file '%s'\n", corr_dot_file );
			fprintf ( fp, "digraph G  {\n" );

			/* Find correlated alerts */
			for ( corr = correlation_table; corr; corr = ( AI_alert_correlation* ) corr->hh.next )
			{
				if ( corr->correlation >= corr_threshold &&
						corr_threshold != 0.0 &&
						corr->key.a->timestamp <= corr->key.b->timestamp && ! (
						corr->key.a->gid == corr->key.b->gid &&
						corr->key.a->sid == corr->key.b->sid &&
						corr->key.a->rev == corr->key.b->rev ))
				{
					if ( !( corr->key.a->derived_alerts = ( AI_snort_alert** ) realloc ( corr->key.a->derived_alerts, (++corr->key.a->n_derived_alerts) * sizeof ( AI_snort_alert* ))))
						_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );

					if ( !( corr->key.b->parent_alerts = ( AI_snort_alert** ) realloc ( corr->key.b->parent_alerts, (++corr->key.b->n_parent_alerts) * sizeof ( AI_snort_alert* ))))
						_dpd.fatalMsg ( "AIPreproc: Fatal memory allocation error at %s:%d\n", __FILE__, __LINE__ );

					corr->key.a->derived_alerts[ corr->key.a->n_derived_alerts - 1 ] = corr->key.b;
					corr->key.b->parent_alerts [ corr->key.b->n_parent_alerts  - 1 ] = corr->key.a;
					_AI_print_correlated_alerts ( corr, fp );
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
		}

		pthread_mutex_unlock ( &mutex );
	}

	pthread_exit (( void* ) 0 );
	return (void*) 0;
}		/* -----  end of function AI_alert_correlation_thread  ----- */

/** @} */

