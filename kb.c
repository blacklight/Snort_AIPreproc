/*
 * =====================================================================================
 *
 *       Filename:  kb.c
 *
 *    Description:  Hyperalert knowledge-base oriented index
 *
 *        Version:  0.1
 *        Created:  20/01/2011 18:00:34
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
#include	<sys/stat.h>

/** \defgroup correlation Module for the correlation of hyperalerts
 * @{ */

#ifndef 	LIBXML_READER_ENABLED
#error 	"libxml2 reader not enabled\n"
#endif

/** Enumeration for the types of hyperalert XML tags */
enum  { inHyperAlert, inSnortIdTag, inPreTag, inPostTag, HYP_TAG_NUM };

PRIVATE AI_hyperalert_info *hyperalerts = NULL;

/**
 * \brief  Get the name of the function called by a pre-condition or post-condition predicate
 * \param  orig_stmt 	Statement representing a pre-condition or post-condition
 * \return The name of the function called by that statement
 */

PRIVATE char*
__AI_get_function_name ( const char *orig_stmt )
{
	unsigned long int parenthesis_pos, function_name_len;
	char function_name[4096];
	char *stmt = NULL;

	if ( !( stmt = (char*) alloca ( strlen ( orig_stmt ))))
		return NULL;
	strcpy ( stmt, orig_stmt );

	memset ( function_name, 0, sizeof ( function_name ));

	if ( !( parenthesis_pos = (unsigned long int) strstr ( stmt, "(" )))
		return NULL;

	parenthesis_pos -= (unsigned long int) stmt;
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
	unsigned long int  par_pos = 0;
	     *n_args = 0;

	if ( !( stmt = (char*) alloca ( strlen ( orig_stmt ))))
		return NULL;
	strcpy ( stmt, orig_stmt );

	if ( !( par_pos = (unsigned long int) strstr ( stmt, "(" )))
		return NULL;
	
	par_pos -= (unsigned long int) stmt;
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

double
AI_kb_correlation_coefficient ( const AI_snort_alert *a, const AI_snort_alert *b )
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

	if ( config->use_knowledge_base_correlation_index == 0 )
	{
		return 0.0;
	}

	if ( !a->hyperalert || !b->hyperalert )
	{
		return 0.0;
	}

	if ( a->hyperalert->n_postconds == 0 || b->hyperalert->n_preconds == 0 )
	{
		return 0.0;
	}

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
 * \brief  Initialize the hyperalert structures for the knowledge base correlation index
 * \param  alerts 	Alert list
 */

void
AI_kb_index_init ( AI_snort_alert *alerts )
{
	int i;
	AI_hyperalert_key  key;
	AI_hyperalert_info *hyp = NULL;
	AI_snort_alert  *alert_iterator = NULL;

	if ( config->use_knowledge_base_correlation_index == 0 )
	{
		return;
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
}		/* -----  end of function AI_kb_index_init  ----- */

/** @} */

