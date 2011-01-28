/*
 * =====================================================================================
 *
 *       Filename:  manual.c
 *
 *    Description:  Managing the thread for manual correlations
 *
 *        Version:  0.1
 *        Created:  20/01/2011 19:00:34
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

#include	<libxml/xmlreader.h>
#include	<unistd.h>
#include	<sys/stat.h>

/** \defgroup correlation Module for the correlation of hyperalerts
 * @{ */

#ifndef 	LIBXML_READER_ENABLED
#error 	"libxml2 reader not enabled\n"
#endif

/** Enumeration for the types of manual correlations XML tags */
enum  { inCorrelation, inCorrelations, inFromTag, inToTag, MAN_TAG_NUM };

AI_alert_type_pair *manual_correlations   = NULL;
AI_alert_type_pair *manual_uncorrelations = NULL;

/**
 * \brief  Parse the manual specified correlations from XML file(s) and fills the hash table
 */

void*
AI_manual_correlations_parsing_thread ( void *arg )
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

