/*
 * =====================================================================================
 *
 *       Filename:  spp_ai.c
 *
 *    Description:  Main file for the spp_ai Snort preprocessor module
 *
 *        Version:  0.1
 *        Created:  26/07/2010 11:00:41
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#include "spp_ai.h"
#include "sfPolicyUserData.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/** \defgroup spp_ai Main file for spp_ai module
 * @{ */

tSfPolicyUserContextId ex_config = NULL;
static void* (*alertparser_thread)(void*) = NULL;

#ifdef SNORT_RELOAD
tSfPolicyUserContextId ex_swap_config = NULL;
#endif

static void AI_init(char *);
static void AI_process(void *, void *);
static AI_config * AI_parse(char *);
#ifdef SNORT_RELOAD
static void AI_reload(char *);
static int AI_reloadSwapPolicyFree(tSfPolicyUserContextId, tSfPolicyId, void *);
static void * AI_reloadSwap(void);
static void AI_reloadSwapFree(void *);
#endif


/**
 * \brief  Set up the preprocessor module
 */

void AI_setup(void)
{
#ifndef SNORT_RELOAD
	_dpd.registerPreproc("ai", AI_init);
#else
	_dpd.registerPreproc("ai", AI_init, AI_reload,
			AI_reloadSwap, AI_reloadSwapFree);
#endif

	DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: AI is setup\n"););
} 		/* -----  end of function AI_setup  ----- */


/**
 * \brief  Initialize the preprocessor module
 * \param  args 	Configuration arguments passed to the module
 */

static void AI_init(char *args)
{
	AI_config *config;

	pthread_t  cleanup_thread,
			 logparse_thread;

	tSfPolicyId policy_id = _dpd.getParserPolicy();

	_dpd.logMsg("AI dynamic preprocessor configuration\n");

	if (ex_config == NULL)
	{
		ex_config = sfPolicyConfigCreate();
		if (ex_config == NULL)
			_dpd.fatalMsg("Could not allocate configuration struct.\n");
	}

	config = AI_parse(args);
	sfPolicyUserPolicySet(ex_config, policy_id);
	sfPolicyUserDataSetCurrent(ex_config, config);

	/* If the hash_cleanup_interval of stream_expire_interval options are set to zero,
	 * no cleanup will be made on the streams */
	if ( config->hashCleanupInterval != 0 && config->streamExpireInterval != 0 )
	{
		if ( pthread_create ( &cleanup_thread, NULL, AI_hashcleanup_thread, config ) != 0 )
		{
			_dpd.fatalMsg ( "Failed to create the hash cleanup thread\n" );
		}
	}

	if ( strlen ( config->alertfile ) > 0 )
	{
		if ( pthread_create ( &logparse_thread, NULL, alertparser_thread, config ) != 0 )
		{
			_dpd.fatalMsg ( "Failed to create the alert parser thread\n" );
		}
	}

	/* Register the preprocessor function, Transport layer, ID 10000 */
	_dpd.addPreproc(AI_process, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);
	DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: AI is initialized\n"););
} 		/* -----  end of function AI_init  ----- */

/**
 * \brief  Parse the arguments passed to the module saving them to a valid configuration struct
 * \param  args 	Arguments passed to the module
 * \return Pointer to AI_config keeping the configuration for the module
 */

static AI_config * AI_parse(char *args)
{
	char *arg;
	char *match;
	char alertfile[1024]   = { 0 };
	char clusterfile[1024] = { 0 };

	char **matches       = NULL;
	int  nmatches        = 0;

	int  i;
	int  offset;
	int  len;
	uint32_t netmask;

	int  min_val;
	int  max_val;
	char label[256];
	cluster_type   type;

	hierarchy_node **hierarchy_nodes = NULL;
	int            n_hierarchy_nodes = 0;

	unsigned long cleanup_interval          = 0,
			    stream_expire_interval    = 0,
			    alertfile_len             = 0,
			    clusterfile_len           = 0,
			    alert_clustering_interval = 0,
			    database_parsing_interval = 0;

	BOOL has_cleanup_interval       = false,
		has_stream_expire_interval = false,
		has_database_interval      = false,
		has_alertfile              = false,
		has_clusterfile            = false,
		has_clustering             = false,
		has_database_log           = false;

	AI_config *config               = NULL;

	if ( !( config = ( AI_config* ) malloc ( sizeof( AI_config )) ))
		_dpd.fatalMsg("Could not allocate configuration struct.\n");
	memset ( config, 0, sizeof ( AI_config ));

	/* Parsing the hashtable_cleanup_interval option */
	if (( arg = (char*) strcasestr( args, "hashtable_cleanup_interval" ) ))
	{
		has_cleanup_interval = true;

		for ( arg += strlen("hashtable_cleanup_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			_dpd.fatalMsg("AIPreproc: hashtable_cleanup_interval option used but "
				"no value specified\n");
		}

		cleanup_interval = strtoul(arg, NULL, 10);
		config->hashCleanupInterval = cleanup_interval;
		_dpd.logMsg("    Hash table cleanup interval: %d\n", config->hashCleanupInterval);
	}

	/* Parsing the tcp_stream_expire_interval option */
	if (( arg = (char*) strcasestr( args, "tcp_stream_expire_interval" ) ))
	{
		has_stream_expire_interval = true;

		for ( arg += strlen("tcp_stream_expire_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			_dpd.fatalMsg("AIPreproc: tcp_stream_expire_interval option used but "
				"no value specified\n");
		}

		stream_expire_interval = strtoul(arg, NULL, 10);
		config->streamExpireInterval = stream_expire_interval;
		_dpd.logMsg("    TCP stream expire interval: %d\n", config->streamExpireInterval);
	}

	/* Parsing the alert_clustering_interval option */
	if (( arg = (char*) strcasestr( args, "alert_clustering_interval" ) ))
	{
		for ( arg += strlen("alert_clustering_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			_dpd.fatalMsg("AIPreproc: alert_clustering_interval option used but "
				"no value specified\n");
		}

		alert_clustering_interval = strtoul(arg, NULL, 10);
		config->alertClusteringInterval = alert_clustering_interval;
		_dpd.logMsg("    Alert clustering interval: %d\n", config->alertClusteringInterval);
	}

	/* Parsing the database_parsing_interval option */
	if (( arg = (char*) strcasestr( args, "database_parsing_interval" ) ))
	{
		has_database_interval = true;

		for ( arg += strlen("database_parsing_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			_dpd.fatalMsg("AIPreproc: database_parsing_interval option used but "
				"no value specified\n");
		}

		database_parsing_interval = strtoul(arg, NULL, 10);
		config->databaseParsingInterval = database_parsing_interval;
		_dpd.logMsg("    Database parsing interval: %d\n", config->databaseParsingInterval);
	}

	/* Parsing the alertfile option */
	if (( arg = (char*) strcasestr( args, "alertfile" ) ))
	{
		for ( arg += strlen("alertfile");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			_dpd.fatalMsg("AIPreproc: alertfile option used but no filename specified\n");
		}

		for ( alertfile[ (++alertfile_len)-1 ] = *arg;
				*arg && *arg != '"' && alertfile_len < 1024;
				arg++, alertfile[ (++alertfile_len)-1 ] = *arg );

		if ( alertfile[0] == 0 || alertfile_len <= 1 )  {
			has_alertfile = false;
		} else {
			if ( alertfile_len >= 1024 )  {
				_dpd.fatalMsg("AIPreproc: alertfile path too long ( >= 1024 )\n");
			} else if ( strlen( alertfile ) == 0 ) {
				has_alertfile = false;
			} else {
				has_alertfile = true;
				alertparser_thread = AI_file_alertparser_thread;
				alertfile[ alertfile_len-1 ] = 0;
				strncpy ( config->alertfile, alertfile, alertfile_len );
				_dpd.logMsg("    alertfile path: %s\n", config->alertfile);
			}
		}
	}

	/* Parsing the clusterfile option */
	if (( arg = (char*) strcasestr( args, "clusterfile" ) ))
	{
		for ( arg += strlen("clusterfile");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			_dpd.fatalMsg("AIPreproc: clusterfile option used but no filename specified\n");
		}

		for ( clusterfile[ (++clusterfile_len)-1 ] = *arg;
				*arg && *arg != '"' && clusterfile_len < 1024;
				arg++, clusterfile[ (++clusterfile_len)-1 ] = *arg );

		if ( clusterfile[0] == 0 || clusterfile_len <= 1 )  {
			has_clusterfile = false;
		} else {
			if ( clusterfile_len >= 1024 )  {
				_dpd.fatalMsg("AIPreproc: clusterfile path too long ( >= 1024 )\n");
			} else if ( strlen( clusterfile ) == 0 ) {
				has_clusterfile = false;
			} else {
				has_clusterfile = true;
				clusterfile[ clusterfile_len-1 ] = 0;
				strncpy ( config->clusterfile, clusterfile, clusterfile_len );
				_dpd.logMsg("    clusterfile path: %s\n", config->clusterfile);
			}
		}
	}

	/* Parsing database option */
	if ( preg_match ( "\\s*database\\s*\\(\\s*([^\\)]+)\\)", args, &matches, &nmatches ) > 0 )
	{
		if ( ! has_database_log )
			has_database_log = true;

		match = strdup ( matches[0] );

		for ( i=0; i < nmatches; i++ )
			free ( matches[i] );

		free ( matches );
		matches = NULL;

		if ( preg_match ( "type\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			/* TODO Support other databases than MySQL */
			if ( strcasecmp ( matches[0], "mysql" ))
			{
				_dpd.fatalMsg ( "AIPreproc: Not supported database '%s' (supported types: mysql)\n", matches[0] );
			}

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "name\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->dbname, matches[0], sizeof ( config->dbname ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "user\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->dbuser, matches[0], sizeof ( config->dbuser ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "password\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->dbpass, matches[0], sizeof ( config->dbpass ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "host\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->dbhost, matches[0], sizeof ( config->dbhost ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		free ( match );

		if ( !strlen ( config->dbhost ) || !strlen ( config->dbname ) || !strlen ( config->dbpass ) || !strlen ( config->dbuser ))
		{
			_dpd.fatalMsg ( "AIPreproc: Database option used in config, but missing configuration option (all 'host', 'type', 'name', 'user', and 'password' option must be used)\n" );
		}
	}

	/* Parsing cluster options */
	while ( preg_match ( "\\s*(cluster\\s*\\(\\s*)([^\\)]+)\\)", args, &matches, &nmatches ) > 0 )
	{
		if ( ! has_clustering )
			has_clustering = true;

		memset ( label, 0, sizeof(label) );
		min_val = -1;
		max_val = -1;
		type    = none;

		match   = strdup ( matches[1] );
		offset  = (int) strcasestr ( args, matches[0] ) - (int) args;
		len     = strlen ( matches[0] );

		for ( i=0; i < nmatches; i++ )
			free ( matches[i] );

		free ( matches );
		matches = NULL;

		if ( preg_match ( "class\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			if ( !strcasecmp ( matches[0], "src_port" ))
				type = src_port;
			else if ( !strcasecmp ( matches[0], "dst_port" ))
				type = dst_port;
			else if ( !strcasecmp ( matches[0], "src_addr" ))
				type = src_addr;
			else if ( !strcasecmp ( matches[0], "dst_addr" ))
				type = dst_addr;
			else
				_dpd.fatalMsg ( "AIPreproc: Unknown class type in configuration: '%s'\n", matches[0] );

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );
			
			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "name\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			if ( strlen( matches[0] ) > sizeof(label) )
				_dpd.fatalMsg ( "AIPreproc: Label name too long in configuration: '%s' (maximum allowed length: %d)\n",
						matches[0], sizeof(label) );

			strncpy ( label, matches[0], sizeof(label) );

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "range\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			arg = strdup ( matches[0] );

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;

			switch ( type )
			{
				case src_port:
				case dst_port:
					if ( preg_match ( "^([0-9]+)-([0-9]+)$", arg, &matches, &nmatches ) > 0 )
					{
						min_val = strtoul ( matches[0], NULL, 10 );
						max_val = strtoul ( matches[1], NULL, 10 );

						if ( min_val > max_val )
						{
							_dpd.fatalMsg ( "AIPreproc: Parse error in configuration: '%s', minval > maxval\n", arg );
						}

						for ( i=0; i < nmatches; i++ )
							free ( matches[i] );
				
						free ( matches );
						matches = NULL;
					} else if ( preg_match ( "^([0-9]+)$", arg, &matches, &nmatches ) > 0 ) {
						min_val = strtoul ( matches[0], NULL, 10 );
						max_val = min_val;

						for ( i=0; i < nmatches; i++ )
							free ( matches[i] );
				
						free ( matches );
						matches = NULL;
					} else {
						_dpd.fatalMsg ( "AIPreproc: Unallowed format for a port range in configuration file: '%s'\n", arg );
					}

					break;

				case src_addr:
				case dst_addr:
					if ( preg_match ( "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/([0-9]{1,2})$", arg, &matches, &nmatches ) > 0 )
					{
						if (( min_val = inet_addr ( matches[0] )) == INADDR_NONE )
						{
							_dpd.fatalMsg ( "AIPreproc: Unallowed IPv4 format in configuration: '%s'\n", matches[0] );

							for ( i=0; i < nmatches; i++ )
								free ( matches[i] );

							free ( matches );
							matches = NULL;
						}

						netmask = strtoul ( matches[1], NULL, 10 );

						for ( i=0; i < nmatches; i++ )
							free ( matches[i] );

						free ( matches );
						matches = NULL;

						if ( netmask > 32 )
						{
							_dpd.fatalMsg ( "AIPreproc: The netmask number of bits should be in [0,32] in '%s'\n", arg );
						}

						netmask = 1 << (( 8*sizeof ( uint32_t )) - netmask );
						min_val = ntohl ( min_val ) & (~(netmask - 1));
						max_val = min_val | (netmask - 1);
					} else if ( preg_match ( "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})$", arg, &matches, &nmatches ) > 0 ) {
						if (( min_val = inet_addr ( matches[0] )) == INADDR_NONE )
						{
							_dpd.fatalMsg ( "AIPreproc: Unallowed IPv4 format in configuration: '%s'\n", matches[0] );

							for ( i=0; i < nmatches; i++ )
								free ( matches[i] );

							free ( matches );
							matches = NULL;
						}

						for ( i=0; i < nmatches; i++ )
							free ( matches[i] );

						free ( matches );
						matches = NULL;

						min_val = ntohl ( min_val );
						max_val = min_val;
					} else {
						_dpd.fatalMsg ( "AIPreproc: Invalid value for an IP address or a subnet in configuration: '%s'\n", arg );
					}

					break;

				/* TODO Manage ranges and clusters for timestamps (and more?) here */
				default:
					break;
			}

			if ( matches )
			{
				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			}

			if ( arg )
			{
				free ( arg );
				arg = NULL;
			}
		}

		for ( i=offset; i <= strlen(args); i++ )
			args[i] = args[ i+len ];

		if ( min_val == -1 || max_val == -1 || type == none || strlen ( label ) == 0 )
		{
			_dpd.fatalMsg ( "AIPreproc: Invalid cluster in configuration: '%s'\nAll of the following fields are required: class, range, name\n", match );
			free ( match );
			match = NULL;
		}

		if ( !( hierarchy_nodes = ( hierarchy_node** ) realloc ( hierarchy_nodes, (++n_hierarchy_nodes) * sizeof(hierarchy_node) )) )
		{
			_dpd.fatalMsg ( "Fatal dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			free ( match );
			match = NULL;
		}

		if ( !( hierarchy_nodes[ n_hierarchy_nodes - 1 ] = ( hierarchy_node* ) malloc ( sizeof(hierarchy_node) ) ))
		{
			_dpd.fatalMsg ( "Fatal dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			free ( match );
			match = NULL;
		}

		hierarchy_nodes[ n_hierarchy_nodes - 1 ]->type      =  type;
		hierarchy_nodes[ n_hierarchy_nodes - 1 ]->min_val   =  min_val;
		hierarchy_nodes[ n_hierarchy_nodes - 1 ]->max_val   =  max_val;
		hierarchy_nodes[ n_hierarchy_nodes - 1 ]->nchildren =  0;
		hierarchy_nodes[ n_hierarchy_nodes - 1 ]->children  =  NULL;
		hierarchy_nodes[ n_hierarchy_nodes - 1 ]->parent    =  NULL;

		strncpy ( hierarchy_nodes[ n_hierarchy_nodes - 1 ]->label,
				label,
				sizeof ( hierarchy_nodes[ n_hierarchy_nodes - 1 ]->label ));

		free ( match );
		match = NULL;
	}

	if ( ! has_cleanup_interval )
	{
		config->hashCleanupInterval = DEFAULT_HASH_CLEANUP_INTERVAL;
	}

	if ( ! has_stream_expire_interval )
	{
		config->streamExpireInterval = DEFAULT_STREAM_EXPIRE_INTERVAL;
	}

	if ( !has_database_interval && has_database_log )
	{
		config->databaseParsingInterval = DEFAULT_DATABASE_INTERVAL;
	}
	
	if ( !has_alertfile && !has_database_log )
	{
		strncpy ( config->alertfile, DEFAULT_ALERT_LOG_FILE, sizeof ( config->alertfile ));
		has_alertfile = true;
		alertparser_thread = AI_file_alertparser_thread;
	} else if ( has_database_log )  {
		has_alertfile = false;
		alertparser_thread = AI_mysql_alertparser_thread;
	} else if ( has_alertfile ) {
		alertparser_thread = AI_file_alertparser_thread;
	}

	if ( has_clustering )
	{
		if ( ! hierarchy_nodes )
		{
			_dpd.fatalMsg ( "AIPreproc: cluster file specified in the configuration but no clusters were specified\n" );
		}

		if ( ! has_clusterfile )
		{
			strncpy ( config->clusterfile, DEFAULT_CLUSTER_LOG_FILE, sizeof ( config->clusterfile ));
		}

		if ( ! alert_clustering_interval )
		{
			config->alertClusteringInterval = DEFAULT_ALERT_CLUSTERING_INTERVAL;
		}

		AI_hierarchies_build ( config, hierarchy_nodes, n_hierarchy_nodes );
	}

	if ( has_database_log )
	{
		get_alerts = AI_mysql_get_alerts;
	} else {
		get_alerts = AI_get_alerts;
	}

	return config;
} 		/* -----  end of function AI_config  ----- */


/**
 * \brief  Function executed every time the module receives a packet to be processed
 * \param  pkt 	void* pointer to the packet data
 * \param  context 	void* pointer to the context
 */

void AI_process(void *pkt, void *context)
{
	SFSnortPacket *p = (SFSnortPacket *) pkt;
	AI_config *config;

	sfPolicyUserPolicySet(ex_config, _dpd.getRuntimePolicy());
	config = (AI_config * ) sfPolicyUserDataGetCurrent (ex_config);

	if (config == NULL)
		return;

	if (!p->ip4_header || p->ip4_header->proto != IPPROTO_TCP || !p->tcp_header)
	{
		/* Not for me, return */
		return;
	}

	AI_pkt_enqueue ( pkt );
} 		/* -----  end of function AI_process  ----- */

#ifdef SNORT_RELOAD
static void AI_reload(char *args)
{
	AI_config *config;
	tSfPolicyId policy_id = _dpd.getParserPolicy();

	_dpd.logMsg("AI dynamic preprocessor configuration\n");

	if (ex_swap_config == NULL)
	{
		ex_swap_config = sfPolicyConfigCreate();
		if (ex_swap_config == NULL)
			_dpd.fatalMsg("Could not allocate configuration struct.\n");
	}

	config = AI_parse(args);
	sfPolicyUserPolicySet(ex_swap_config, policy_id);
	sfPolicyUserDataSetCurrent(ex_swap_config, config);

	/* Register the preprocessor function, Transport layer, ID 10000 */
	_dpd.addPreproc(AI_process, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

	DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: AI is initialized\n"););
}

static int AI_reloadSwapPolicyFree(tSfPolicyUserContextId config, tSfPolicyId policyId, void *data)
{
	AI_config *policy_config = (AI_config *)data;

	sfPolicyUserDataClear(config, policyId);
	free(policy_config);
	return 0;
}

static void * AI_reloadSwap(void)
{
	tSfPolicyUserContextId old_config = ex_config;

	if (ex_swap_config == NULL)
		return NULL;

	ex_config = ex_swap_config;
	ex_swap_config = NULL;

	return (void *)old_config;
}

static void AI_reloadSwapFree(void *data)
{
	tSfPolicyUserContextId config = (tSfPolicyUserContextId)data;

	if (data == NULL)
		return;

	sfPolicyUserDataIterate(config, AI_reloadSwapPolicyFree);
	sfPolicyConfigDelete(config);
}
#endif

/** @} */

