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
#include "sf_preproc_info.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/** \defgroup spp_ai Main file for spp_ai module
 * @{ */

AI_snort_alert* (*get_alerts)(void);
AI_config *config = NULL;

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
 * \brief  Function called when the module experiences a fatal error
 * \param  msg 	Error message
 * \param  file 	File where the error occurred
 * \param  line 	Line number where the error occurred
 */

void
AI_fatal_err ( const char *msg, const char *file, const int line )
{
	_dpd.fatalMsg ( "%s: %s at %s:%d (%s)\n",
		PREPROC_NAME, msg, file, line,
		((errno != 0) ? strerror(errno) : ""));
}		/* -----  end of function AI_fatal_err  ----- */

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
	pthread_t  cleanup_thread,
			 logparse_thread,
			 webserv_thread,
			 neural_thread,
			 correlation_thread;

	tSfPolicyId policy_id = _dpd.getParserPolicy();

	_dpd.logMsg("AI dynamic preprocessor configuration\n");

	if (ex_config == NULL)
	{
		ex_config = sfPolicyConfigCreate();
		if (ex_config == NULL)
			AI_fatal_err ("Could not allocate configuration struct", __FILE__, __LINE__);
	}

	config = AI_parse(args);
	sfPolicyUserPolicySet(ex_config, policy_id);
	sfPolicyUserDataSetCurrent(ex_config, config);

	/* Initialize the extra correlation modules */
	AI_init_corr_modules();

	/* If the hash_cleanup_interval or stream_expire_interval options are set to zero,
	 * no cleanup will be made on the streams */
	if ( config->hashCleanupInterval != 0 && config->streamExpireInterval != 0 )
	{
		if ( pthread_create ( &cleanup_thread, NULL, AI_hashcleanup_thread, config ) != 0 )
		{
			AI_fatal_err ( "Failed to create the hash cleanup thread", __FILE__, __LINE__ );
		}
	}

	/* If the correlation_graph_interval option is set to zero, no correlation
	 * algorithm will be run over the alerts */
	if ( config->correlationGraphInterval != 0 )
	{
		if ( pthread_create ( &correlation_thread, NULL, AI_alert_correlation_thread, config ) != 0 )
		{
			AI_fatal_err ( "Failed to create the alert correlation thread", __FILE__, __LINE__ );
		}
	}

	if ( strlen ( config->alertfile ) > 0 )
	{
		if ( pthread_create ( &logparse_thread, NULL, alertparser_thread, config ) != 0 )
		{
			AI_fatal_err ( "Failed to create the alert parser thread", __FILE__, __LINE__ );
		}
	}

	/* If webserv_port is != 0, start the web server */
	if ( config->webserv_port != 0 )
	{
		if ( pthread_create ( &webserv_thread, NULL, AI_webserv_thread, NULL ) != 0 )
		{
			AI_fatal_err ( "Failed to create the web server thread", __FILE__, __LINE__ );
		}
	}

	/* If neural_network_training_interval != 0, start the thread for the neural network */
	if ( config->neuralNetworkTrainingInterval != 0 )
	{
		if ( pthread_create ( &neural_thread, NULL, AI_neural_thread, NULL ) != 0 )
		{
			AI_fatal_err ( "Failed to create the neural network thread", __FILE__, __LINE__ );
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
	char alertfile[1024]          = { 0 },
		alert_history_file[1024] = { 0 },
		clusterfile[1024]        = { 0 },
		corr_alerts_dir[1024]    = { 0 },
		corr_modules_dir[1024]   = { 0 },
		corr_rules_dir[1024]     = { 0 },
		webserv_dir[1024]        = { 0 },
		webserv_banner[1024]     = { 0 };

	char **matches       = NULL;
	int  nmatches        = 0;

	int      i;
	int      offset;
	int      len;
	double   corr_threshold_coefficient = DEFAULT_CORR_THRESHOLD;
	uint32_t netmask;

	int           min_val;
	int           max_val;
	char          label[256];
	cluster_type  type;

	hierarchy_node **hierarchy_nodes = NULL;
	int            n_hierarchy_nodes = 0;

	unsigned short webserv_port                         = 0;
	
	unsigned long  alertfile_len                        = 0,
			     alert_bufsize                        = 0,
			     alert_clustering_interval            = 0,
				alert_correlation_weight             = 0,
			     alert_history_file_len               = 0,
			     alert_serialization_interval         = 0,
			     bayesian_correlation_cache_validity  = 0,
			     bayesian_correlation_interval        = 0,
				cleanup_interval                     = 0,
			     clusterfile_len                      = 0,
			     cluster_max_alert_interval           = 0,
			     corr_alerts_dir_len                  = 0,
				corr_modules_dir_len                 = 0,
			     corr_rules_dir_len                   = 0,
			     correlation_graph_interval           = 0,
			     database_parsing_interval            = 0,
				manual_correlations_parsing_interval = 0,
				neural_network_training_interval     = 0,
				neural_train_steps                   = 0,
				output_neurons_per_side              = 0,
			     stream_expire_interval               = 0,
				webserv_banner_len                   = 0,
				webserv_dir_len                      = 0;

	BOOL has_cleanup_interval        = false,
		has_stream_expire_interval  = false,
		has_correlation_interval    = false,
		has_corr_alerts_dir         = false,
		has_corr_modules_dir        = false,
		has_database_interval       = false,
		has_webserv_dir             = false,
		has_webserv_banner          = false,
		has_alertfile               = false,
		has_clusterfile             = false,
		has_corr_rules_dir          = false,
		has_clustering              = false,
		has_database_log            = false,
		has_database_output         = false,
		has_alert_history_file      = false;

	if ( !( config = ( AI_config* ) malloc ( sizeof( AI_config )) ))
		AI_fatal_err( "Could not allocate configuration struct", __FILE__, __LINE__ );
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
			AI_fatal_err ( "Hashtable_cleanup_interval option used but "
				"no value specified", __FILE__, __LINE__ );
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
			AI_fatal_err( "tcp_stream_expire_interval option used but "
				"no value specified", __FILE__, __LINE__ );
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
			AI_fatal_err ( "alert_clustering_interval option used but "
				"no value specified", __FILE__, __LINE__ );
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
			AI_fatal_err ( "database_parsing_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		database_parsing_interval = strtoul(arg, NULL, 10);
		config->databaseParsingInterval = database_parsing_interval;
		_dpd.logMsg("    Database parsing interval: %d\n", config->databaseParsingInterval);
	}

	/* Parsing the correlation_graph_interval option */
	if (( arg = (char*) strcasestr( args, "correlation_graph_interval" ) ))
	{
		has_correlation_interval = true;

		for ( arg += strlen("correlation_graph_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "correlation_graph_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		correlation_graph_interval = strtoul(arg, NULL, 10);
		config->correlationGraphInterval = correlation_graph_interval;
		_dpd.logMsg("    Correlation graph thread interval: %d\n", config->correlationGraphInterval);
	}

	/* Parsing the alert_serialization_interval option */
	if (( arg = (char*) strcasestr( args, "alert_serialization_interval" ) ))
	{
		for ( arg += strlen("alert_serialization_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "alert_serialization_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		alert_serialization_interval = strtoul(arg, NULL, 10);
		config->alertSerializationInterval = alert_serialization_interval;
		_dpd.logMsg("    Alert serialization thread interval: %d\n", config->correlationGraphInterval);
	}

	/* Parsing the alert_bufsize option */
	if (( arg = (char*) strcasestr( args, "alert_bufsize" ) ))
	{
		for ( arg += strlen("alert_bufsize");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err( "alert_bufsize option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		alert_bufsize = strtoul(arg, NULL, 10);
		config->alert_bufsize= alert_bufsize;
		_dpd.logMsg("    Alert buffer size: %d\n", config->alert_bufsize );
	}

	/* Parsing the webserv_port option */
	if (( arg = (char*) strcasestr( args, "webserv_port" ) ))
	{
		for ( arg += strlen("webserv_port");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err( "webserv_port option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		webserv_port = (unsigned short) strtoul(arg, NULL, 10);
		config->webserv_port= webserv_port;
	} else {
		config->webserv_port = DEFAULT_WEBSERV_PORT;
	}

	_dpd.logMsg("    Web server port: %d\n", config->webserv_port );

	/* Parsing the correlation_threshold_coefficient option */
	if (( arg = (char*) strcasestr( args, "correlation_threshold_coefficient" ) ))
	{
		for ( arg += strlen("correlation_threshold_coefficient");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err( "correlation_threshold_coefficient option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		corr_threshold_coefficient = strtod ( arg, NULL );
	}

	config->correlationThresholdCoefficient = corr_threshold_coefficient;
	_dpd.logMsg( "    Correlation threshold coefficient: %f\n", corr_threshold_coefficient );

	/* Parsing the bayesian_correlation_interval option */
	if (( arg = (char*) strcasestr( args, "bayesian_correlation_interval" ) ))
	{
		for ( arg += strlen("bayesian_correlation_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "bayesian_correlation_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		bayesian_correlation_interval = strtoul ( arg, NULL, 10 );
		config->bayesianCorrelationInterval = bayesian_correlation_interval;
	} else {
		bayesian_correlation_interval = DEFAULT_BAYESIAN_CORRELATION_INTERVAL;
	}

	config->bayesianCorrelationInterval = bayesian_correlation_interval;
	_dpd.logMsg( "    Bayesian correlation interval: %u\n", config->bayesianCorrelationInterval );

	/* Parsing the manual_correlations_parsing_interval option */
	if (( arg = (char*) strcasestr( args, "manual_correlations_parsing_interval" ) ))
	{
		for ( arg += strlen("manual_correlations_parsing_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "manual_correlations_parsing_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		manual_correlations_parsing_interval = strtoul ( arg, NULL, 10 );
	} else {
		manual_correlations_parsing_interval = DEFAULT_MANUAL_CORRELATIONS_PARSING_INTERVAL;
	}

	config->manualCorrelationsParsingInterval = manual_correlations_parsing_interval;
	_dpd.logMsg( "    Manual correlations parsing interval: %u\n", config->manualCorrelationsParsingInterval );

	/* Parsing the bayesian_correlation_cache_validity option */
	if (( arg = (char*) strcasestr( args, "bayesian_correlation_cache_validity" ) ))
	{
		for ( arg += strlen("bayesian_correlation_cache_validity");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "bayesian_correlation_cache_validity option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		bayesian_correlation_cache_validity = strtoul ( arg, NULL, 10 );
		config->bayesianCorrelationCacheValidity = bayesian_correlation_cache_validity;
	} else {
		bayesian_correlation_cache_validity = DEFAULT_BAYESIAN_CORRELATION_CACHE_VALIDITY;
	}

	config->bayesianCorrelationCacheValidity = bayesian_correlation_cache_validity;
	_dpd.logMsg( "    Bayesian cache validity interval: %u\n", config->bayesianCorrelationCacheValidity );


	/* Parsing the cluster_max_alert_interval option */
	if (( arg = (char*) strcasestr( args, "cluster_max_alert_interval" ) ))
	{
		for ( arg += strlen("cluster_max_alert_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "cluster_max_alert_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		cluster_max_alert_interval = strtoul ( arg, NULL, 10 );
	} else {
		cluster_max_alert_interval = DEFAULT_CLUSTER_MAX_ALERT_INTERVAL;
	}

	config->clusterMaxAlertInterval = cluster_max_alert_interval;
	_dpd.logMsg( "    Cluster alert max interval: %u\n", config->clusterMaxAlertInterval );

	/* Parsing the neural_network_training_interval option */
	if (( arg = (char*) strcasestr( args, "neural_network_training_interval" ) ))
	{
		for ( arg += strlen("neural_network_training_interval");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "neural_network_training_interval option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		neural_network_training_interval = strtoul ( arg, NULL, 10 );
	} else {
		neural_network_training_interval = DEFAULT_NEURAL_NETWORK_TRAINING_INTERVAL;
	}

	config->neuralNetworkTrainingInterval = neural_network_training_interval;
	_dpd.logMsg( "    Neural network training interval: %u\n", config->neuralNetworkTrainingInterval );

	/* Parsing the output_neurons_per_side option */
	if (( arg = (char*) strcasestr( args, "output_neurons_per_side" ) ))
	{
		for ( arg += strlen("output_neurons_per_side");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "output_neurons_per_side option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		output_neurons_per_side = strtoul ( arg, NULL, 10 );
	} else {
		output_neurons_per_side = DEFAULT_OUTPUT_NEURONS_PER_SIDE;
	}

	config->outputNeuronsPerSide = output_neurons_per_side;
	_dpd.logMsg( "    Output neurons per side: %u\n", config->outputNeuronsPerSide );

	/* Parsing the neural_train_steps option */
	if (( arg = (char*) strcasestr( args, "neural_train_steps" ) ))
	{
		for ( arg += strlen("neural_train_steps");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "neural_train_steps option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		neural_train_steps = strtoul ( arg, NULL, 10 );
	} else {
		neural_train_steps = DEFAULT_NEURAL_TRAIN_STEPS;
	}

	config->neural_train_steps = neural_train_steps;
	_dpd.logMsg( "    Neural train steps: %u\n", config->neural_train_steps );

	/* Parsing the alert_correlation_weight option */
	if (( arg = (char*) strcasestr( args, "alert_correlation_weight" ) ))
	{
		for ( arg += strlen("alert_correlation_weight");
				*arg && (*arg < '0' || *arg > '9');
				arg++ );

		if ( !(*arg) )
		{
			AI_fatal_err ( "alert_correlation_weight option used but "
				"no value specified", __FILE__, __LINE__ );
		}

		alert_correlation_weight = strtoul ( arg, NULL, 10 );
	} else {
		alert_correlation_weight = DEFAULT_ALERT_CORRELATION_WEIGHT;
	}

	config->alert_correlation_weight = alert_correlation_weight;
	_dpd.logMsg( "    Alert correlation weight: %u\n", config->alert_correlation_weight );

	/* Parsing the alertfile option */
	if (( arg = (char*) strcasestr( args, "alertfile" ) ))
	{
		for ( arg += strlen("alertfile");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "alertfile option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( alertfile[ (++alertfile_len)-1 ] = *arg;
				*arg && *arg != '"' && alertfile_len < 1024;
				arg++, alertfile[ (++alertfile_len)-1 ] = *arg );

		if ( alertfile[0] == 0 || alertfile_len <= 1 )  {
			has_alertfile = false;
		} else {
			if ( alertfile_len >= 1024 )  {
				AI_fatal_err ( "alertfile path too long ( >= 1024 )", __FILE__, __LINE__ );
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

	/* Parsing the alert_history_file option */
	if (( arg = (char*) strcasestr( args, "alert_history_file" ) ))
	{
		for ( arg += strlen("alert_history_file");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "alert_history_file option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( alert_history_file[ (++alert_history_file_len)-1 ] = *arg;
				*arg && *arg != '"' && alert_history_file_len < 1024;
				arg++, alert_history_file[ (++alert_history_file_len)-1 ] = *arg );

		if ( alert_history_file[0] == 0 || alert_history_file_len <= 1 )  {
			has_alert_history_file = false;
		} else {
			if ( alert_history_file_len >= 1024 )  {
				AI_fatal_err ( "alert_history_file path too long ( >= 1024 )", __FILE__, __LINE__ );
			} else if ( strlen( alert_history_file ) == 0 ) {
				has_alert_history_file = false;
			} else {
				has_alert_history_file = true;
				alert_history_file [ alert_history_file_len-1 ] = 0;
				strncpy ( config->alert_history_file, alert_history_file, alert_history_file_len );
				_dpd.logMsg("    alert_history_file path: %s\n", config->alert_history_file);
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
			AI_fatal_err ( "clusterfile option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( clusterfile[ (++clusterfile_len)-1 ] = *arg;
				*arg && *arg != '"' && clusterfile_len < 1024;
				arg++, clusterfile[ (++clusterfile_len)-1 ] = *arg );

		if ( clusterfile[0] == 0 || clusterfile_len <= 1 )  {
			has_clusterfile = false;
		} else {
			if ( clusterfile_len >= 1024 )  {
				AI_fatal_err ( "clusterfile path too long ( >= 1024 )", __FILE__, __LINE__ );
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

	/* Parsing the correlation_rules_dir option */
	if (( arg = (char*) strcasestr( args, "correlation_rules_dir" ) ))
	{
		for ( arg += strlen("correlation_rules_dir");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "correlation_rules_dir option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( corr_rules_dir[ (++corr_rules_dir_len)-1 ] = *arg;
				*arg && *arg != '"' && corr_rules_dir_len < 1024;
				arg++, corr_rules_dir[ (++corr_rules_dir_len)-1 ] = *arg );

		if ( corr_rules_dir[0] == 0 || corr_rules_dir_len <= 1 )  {
			has_corr_rules_dir = false;
		} else {
			if ( corr_rules_dir_len >= 1024 )  {
				AI_fatal_err ( "corr_rules_dir path too long ( >= 1024 )", __FILE__, __LINE__ );
			} else if ( strlen( corr_rules_dir ) == 0 ) {
				has_corr_rules_dir = false;
			} else {
				has_corr_rules_dir = true;
				corr_rules_dir[ corr_rules_dir_len-1 ] = 0;
				strncpy ( config->corr_rules_dir, corr_rules_dir, corr_rules_dir_len );
				_dpd.logMsg("    corr_rules_dir path: %s\n", config->corr_rules_dir);
			}
		}
	}

	/* Parsing the correlated_alerts_dir option */
	if (( arg = (char*) strcasestr( args, "correlated_alerts_dir" ) ))
	{
		for ( arg += strlen("correlated_alerts_dir");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "correlated_alerts_dir option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( corr_alerts_dir[ (++corr_alerts_dir_len)-1 ] = *arg;
				*arg && *arg != '"' && corr_alerts_dir_len < 1024;
				arg++, corr_alerts_dir[ (++corr_alerts_dir_len)-1 ] = *arg );

		if ( corr_alerts_dir[0] == 0 || corr_alerts_dir_len <= 1 )  {
			has_corr_alerts_dir = false;
		} else {
			if ( corr_alerts_dir_len >= 1024 )  {
				AI_fatal_err ( "correlated_alerts_dir path too long ( >= 1024 )", __FILE__, __LINE__ );
			} else if ( strlen( corr_alerts_dir ) == 0 ) {
				has_corr_alerts_dir = false;
			} else {
				has_corr_alerts_dir = true;
				corr_alerts_dir[ corr_alerts_dir_len-1 ] = 0;
				strncpy ( config->corr_alerts_dir, corr_alerts_dir, corr_alerts_dir_len );
				_dpd.logMsg("    correlated_alerts_dir: %s\n", config->corr_alerts_dir);
			}
		}
	}

	/* Parsing the webserv_dir option */
	if (( arg = (char*) strcasestr( args, "webserv_dir" ) ))
	{
		for ( arg += strlen("webserv_dir");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "webserv_dir option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( webserv_dir[ (++webserv_dir_len)-1 ] = *arg;
				*arg && *arg != '"' && webserv_dir_len < sizeof ( webserv_dir );
				arg++, webserv_dir[ (++webserv_dir_len)-1 ] = *arg );

		if ( webserv_dir[0] == 0 || webserv_dir_len <= 1 )  {
			has_webserv_dir = false;
		} else {
			if ( webserv_dir_len >= sizeof ( webserv_dir ))  {
				AI_fatal_err ( "webserv_dir path too long ( >= 1024 )", __FILE__, __LINE__ );
			} else if ( strlen( webserv_dir ) == 0 ) {
				has_webserv_dir = false;
			} else {
				has_webserv_dir = true;
				webserv_dir[ webserv_dir_len-1 ] = 0;
				strncpy ( config->webserv_dir, webserv_dir, webserv_dir_len );
			}
		}
	}

	if ( ! has_webserv_dir )
	{
		#ifndef HAVE_CONFIG_H
			AI_fatal_err ( "Unable to read PREFIX from config.h", __FILE__, __LINE__  );
		#endif

		snprintf ( config->webserv_dir, sizeof ( config->webserv_dir ), "%s/share/snort_ai_preprocessor/htdocs", PREFIX );
	}

	/* Remove unnecessary '/' at the end of the web server directory */
	for ( i = strlen ( config->webserv_dir ) - 1; i >= 0 && config->webserv_dir[i] == '/'; i-- )
		config->webserv_dir[i] = 0;

	_dpd.logMsg("    webserv_dir: %s\n", config->webserv_dir);

	/* Parsing the corr_modules_dir option */
	if (( arg = (char*) strcasestr( args, "corr_modules_dir" ) ))
	{
		for ( arg += strlen("corr_modules_dir");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "corr_modules_dir option used but no filename specified", __FILE__, __LINE__ );
		}

		for ( corr_modules_dir[ (++corr_modules_dir_len)-1 ] = *arg;
				*arg && *arg != '"' && corr_modules_dir_len < sizeof ( corr_modules_dir );
				arg++, corr_modules_dir[ (++corr_modules_dir_len)-1 ] = *arg );

		if ( corr_modules_dir[0] == 0 || corr_modules_dir_len <= 1 )  {
			has_corr_modules_dir = false;
		} else {
			if ( corr_modules_dir_len >= sizeof ( corr_modules_dir ))  {
				AI_fatal_err ( "corr_modules_dir path too long ( >= 1024 )", __FILE__, __LINE__ );
			} else if ( strlen( corr_modules_dir ) == 0 ) {
				has_corr_modules_dir = false;
			} else {
				has_corr_modules_dir = true;
				corr_modules_dir[ corr_modules_dir_len-1 ] = 0;
				strncpy ( config->corr_modules_dir, corr_modules_dir, corr_modules_dir_len );
			}
		}
	}

	if ( ! has_corr_modules_dir )
	{
		#ifndef HAVE_CONFIG_H
			AI_fatal_err ( "Unable to read PREFIX from config.h", __FILE__, __LINE__  );
		#endif

		snprintf ( config->corr_modules_dir, sizeof ( config->corr_modules_dir ), "%s/share/snort_ai_preprocessor/corr_modules", PREFIX );
	}

	/* Neural network output file */
	if ( config->neuralNetworkTrainingInterval != 0 )
	{
		#ifndef HAVE_DB
			AI_fatal_err ( "Neural network based correlation support set but the module was compiled with no database support "
					"(recompile the module with database support or set the neural_network_training_interval option in snort.conf to 0",
					__FILE__, __LINE__ );
		#endif

		#ifndef HAVE_CONFIG_H
			AI_fatal_err ( "Unable to read PREFIX from config.h", __FILE__, __LINE__  );
		#endif

		snprintf ( config->netfile, sizeof ( config->netfile ), "%s/share/snort_ai_preprocessor/som.dat", PREFIX );
	}

	/* Parsing the webserv_banner option */
	if (( arg = (char*) strcasestr( args, "webserv_banner" ) ))
	{
		for ( arg += strlen("webserv_banner");
				*arg && *arg != '"';
				arg++ );

		if ( !(*(arg++)) )
		{
			AI_fatal_err ( "webserv_banner option used but no value specified", __FILE__, __LINE__ );
		}

		for ( webserv_banner[ (++webserv_banner_len)-1 ] = *arg;
				*arg && *arg != '"' && webserv_banner_len < sizeof ( webserv_banner );
				arg++, webserv_banner[ (++webserv_banner_len)-1 ] = *arg );

		if ( webserv_banner[0] == 0 || webserv_banner_len <= 1 )  {
			has_webserv_banner = false;
		} else {
			if ( webserv_banner_len >= sizeof ( webserv_banner ))  {
				AI_fatal_err ( "webserv_banner path too long ( >= 1024 )", __FILE__, __LINE__ );
			} else if ( strlen( webserv_banner ) == 0 ) {
				has_webserv_banner = false;
			} else {
				has_webserv_banner = true;
				webserv_banner[ webserv_banner_len-1 ] = 0;
				strncpy ( config->webserv_banner, webserv_banner, webserv_banner_len );
			}
		}
	}

	if ( ! has_webserv_banner )
	{
		strncpy ( config->webserv_banner, DEFAULT_WEBSERV_BANNER, webserv_banner_len );
	}

	_dpd.logMsg("    webserv_banner: %s\n", config->webserv_banner);

	/* Parsing database option */
	if ( preg_match ( "\\s+database\\s*\\(\\s*([^\\)]+)\\)", args, &matches, &nmatches ) > 0 )
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
			if ( strcasecmp ( matches[0], "mysql" ) && strcasecmp ( matches[0], "postgresql" ))
			{
				AI_fatal_err ( "Not supported database type in configuration (supported types: mysql, postgresql)", __FILE__, __LINE__ );
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

		if ( !strlen ( config->dbname ))
		{
			AI_fatal_err ( "Database option used in config, but missing configuration option (at least 'type' and 'name' options must be used)", __FILE__, __LINE__  );
		}

		_dpd.logMsg("    Reading alerts from the database %s\n", config->dbname );
	}

	/* Parsing output_database option */
	config->outdbtype = outdb_none;

	if ( preg_match ( "\\s*output_database\\s*\\(\\s*([^\\)]+)\\)", args, &matches, &nmatches ) > 0 )
	{
		if ( ! has_database_output )
			has_database_output = true;

		match = strdup ( matches[0] );

		for ( i=0; i < nmatches; i++ )
			free ( matches[i] );

		free ( matches );
		matches = NULL;

		if ( preg_match ( "type\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			if ( !strcasecmp ( matches[0], "mysql" ))
			{
				#ifndef HAVE_LIBMYSQLCLIENT
					AI_fatal_err ( "mysql output set in 'output_database' option but the module was not compiled through --with-mysql option", __FILE__, __LINE__  );
				#else
					config->outdbtype = outdb_mysql;
				#endif
			} else if ( !strcasecmp ( matches[0], "postgresql" )) {
				#ifndef HAVE_LIBPQ
					AI_fatal_err ( "postgresql output set in 'output_database' option but the module was not compiled through --with-postgresql option", __FILE__, __LINE__  );
				#else
					config->outdbtype = outdb_postgresql;
				#endif
			} else {
				AI_fatal_err ( "Not supported database in configuration (supported types: mysql, postgresql)", __FILE__, __LINE__  );
			}

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "name\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->outdbname, matches[0], sizeof ( config->outdbname ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "user\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->outdbuser, matches[0], sizeof ( config->outdbuser ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "password\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->outdbpass, matches[0], sizeof ( config->outdbpass ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "host\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			strncpy ( config->outdbhost, matches[0], sizeof ( config->outdbhost ));

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );

			free ( matches );
			matches = NULL;
		}

		free ( match );

		if ( !strlen ( config->outdbname ))
		{
			AI_fatal_err ( "Output database option used in config, but missing configuration option (at least 'type' and 'name' options must be used)", __FILE__, __LINE__  );
		}

		AI_outdb_mutex_initialize();
		_dpd.logMsg("    Saving output alerts to the database %s\n", config->outdbname );
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
				AI_fatal_err ( "Unknown class type in configuration", __FILE__, __LINE__  );

			for ( i=0; i < nmatches; i++ )
				free ( matches[i] );
			
			free ( matches );
			matches = NULL;
		}

		if ( preg_match ( "name\\s*=\\s*\"([^\"]+)\"", match, &matches, &nmatches ) > 0 )
		{
			if ( strlen( matches[0] ) > sizeof(label) )
				AI_fatal_err ( "Label name too long in configuration", __FILE__, __LINE__  );

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
							AI_fatal_err ( "Parse error in configuration: minval > maxval", __FILE__, __LINE__ );
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
						AI_fatal_err ( "Unallowed format for a port range in configuration file", __FILE__, __LINE__ );
					}

					break;

				case src_addr:
				case dst_addr:
					if ( preg_match ( "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/([0-9]{1,2})$", arg, &matches, &nmatches ) > 0 )
					{
						if (( min_val = inet_addr ( matches[0] )) == INADDR_NONE )
						{
							AI_fatal_err ( "Unallowed IPv4 format in configuration", __FILE__, __LINE__ );

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
							AI_fatal_err ( "The netmask number of bits should be in [0,32] in configuration file", __FILE__, __LINE__ );
						}

						netmask = 1 << (( 8*sizeof ( uint32_t )) - netmask );
						min_val = ntohl ( min_val ) & (~(netmask - 1));
						max_val = min_val | (netmask - 1);
					} else if ( preg_match ( "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})$", arg, &matches, &nmatches ) > 0 ) {
						if (( min_val = inet_addr ( matches[0] )) == INADDR_NONE )
						{
							AI_fatal_err ( "Unallowed IPv4 format in configuration", __FILE__, __LINE__ );

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
						AI_fatal_err ( "Invalid value for an IP address or a subnet in configuration", __FILE__, __LINE__ );
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
			AI_fatal_err ( "Invalid cluster in configuration\nAll of the following fields are required: class, range, name", __FILE__, __LINE__ );
			free ( match );
			match = NULL;
		}

		if ( !( hierarchy_nodes = ( hierarchy_node** ) realloc ( hierarchy_nodes, (++n_hierarchy_nodes) * sizeof(hierarchy_node) )) )
		{
			AI_fatal_err ( "Fatal dynamic memory allocation failure", __FILE__, __LINE__ );
			free ( match );
			match = NULL;
		}

		if ( !( hierarchy_nodes[ n_hierarchy_nodes - 1 ] = ( hierarchy_node* ) malloc ( sizeof(hierarchy_node) ) ))
		{
			AI_fatal_err ( "Fatal dynamic memory allocation failure", __FILE__, __LINE__ );
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

	if ( ! has_correlation_interval )
	{
		config->correlationGraphInterval = DEFAULT_ALERT_CORRELATION_INTERVAL;
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

		#ifdef 	HAVE_DB
			alertparser_thread = AI_db_alertparser_thread;
		#else
			AI_fatal_err ( "Database logging enabled in config file, but the module was not compiled "
					"with database support (recompile, i.e., with ./configure --with-mysql or --with-postgresql)", __FILE__, __LINE__  );
		#endif
	} else if ( has_alertfile ) {
		alertparser_thread = AI_file_alertparser_thread;
	}

	if ( !has_alert_history_file )
	{
		strncpy ( config->alert_history_file, DEFAULT_ALERT_HISTORY_FILE, sizeof ( config->alert_history_file ));
		has_alert_history_file = true;
	}

	if ( has_clustering )
	{
		if ( ! hierarchy_nodes )
		{
			AI_fatal_err ( "Cluster file specified in the configuration but no clusters were specified", __FILE__, __LINE__  );
		}

		if ( ! has_clusterfile )
		{
			strncpy ( config->clusterfile, DEFAULT_CLUSTER_LOG_FILE, sizeof ( config->clusterfile ));
		}

		if ( ! alert_clustering_interval )
		{
			config->alertClusteringInterval = DEFAULT_ALERT_CLUSTERING_INTERVAL;
		}

		AI_hierarchies_build ( hierarchy_nodes, n_hierarchy_nodes );
	}

	if ( ! has_corr_rules_dir )
	{
		#ifndef HAVE_CONFIG_H
			AI_fatal_err ( "Unable to read PREFIX from config.h", __FILE__, __LINE__  );
		#endif

		if ( !strcmp ( PREFIX, "/usr" ) || !strcmp ( PREFIX, "/usr/" ))
		{
			strncpy ( config->corr_rules_dir, DEFAULT_CORR_RULES_DIR, sizeof ( DEFAULT_CORR_RULES_DIR ));
		} else {
			snprintf ( config->corr_rules_dir, sizeof ( config->corr_rules_dir ), "%s/etc/corr_rules", PREFIX );
		}
	}

	_dpd.logMsg ( "    Using correlation rules from directory %s\n", config->corr_rules_dir );

	if ( ! has_corr_alerts_dir )
	{
		strncpy ( config->corr_alerts_dir, DEFAULT_CORR_ALERTS_DIR, sizeof ( DEFAULT_CORR_ALERTS_DIR ));
	}

	if ( ! alert_serialization_interval )
	{
		config->alertSerializationInterval = DEFAULT_ALERT_SERIALIZATION_INTERVAL;
	}

	if ( ! alert_bufsize )
	{
		config->alert_bufsize = DEFAULT_ALERT_BUFSIZE;
	}

	_dpd.logMsg ( "    Saving correlated alerts information in %s\n", config->corr_alerts_dir );

	if ( has_database_log )
	{
		#ifdef 	HAVE_DB
			get_alerts = AI_db_get_alerts;
		#else
			AI_fatal_err ( "Using database alert log, but the module was not compiled with database support", __FILE__, __LINE__ );
		#endif
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
	AI_config *_config;

	sfPolicyUserPolicySet(ex_config, _dpd.getRuntimePolicy());
	_config = (AI_config * ) sfPolicyUserDataGetCurrent (ex_config);

	if (_config == NULL)
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
	/* AI_config *config; */
	tSfPolicyId policy_id = _dpd.getParserPolicy();

	_dpd.logMsg("AI dynamic preprocessor configuration\n");

	if (ex_swap_config == NULL)
	{
		ex_swap_config = sfPolicyConfigCreate();
		if (ex_swap_config == NULL)
			AI_fatal_err ( "Could not allocate configuration struct", __FILE__, __LINE__ );
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

