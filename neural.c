/*
 * =====================================================================================
 *
 *       Filename:  neural.c
 *
 *    Description:  Manage the alert correlation based on SOM neural network
 *
 *        Version:  0.1
 *        Created:  21/10/2010 08:51:28
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

/** \defgroup neural Module for the neural network-based alert correlation
 * @{ */

#ifdef 	HAVE_DB

#include	"db.h"
#include	"fsom.h"

#include	<alloca.h>
#include	<limits.h>
#include	<math.h>
#include	<sys/stat.h>
#include	<time.h>
#include	<unistd.h>

/** Enumeration for the input fields of the SOM neural network */
enum  { som_src_ip, som_dst_ip, som_src_port, som_dst_port, som_time, som_gid, som_sid, som_rev, SOM_NUM_ITEMS };

typedef struct  {
	unsigned int  gid;
	unsigned int  sid;
	unsigned int  rev;
	uint32_t      src_ip_addr;
	uint32_t      dst_ip_addr;
	uint16_t      src_port;
	uint16_t      dst_port;
	time_t        timestamp;
} AI_som_alert_tuple;

PRIVATE time_t latest_serialization_time  = ( time_t ) 0;
PRIVATE som_network_t *net                = NULL;
PRIVATE pthread_mutex_t neural_mutex;

/**
 * \brief  Get the current weight of the neural correlation index using a hyperbolic tangent function with a parameter expressed in function of the current number of alerts in the database
 * \return The weight of the correlation index ( 0 <= weight < 1 )
 */

double
AI_neural_correlation_weight ()
{
	DB_result res;
	DB_row    row;
	char      query[1024] = { 0 };
	double    x = 0,
			k = (double) config->alert_correlation_weight / HYPERBOLIC_TANGENT_SOLUTION;
	
	snprintf ( query, sizeof ( query ), "SELECT count(*) FROM %s", outdb_config[ALERTS_TABLE] );
	pthread_mutex_lock ( &outdb_mutex );

	if ( !DB_out_init() )
	{
		pthread_mutex_unlock ( &outdb_mutex );
		AI_fatal_err ( "Unable to connect to the database specified in module configuration", __FILE__, __LINE__ );
	}

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		pthread_mutex_unlock ( &outdb_mutex );
		return 0;
	}

	row = (DB_row) DB_fetch_row ( res );
	x = strtod ( row[0], NULL );
	DB_free_result ( res );
	pthread_mutex_unlock ( &outdb_mutex );

	return (( exp(x/k) - exp(-x/k) ) / ( exp(x/k) + exp(-x/k) ));
}		/* -----  end of function AI_neural_correlation_weight  ----- */

/**
 * \brief  Convert an alert row fetched from db to a vector suitable for being elaborated by the SOM neural network
 * \param  alert 	AI_som_alert_tuple object identifying the alert tuple
 * \param  data 	Reference to the vector that will contain the SOM data
 */

PRIVATE void
__AI_alert_to_som_data ( const AI_som_alert_tuple alert, double **input )
{
	(*input)[som_gid]      = (double) alert.gid / (double) USHRT_MAX;
	(*input)[som_sid]      = (double) alert.sid / (double) USHRT_MAX;
	(*input)[som_rev]      = (double) alert.rev / (double) USHRT_MAX;
	(*input)[som_time]     = (double) alert.timestamp / (double) INT_MAX;
	(*input)[som_src_ip]   = (double) alert.src_ip_addr / (double) UINT_MAX;
	(*input)[som_dst_ip]   = (double) alert.dst_ip_addr / (double) UINT_MAX;
	(*input)[som_src_port] = (double) alert.src_port / (double) USHRT_MAX;
	(*input)[som_dst_port] = (double) alert.dst_port / (double) USHRT_MAX;
}		/* -----  end of function __AI_alert_to_som_data  ----- */

/**
 * \brief  Get the distance between two alerts mapped on the SOM neural network
 * \param  alert1 	Tuple identifying the first alert
 * \param  alert2 	Tuple identifying the second alert
 * \return The distance between the alerts
 */

PRIVATE double
__AI_som_alert_distance ( const AI_som_alert_tuple alert1, const AI_som_alert_tuple alert2 )
{
	double *input1 = NULL,
		  *input2 = NULL;

	size_t x1 = 0,
		  y1 = 0,
		  x2 = 0,
		  y2 = 0;
	
	if ( !( input1 = (double*) alloca ( SOM_NUM_ITEMS * sizeof ( double ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	if ( !( input2 = (double*) alloca ( SOM_NUM_ITEMS * sizeof ( double ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	pthread_mutex_lock ( &neural_mutex );

	if ( !net )
	{
		pthread_mutex_unlock ( &neural_mutex );
		return 0.0;
	}

	__AI_alert_to_som_data ( alert1, &input1 );
	som_set_inputs ( net, input1 );
	som_get_best_neuron_coordinates ( net, &x1, &y1 );

	__AI_alert_to_som_data ( alert2, &input2 );
	som_set_inputs ( net, input2 );
	som_get_best_neuron_coordinates ( net, &x2, &y2 );

	pthread_mutex_unlock ( &neural_mutex );

	/* Return the normalized euclidean distance in [0,1] (the normalization is made considering that the maximum distance
	 * between two points on the output neurons matrix is the distance between the upper-left and bottom-right points) */
	return sqrt ((double) ( (x2-x1)*(x2-x1) + (y2-y1)*(y2-y1) )) /
		sqrt ((double) ( 2 * (config->outputNeuronsPerSide-1) * (config->outputNeuronsPerSide-1) ));
}		/* -----  end of function __AI_som_alert_distance  ----- */

/**
 * \brief  Get the SOM neural correlation between two alerts given as AI_snort_alert objects
 * \param  a 	First alert
 * \param  b 	Second alert
 * \return The correlation between a and b computed by the neural network
 */

double
AI_alert_neural_som_correlation ( const AI_snort_alert *a, const AI_snort_alert *b )
{
	size_t                 i = 0;
	unsigned long long int time_sum = 0;
	AI_som_alert_tuple     t1, t2;

	t1.gid = a->gid;
	t1.sid = a->sid;
	t1.rev = a->rev;
	t1.src_ip_addr = ntohl ( a->ip_src_addr );
	t1.dst_ip_addr = ntohl ( a->ip_dst_addr );
	t1.src_port = ntohs ( a->tcp_src_port );
	t1.dst_port = ntohs ( a->tcp_dst_port );
	time_sum = (unsigned long long int) a->timestamp;
	
	/* The timestamp of this alert is computed like the average timestamp of the grouped alerts */
	for ( i=1; i < a->grouped_alerts_count; i++ )
	{
		if ( a->grouped_alerts[i-1] )
		{
			time_sum += (unsigned long long int) a->grouped_alerts[i-1]->timestamp;
		}
	}

	t1.timestamp = (time_t) ( time_sum / a->grouped_alerts_count );

	t2.gid = b->gid;
	t2.sid = b->sid;
	t2.rev = b->rev;
	t2.src_ip_addr = ntohl ( b->ip_src_addr );
	t2.dst_ip_addr = ntohl ( b->ip_dst_addr );
	t2.src_port = ntohs ( b->tcp_src_port );
	t2.dst_port = ntohs ( b->tcp_dst_port );
	time_sum = (unsigned long long int) b->timestamp;
	
	for ( i=1; i < b->grouped_alerts_count; i++ )
	{
		if ( b->grouped_alerts[i-1] )
		{
			time_sum += (unsigned long long int) b->grouped_alerts[i-1]->timestamp;
		}
	}

	t2.timestamp = (time_t) ( time_sum / b->grouped_alerts_count );
	return __AI_som_alert_distance ( t1, t2 );
}		/* -----  end of function AI_alert_neural_som_correlation  ----- */

/**
 * \brief  Train the neural network taking the alerts from the latest serialization time
 */

PRIVATE void
__AI_som_train ()
{
	double    **inputs = NULL;

	char      query[1024] = { 0 };

	size_t    i = 0,
			num_rows = 0;

	DB_result res;
	DB_row    row;
	AI_som_alert_tuple   *tuples = NULL;

	pthread_mutex_lock ( &outdb_mutex );

	if ( !DB_out_init() )
	{
		pthread_mutex_unlock ( &outdb_mutex );
		AI_fatal_err ( "Unable to connect to the database specified in module configuration", __FILE__, __LINE__ );
	}

	#ifdef 	HAVE_LIBMYSQLCLIENT
	snprintf ( query, sizeof ( query ),
		"SELECT gid, sid, rev, unix_timestamp(timestamp), ip_src_addr, ip_dst_addr, tcp_src_port, tcp_dst_port "
		"FROM (%s a LEFT JOIN %s ip ON a.ip_hdr=ip.ip_hdr_id) LEFT JOIN %s tcp "
		"ON a.tcp_hdr=tcp.tcp_hdr_id "
		"WHERE unix_timestamp(timestamp) >= %lu",
		outdb_config[ALERTS_TABLE], outdb_config[IPV4_HEADERS_TABLE], outdb_config[TCP_HEADERS_TABLE],
		latest_serialization_time
	);
	#elif 	HAVE_LIBPQ
	snprintf ( query, sizeof ( query ),
		"SELECT gid, sid, rev, date_part('epoch', \"timestamp\"(timestamp)), ip_src_addr, ip_dst_addr, tcp_src_port, tcp_dst_port "
		"FROM (%s a LEFT JOIN %s ip ON a.ip_hdr=ip.ip_hdr_id) LEFT JOIN %s tcp "
		"ON a.tcp_hdr=tcp.tcp_hdr_id "
		"WHERE date_part ('epoch', \"timestamp\"(timestamp)) >= %lu",
		outdb_config[ALERTS_TABLE], outdb_config[IPV4_HEADERS_TABLE], outdb_config[TCP_HEADERS_TABLE],
		latest_serialization_time
	);
	#endif

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		pthread_mutex_unlock ( &outdb_mutex );
		return;
	}

	pthread_mutex_unlock ( &outdb_mutex );
	num_rows = DB_num_rows ( res );

	if ( num_rows == 0 )
	{
		DB_free_result ( res );
		latest_serialization_time = time ( NULL );
		return;
	}

	if ( !( inputs = (double**) alloca ( num_rows * sizeof ( double* ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	if ( !( tuples = (AI_som_alert_tuple*) alloca ( num_rows * sizeof ( AI_som_alert_tuple ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	for ( i=0; i < num_rows; i++ )
	{
		row = (DB_row) DB_fetch_row ( res );

		tuples[i].gid = row[0] ? strtoul ( row[0], NULL, 10 ) : 0;
		tuples[i].sid = row[1] ? strtoul ( row[1], NULL, 10 ) : 0;
		tuples[i].rev = row[2] ? strtoul ( row[2], NULL, 10 ) : 0;
		tuples[i].timestamp = row[3] ? (time_t) strtol ( row[3], NULL, 10 ) : (time_t) 0;
		tuples[i].src_ip_addr = row[4] ? ntohl ( inet_addr ( row[4] )) : 0;
		tuples[i].dst_ip_addr = row[5] ? ntohl ( inet_addr ( row[5] )) : 0;
		tuples[i].src_port = row[6] ? (uint16_t) strtoul ( row[6], NULL, 10 ) : 0;
		tuples[i].dst_port = row[7] ? (uint16_t) strtoul ( row[7], NULL, 10 ) : 0;

		if ( !( inputs[i] = (double*) alloca ( SOM_NUM_ITEMS * sizeof ( double ))))
		{
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
		}

		__AI_alert_to_som_data ( tuples[i], &inputs[i] );
	}

	DB_free_result ( res );
	pthread_mutex_lock ( &neural_mutex );

	if ( !net )
	{
		if ( !( net = som_network_new ( SOM_NUM_ITEMS, config->outputNeuronsPerSide, config->outputNeuronsPerSide )))
		{
			AI_fatal_err ( "AIPreproc: Could not create the neural network", __FILE__, __LINE__ );
		}

		som_init_weights ( net, inputs, num_rows );
		som_train ( net, inputs, num_rows, config->neural_train_steps );
	} else {
		som_train ( net, inputs, num_rows, config->neural_train_steps );
	}

	pthread_mutex_unlock ( &neural_mutex );

	latest_serialization_time = time ( NULL );
	net->serialization_time = latest_serialization_time;
	som_serialize ( net, config->netfile );
}		/* -----  end of function __AI_som_train  ----- */

/**
 * \brief  Thread for managing the self-organazing map (SOM) neural network for the alert correlation
 */

void*
AI_neural_thread ( void *arg )
{
	BOOL do_train = false;
	struct stat st;

	pthread_mutex_init ( &neural_mutex, NULL );

	if ( !config->netfile )
	{
		AI_fatal_err ( "AIPreproc: neural network thread launched but netfile option was not specified", __FILE__, __LINE__ );
	}

	if ( strlen ( config->netfile ) == 0 )
	{
		AI_fatal_err ( "AIPreproc: neural network thread launched but netfile option was not specified", __FILE__, __LINE__ );
	}

	while ( 1 )
	{
		if ( stat ( config->netfile, &st ) < 0 )
		{
			do_train = true;
		} else {
			if ( !( net = som_deserialize ( config->netfile )))
			{
				AI_fatal_err ( "AIPreproc: Error in deserializing the neural network from the network file", __FILE__, __LINE__ );
			}

			/* If more than N seconds passed from the latest serialization, re-train the neural network */
			if ( (int) ( time (NULL) - net->serialization_time ) > config->neuralNetworkTrainingInterval )
			{
				do_train = true;
			}
		}

		if ( do_train )
		{
			__AI_som_train();
		}

		sleep ( config->neuralNetworkTrainingInterval );
	}

	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function AI_neural_thread  ----- */

#endif

/** @} */

