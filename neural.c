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
#include	<pthread.h>
#include	<stdio.h>
#include	<sys/stat.h>
#include	<time.h>
#include	<unistd.h>

enum  { som_src_ip, som_dst_ip, som_src_port, som_dst_port, som_time, som_alert_id, SOM_NUM_ITEMS };

PRIVATE time_t latest_serialization_time = ( time_t ) 0;
PRIVATE som_network_t *net = NULL;

/**
 * \brief  Train the neural network taking the alerts from the latest serialization time
 */

PRIVATE void
AI_som_train ()
{
	unsigned long snort_id = 0;
	double    **inputs;
	char      query[1024]          = { 0 };
	size_t    i        = 0,
			num_rows = 0;
	DB_result res;
	DB_row    row;

	if ( !DB_out_init() )
	{
		AI_fatal_err ( "Unable to connect to the database specified in module configuration", __FILE__, __LINE__ );
	}

	#ifdef 	HAVE_LIBMYSQLCLIENT
	snprintf ( query, sizeof ( query ),
		"SELECT gid, sid, rev, timestamp, ip_src_addr, ip_dst_addr, tcp_src_port, tcp_dst_port "
		"FROM %s a JOIN %s ip JOIN %s tcp "
		"ON a.ip_hdr=ip.ip_hdr_id AND a.tcp_hdr=tcp.tcp_hdr_id "
		"WHERE unix_timestamp(timestamp) > %lu",
		outdb_config[ALERTS_TABLE], outdb_config[IPV4_HEADERS_TABLE], outdb_config[TCP_HEADERS_TABLE],
		latest_serialization_time
	);
	#elif 	HAVE_LIBPQ
	snprintf ( query, sizeof ( query ),
		"SELECT gid, sid, rev, timestamp, ip_src_addr, ip_dst_addr, tcp_src_port, tcp_dst_port "
		"FROM %s a JOIN %s ip JOIN %s tcp "
		"ON a.ip_hdr=ip.ip_hdr_id AND a.tcp_hdr=tcp.tcp_hdr_id "
		"WHERE date_part ('epoch', \"timestamp\"(timestamp)) > %lu",
		outdb_config[ALERTS_TABLE], outdb_config[IPV4_HEADERS_TABLE], outdb_config[TCP_HEADERS_TABLE],
		latest_serialization_time
	);
	#endif

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		AI_fatal_err ( "AIPreproc: Query error", __FILE__, __LINE__ );
	}

	num_rows = DB_out_num_rows();

	if ( !( inputs = (double**) alloca ( num_rows * sizeof ( double* ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	for ( i=0; i < num_rows; i++ )
	{
		row = (DB_row) DB_fetch_row ( res );
		snort_id = 0;

		if ( !( inputs[i] = (double*) alloca ( SOM_NUM_ITEMS * sizeof ( double ))))
		{
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
		}

		snort_id = (( strtoul ( row[0], NULL, 10 ) & 0xFFFF ) << 16 ) | ( strtoul ( row[1], NULL, 10 ) & 0xFFFF );
		inputs[i][som_alert_id] = (double) snort_id / (double) UINT_MAX;
		inputs[i][som_time]     = (double) strtol ( row[3], NULL, 10 ) / (double) INT_MAX;
		inputs[i][som_src_ip]   = (double) ntohl ( inet_addr ( row[4] )) / (double) UINT_MAX;
		inputs[i][som_dst_ip]   = (double) ntohl ( inet_addr ( row[5] )) / (double) UINT_MAX;
		inputs[i][som_src_port] = (double) strtol ( row[6], NULL, 10 ) / (double) USHRT_MAX;
		inputs[i][som_dst_port] = (double) strtol ( row[7], NULL, 10 ) / (double) USHRT_MAX;
	}

	DB_free_result ( res );
}		/* -----  end of function AI_som_train  ----- */

/**
 * \brief  Thread for managing the self-organazing map (SOM) neural network for the alert correlation
 */

void*
AI_neural_thread ( void *arg )
{
	BOOL do_train = false;
	FILE *fp = NULL;
	struct stat st;

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
		}

		if ( !do_train )
		{
			if ( !( fp = fopen ( config->netfile, "r" )))
			{
				AI_fatal_err ( "AIPreproc: The neural network file exists but it is not readable", __FILE__, __LINE__ );
			}

			fread ( &latest_serialization_time, sizeof ( time_t ), 1, fp );

			/* If more than N seconds passed from the latest serialization, re-train the neural network */
			if ( (int) ( time (NULL) - latest_serialization_time ) > config->neuralNetworkTrainingInterval )
			{
				do_train = true;
			}

			fclose ( fp );
		}

		if ( !do_train )
		{
			if ( !net )
			{
				if ( !( net = som_deserialize ( config->netfile )))
				{
					AI_fatal_err ( "AIPreproc: Error in deserializing the neural network from the network file", __FILE__, __LINE__ );
				}
			}

			sleep ( 5 );
			continue;
		}
	}

	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function AI_neural_thread  ----- */

#endif

/** @} */

