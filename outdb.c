/*
 * =====================================================================================
 *
 *       Filename:  outdb.c
 *
 *    Description:  Module for writing to a database the outputs (alerts, hyperalerts,
 *    			clustered alerts, correlated alerts, alerts' TCP streams) from the
 *    			preprocessor module
 *
 *        Version:  0.1
 *        Created:  30/09/2010 20:02:17
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

/** \defgroup outdb Storing alerts, packets, clusters and correlations information on a database
 * @{ */

#ifdef 	HAVE_DB

#include	"db.h"
#include	"uthash.h"

#include	<alloca.h>

/** Hash table built as cache for the couple of alerts already belonging to the same cluster,
 * for avoiding more queries on the database*/
typedef struct  {
	AI_alerts_couple *alerts_couple;
	unsigned long    cluster_id;
	UT_hash_handle   hh;
} AI_couples_cache;

/** Mutex object, for managing concurrent thread access to the database */
pthread_mutex_t outdb_mutex;
PRIVATE AI_couples_cache *couples_cache = NULL;

/**
 * \brief  Initialize the mutex on the output database
 */

void
AI_outdb_mutex_initialize ()
{
	pthread_mutex_init ( &outdb_mutex, NULL );
}		/* -----  end of function AI_outdb_mutex_initialize  ----- */

/**
 * \brief  Thread for storing an alert to the database
 * \param  arg 	Alert to be stored
 */

void*
AI_store_alert_to_db_thread ( void *arg )
{
	char query[65535]      = { 0 },
		iphdr_id_str[20]  = { 0 },
		tcphdr_id_str[20] = { 0 },
		srcip[INET_ADDRSTRLEN],
		dstip[INET_ADDRSTRLEN];

	unsigned char *pkt_data = NULL;
	unsigned long latest_ip_hdr_id  = 0,
			    latest_tcp_hdr_id = 0,
			    latest_alert_id   = 0,
			    pkt_size          = 0,
			    pkt_size_offset   = 0;

	struct pkt_info *pkt = NULL;
	DB_result res;
	DB_row    row;
	AI_snort_alert *alert = (AI_snort_alert*) arg;

	pthread_mutex_lock ( &outdb_mutex );

	if ( !DB_out_init() )
		AI_fatal_err ( "Unable to connect to the specified output database", __FILE__, __LINE__ );

	inet_ntop ( AF_INET, &(alert->ip_src_addr), srcip, INET_ADDRSTRLEN );
	inet_ntop ( AF_INET, &(alert->ip_dst_addr), dstip, INET_ADDRSTRLEN );

	/* Store the IP header information */
	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ), "INSERT INTO %s (ip_tos, ip_len, ip_id, ip_ttl, ip_proto, ip_src_addr, ip_dst_addr) "
			"VALUES (%u, %u, %u, %u, %u, '%s', '%s')",
		outdb_config[IPV4_HEADERS_TABLE],
		alert->ip_tos,
		ntohs (alert->ip_len ),
		ntohs (alert->ip_id ),
		alert->ip_ttl,
		alert->ip_proto,
		srcip,
		dstip );

	DB_free_result ((DB_result) DB_out_query ( query ));

	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ), "SELECT MAX(ip_hdr_id) FROM %s", outdb_config[IPV4_HEADERS_TABLE] );

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	if ( !( row = (DB_row) DB_fetch_row ( res )))
	{
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
	}

	latest_ip_hdr_id = strtoul ( row[0], NULL, 10 );
	DB_free_result ( res );

	if ( alert->ip_proto == IPPROTO_TCP || alert->ip_proto == IPPROTO_UDP )
	{
		/* Store the TCP header information */
		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof ( query ), "INSERT INTO %s (tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack, tcp_flags, tcp_window, tcp_len) "
				"VALUES (%u, %u, %u, %u, %u, %u, %u)",
				outdb_config[TCP_HEADERS_TABLE],
				ntohs (alert->tcp_src_port ),
				ntohs (alert->tcp_dst_port ),
				ntohl (alert->tcp_seq ),
				ntohl (alert->tcp_ack ),
				alert->tcp_flags,
				ntohs (alert->tcp_window ),
				ntohs (alert->tcp_len ));

		DB_free_result ((DB_result) DB_out_query ( query ));

		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof ( query ), "SELECT MAX(tcp_hdr_id) FROM %s", outdb_config[TCP_HEADERS_TABLE] );

		if ( !( res = (DB_result) DB_out_query ( query )))
		{
			_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
			pthread_mutex_unlock ( &outdb_mutex );
			pthread_exit ((void*) 0);
		}

		if ( !( row = (DB_row) DB_fetch_row ( res )))
		{
			pthread_mutex_unlock ( &outdb_mutex );
			pthread_exit ((void*) 0);
		}

		latest_tcp_hdr_id = strtoul ( row[0], NULL, 10 );
		DB_free_result ( res );
	}

	if ( latest_ip_hdr_id )
	{
		snprintf ( iphdr_id_str, sizeof ( iphdr_id_str ), ", %lu", latest_ip_hdr_id );
	}

	if ( latest_tcp_hdr_id && alert->ip_proto == IPPROTO_TCP )
	{
		snprintf ( tcphdr_id_str, sizeof ( tcphdr_id_str ), ", %lu", latest_tcp_hdr_id );
	}

	memset ( query, 0, sizeof ( query ));

	#ifdef 	HAVE_LIBMYSQLCLIENT
	snprintf ( query, sizeof ( query ), "INSERT INTO %s (gid, sid, rev, priority, description, classification, timestamp%s%s) "
			"VALUES (%u, %u, %u, %u, '%s', '%s', from_unixtime('%lu')%s%s)",
		outdb_config[ALERTS_TABLE],
		((latest_ip_hdr_id  != 0) ? ", ip_hdr"  : ""),
		((latest_tcp_hdr_id != 0) ? ", tcp_hdr" : ""),
		alert->gid,
		alert->sid,
		alert->rev,
		alert->priority,
		((alert->desc) ? alert->desc : ""),
		((alert->classification) ? alert->classification : ""),
		alert->timestamp,
		iphdr_id_str,
		tcphdr_id_str );
	#elif 	HAVE_LIBPQ
	snprintf ( query, sizeof ( query ), "INSERT INTO %s (gid, sid, rev, priority, description, classification, timestamp%s%s) "
			"VALUES (%u, %u, %u, %u, '%s', '%s', timestamp with time zone 'epoch' + %lu * interval '1 second'%s%s)",
		outdb_config[ALERTS_TABLE],
		((latest_ip_hdr_id  != 0) ? ", ip_hdr"  : ""),
		((latest_tcp_hdr_id != 0) ? ", tcp_hdr" : ""),
		alert->gid,
		alert->sid,
		alert->rev,
		alert->priority,
		((alert->desc) ? alert->desc : ""),
		((alert->classification) ? alert->classification : ""),
		alert->timestamp,
		iphdr_id_str,
		tcphdr_id_str );
	#endif

	DB_free_result ((DB_result) DB_out_query ( query ));

	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ), "SELECT MAX(alert_id) FROM %s", outdb_config[ALERTS_TABLE] );

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
	}

	if ( !( row = (DB_row) DB_fetch_row ( res )))
	{
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
	}

	latest_alert_id = strtoul ( row[0], NULL, 10 );
	alert->alert_id = latest_alert_id;
	DB_free_result ( res );

	if ( alert->stream )
	{
		for ( pkt = alert->stream; pkt; pkt = pkt->next )
		{
			pkt_data = NULL;

			if ( !pkt->pkt->ip4_header )
			{
				pkt_size = pkt->pkt->pcap_header->len +
					pkt->pkt->tcp_options_length +
					pkt->pkt->payload_size;
			} else {
				pkt_size = pkt->pkt->ip4_header->data_length;
			}

			pkt_size_offset = 0;

			if ( !( pkt_data = (unsigned char*) alloca ( 2 * ( pkt_size ) + 1 )))
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

			DB_out_escape_string (
					(char**) &pkt_data,
					(const char*) pkt->pkt->pkt_data,
					pkt_size );

			memset ( query, 0, sizeof ( query ));

			#ifdef 	HAVE_LIBMYSQLCLIENT
			snprintf ( query, sizeof ( query ), "INSERT INTO %s (alert_id, pkt_len, timestamp, content) "
					"VALUES (%lu, %u, from_unixtime('%lu'), '%s')",
				outdb_config[PACKET_STREAMS_TABLE],
				latest_alert_id,
				pkt->pkt->pcap_header->len + pkt->pkt->payload_size,
				pkt->timestamp,
				pkt_data );
			#elif 	HAVE_LIBPQ
			snprintf ( query, sizeof ( query ), "INSERT INTO %s (alert_id, pkt_len, timestamp, content) "
					"VALUES (%lu, %u, timestamp with time zone 'epoch' + %lu * interval '1 second', '%s')",
				outdb_config[PACKET_STREAMS_TABLE],
				latest_alert_id,
				pkt->pkt->pcap_header->len + pkt->pkt->payload_size,
				pkt->timestamp,
				pkt_data );
			#endif

			DB_free_result ((DB_result) DB_out_query ( query ));
		}
	}

	pthread_mutex_unlock ( &outdb_mutex );
	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function AI_store_alert_to_db_thread  ----- */

/**
 * \brief  Store an alert cluster to database
 * \param  arg 	Struct pointer containing the couple of alerts to be clustered together
 */

void*
AI_store_cluster_to_db_thread ( void *arg )
{
	unsigned long cluster1 = 0,
			    cluster2 = 0,
			    latest_cluster_id = 0;

	char query[1024] = { 0 },
		srcip[INET_ADDRSTRLEN] = { 0 },
		dstip[INET_ADDRSTRLEN] = { 0 },
		srcport[10] = { 0 },
		dstport[10] = { 0 };

	AI_alerts_couple *alerts_couple = (AI_alerts_couple*) arg;
	AI_couples_cache *found         = NULL;
	DB_result res;
	DB_row    row;
	BOOL      new_cluster = false;

	pthread_mutex_lock ( &outdb_mutex );

	/* Check if the couple of alerts is already in our cache, so it already
	 * belongs to the same cluster. If so, just return */
	HASH_FIND ( hh, couples_cache, alerts_couple, sizeof ( AI_alerts_couple ), found );

	if ( found )
	{
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	/* Initialize the database (it just does nothing if it is already initialized) */
	if ( !DB_out_init() )
		AI_fatal_err ( "Unable to connect to the specified output database", __FILE__, __LINE__ );

	/* If one of the two alerts has no alert_id, simply return */
	if ( !alerts_couple->alert1->alert_id || !alerts_couple->alert2->alert_id )
	{
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	/* Check if there already exist a cluster containing one of them */
	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ),
		"SELECT cluster_id FROM %s WHERE alert_id=%lu OR alert_id=%lu",
		outdb_config[ALERTS_TABLE], alerts_couple->alert1->alert_id, alerts_couple->alert2->alert_id );

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	if ( !( row = (DB_row) DB_fetch_row ( res )))
	{
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	/* If no cluster exists containing at least of them, create it */
	new_cluster = false;

	if ( !row[0] && !row[1] )
	{
		new_cluster = true;
	} else {
		if ( row[0] )
		{
			cluster1 = strtoul ( row[0], NULL, 10 );
		}

		if ( row[1] )
		{
			cluster2 = strtoul ( row[1], NULL, 10 );
		}

		if ( cluster1 == 0 && cluster2 == 0 )
		{
			new_cluster = true;
		}
	}

	DB_free_result ( res );

	/* If both the alerts already belong to the same cluster (but they're not in the cache yet),
	 * insert them in the cache */
	if ( cluster1 != 0 && cluster2 != 0 && cluster1 == cluster2 )
	{
		if ( !( found = ( AI_couples_cache* ) malloc ( sizeof ( AI_couples_cache ))))
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
		
		found->alerts_couple = alerts_couple;
		found->cluster_id = cluster1;
		HASH_ADD ( hh, couples_cache, alerts_couple, sizeof ( AI_alerts_couple ), found );
		pthread_mutex_unlock ( &outdb_mutex );
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	if ( new_cluster )
	{
		/* Insert a new cluster containing alert1 and alert2 for now */
		inet_ntop ( AF_INET, &(alerts_couple->alert1->ip_src_addr), srcip, INET_ADDRSTRLEN );
		inet_ntop ( AF_INET, &(alerts_couple->alert1->ip_dst_addr), dstip, INET_ADDRSTRLEN );
		snprintf ( srcport, sizeof ( srcport ), "%u", ntohs( alerts_couple->alert1->tcp_src_port ));
		snprintf ( dstport, sizeof ( dstport ), "%u", ntohs( alerts_couple->alert1->tcp_dst_port ));

		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof ( query ),
			"INSERT INTO %s ( clustered_srcip, clustered_dstip, clustered_srcport, clustered_dstport ) "
			"VALUES ( '%s', '%s', '%s', '%s' )",
			outdb_config[CLUSTERED_ALERTS_TABLE],
			((alerts_couple->alert1->h_node[src_addr]) ? alerts_couple->alert1->h_node[src_addr]->label : srcip),
			((alerts_couple->alert1->h_node[dst_addr]) ? alerts_couple->alert1->h_node[dst_addr]->label : dstip),
			((alerts_couple->alert1->h_node[src_port]) ? alerts_couple->alert1->h_node[src_port]->label : srcport),
			((alerts_couple->alert1->h_node[dst_port]) ? alerts_couple->alert1->h_node[dst_port]->label : dstport)
		);

		DB_free_result ((DB_result) DB_out_query ( query ));

		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof ( query ),
			"SELECT MAX(cluster_id) FROM %s", outdb_config[CLUSTERED_ALERTS_TABLE] );

		if ( !( res = (DB_result) DB_out_query ( query )))
		{
			_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
			pthread_mutex_unlock ( &outdb_mutex );
			pthread_exit ((void*) 0);
			return (void*) 0;
		}

		if ( !( row = (DB_row) DB_fetch_row ( res )))
		{
			pthread_mutex_unlock ( &outdb_mutex );
			pthread_exit ((void*) 0);
			return (void*) 0;
		}

		latest_cluster_id = strtoul ( row[0], NULL, 10 );
		DB_free_result ( res );

		/* Update the two alerts, setting them as belonging to the new cluster */
		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof ( query ),
			"UPDATE %s SET cluster_id=%lu WHERE alert_id=%lu OR alert_id=%lu",
			outdb_config[ALERTS_TABLE], latest_cluster_id,
			alerts_couple->alert1->alert_id, alerts_couple->alert2->alert_id );

		DB_free_result ((DB_result) DB_out_query ( query ));
	} else {
		/* Update the alert marked as 'not clustered' */
		if ( !cluster1 )
		{
			memset ( query, 0, sizeof ( query ));
			snprintf ( query, sizeof ( query ),
				"UPDATE %s SET cluster_id=%lu WHERE alert_id=%lu",
				outdb_config[ALERTS_TABLE], cluster2, alerts_couple->alert1->alert_id );

			DB_free_result ((DB_result) DB_out_query ( query ));
		} else {
			memset ( query, 0, sizeof ( query ));
			snprintf ( query, sizeof ( query ),
				"UPDATE %s SET cluster_id=%lu WHERE alert_id=%lu",
				outdb_config[ALERTS_TABLE], cluster1, alerts_couple->alert2->alert_id );

			DB_free_result ((DB_result) DB_out_query ( query ));
		}
	}

	/* Add the couple to the cache */
	if ( !( found = ( AI_couples_cache* ) malloc ( sizeof ( AI_couples_cache ))))
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

	found->alerts_couple = alerts_couple;
	found->cluster_id = cluster1;
	HASH_ADD ( hh, couples_cache, alerts_couple, sizeof ( AI_alerts_couple ), found );

	pthread_mutex_unlock ( &outdb_mutex );
	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function AI_store_cluster_to_db_thread  ----- */


/**
 * \brief  Store the correlation between two alerts to the output database
 * \param  arg 	Structure containing the two alerts to be saved and their correlation
 */

void*
AI_store_correlation_to_db_thread ( void *arg )
{
	char query[1024] = { 0 };
	AI_alert_correlation *corr = (AI_alert_correlation*) arg;

	pthread_mutex_lock ( &outdb_mutex );

	/* Initialize the database (it just does nothing if it is already initialized) */
	if ( !DB_out_init() )
		AI_fatal_err ( "Unable to connect to the specified output database", __FILE__, __LINE__ );

	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ),
		"INSERT INTO %s ( alert1, alert2, correlation_coeff ) "
		"VALUES ( %lu, %lu, %f )",
		outdb_config[CORRELATED_ALERTS_TABLE],
		corr->key.a->alert_id,
		corr->key.b->alert_id,
		corr->correlation );
	DB_free_result ((DB_result) DB_out_query ( query ));

	pthread_mutex_unlock ( &outdb_mutex );
	pthread_exit ((void*) 0);
	return 0;
}		/* -----  end of function AI_store_correlation_to_db_thread  ----- */

#endif

/** @} */

