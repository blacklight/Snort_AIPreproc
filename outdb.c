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
#include	<alloca.h>
#include	<pthread.h>

enum  { ALERTS_TABLE, IPV4_HEADERS_TABLE, TCP_HEADERS_TABLE, PACKET_STREAMS_TABLE, CLUSTERED_ALERTS_TABLE, CORRELATED_ALERTS_TABLE, N_TABLES };

static const char *outdb_config[] = {
	"ca_alerts", "ca_ipv4_headers", "ca_tcp_headers",
	"ca_packet_streams", "ca_clustered_alerts", "ca_correlated_alerts"
};

PRIVATE pthread_mutex_t  mutex;

/**
 * \brief  Thread for storing an alert to the database
 * \param  arg 	Alert to be stored
 */

void*
AI_store_alert_to_db_thread ( void *arg )
{
	char srcip[INET_ADDRSTRLEN], dstip[INET_ADDRSTRLEN];
	char query[65535] = { 0 };
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

	pthread_mutex_init ( &mutex, NULL );

	if ( !DB_out_init() )
		_dpd.fatalMsg ( "AIPreproc: Unable to connect to output database '%s'\n", config->outdbname );

	pthread_mutex_lock ( &mutex );

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

	DB_out_query ( query );

	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ), "SELECT MAX(ip_hdr_id) FROM %s", outdb_config[IPV4_HEADERS_TABLE] );

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
		pthread_exit ((void*) 0);
	}

	if ( !( row = (DB_row) DB_fetch_row ( res )))
	{
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

		DB_out_query ( query );

		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof ( query ), "SELECT MAX(tcp_hdr_id) FROM %s", outdb_config[TCP_HEADERS_TABLE] );

		if ( !( res = (DB_result) DB_out_query ( query )))
		{
			_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
			pthread_exit ((void*) 0);
		}

		if ( !( row = (DB_row) DB_fetch_row ( res )))
		{
			pthread_exit ((void*) 0);
		}

		latest_tcp_hdr_id = strtoul ( row[0], NULL, 10 );
		DB_free_result ( res );
	}

	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ), "INSERT INTO %s (gid, sid, rev, priority, description, classification, timestamp, ip_hdr, tcp_hdr) "
			"VALUES (%u, %u, %u, %u, '%s', '%s', from_unixtime('%lu'), %lu, %lu)",
		outdb_config[ALERTS_TABLE],
		alert->gid,
		alert->sid,
		alert->rev,
		alert->priority,
		((alert->desc) ? alert->desc : ""),
		((alert->classification) ? alert->classification : ""),
		alert->timestamp,
		latest_ip_hdr_id,
		((alert->ip_proto == IPPROTO_TCP || alert->ip_proto == IPPROTO_UDP) ? latest_tcp_hdr_id : 0));

	DB_out_query ( query );

	memset ( query, 0, sizeof ( query ));
	snprintf ( query, sizeof ( query ), "SELECT MAX(alert_id) FROM %s", outdb_config[ALERTS_TABLE] );

	if ( !( res = (DB_result) DB_out_query ( query )))
	{
		_dpd.logMsg ( "AIPreproc: Warning: error in executing query: '%s'\n", query );
		pthread_exit ((void*) 0);
	}

	if ( !( row = (DB_row) DB_fetch_row ( res )))
	{
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
			pkt_size = pkt->pkt->pcap_cap_len;
			pkt_size_offset = 0;

			if ( !( pkt_data = (unsigned char*) alloca ( 2 * (pkt->pkt->pcap_header->len + pkt->pkt->payload_size) + 1 )))
				_dpd.fatalMsg ( "AIPreproc: Fatal dynamic allocation memory at %s:%d\n", __FILE__, __LINE__ );

			DB_out_escape_string ( &pkt_data,
					pkt->pkt->pkt_data,
					pkt->pkt->pcap_header->len + pkt->pkt->payload_size );

			memset ( query, 0, sizeof ( query ));
			snprintf ( query, sizeof ( query ), "INSERT INTO %s (alert_id, pkt_len, timestamp, content) "
					"VALUES (%lu, %u, from_unixtime('%lu'), '%s')",
				outdb_config[PACKET_STREAMS_TABLE],
				latest_alert_id,
				pkt->pkt->pcap_header->len + pkt->pkt->payload_size,
				pkt->timestamp,
				pkt_data );

			DB_out_query ( query );
		}
	}

	pthread_mutex_unlock ( &mutex );
	pthread_exit ((void*) 0);
	return (void*) 0;
}

#endif

/** @} */

