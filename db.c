/*
 * =====================================================================================
 *
 *       Filename:  db.c
 *
 *    Description:  Parse the alert log saved by Snort on a database
 *
 *        Version:  0.1
 *        Created:  17/08/2010 17:29:36
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
#ifdef 	ENABLE_DB

#include	"db.h"

#include	<unistd.h>
#include	<time.h>
#include 	<pthread.h>

/** \defgroup db Manage alerts on a database
 * @{ */


PRIVATE AI_config      *config;
PRIVATE AI_snort_alert *alerts = NULL;

/** pthread mutex for accessing database data */
PRIVATE pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * \brief  Thread for parsing alerts from a database
 * \param  arg 	void* pointer to the module configuration
 */

void*
AI_db_alertparser_thread ( void *arg )
{
	char           query[1024];
	int            rows        = 0;
	int            latest_cid  = 0;
	time_t         latest_time = time ( NULL );

	DB_result      res, res2;
	DB_row         row, row2;

	struct pkt_key  key;
	struct pkt_info *info  = NULL;
	AI_snort_alert  *alert = NULL;
	AI_snort_alert  *tmp   = NULL;

	if ( !arg )
	{
		pthread_exit ((void*) 0 );
		return (void*) 0;
	}

	config = ( AI_config* ) arg;
	pthread_mutex_lock ( &db_mutex );

	if ( !DB_init ( config ))
	{
		_dpd.fatalMsg ( "AIPreproc: Unable to connect to the database '%s' @ '%s'\n",
				config->dbname, config->dbhost );
	}

	pthread_mutex_unlock ( &db_mutex );

	while ( 1 )
	{
		sleep ( config->databaseParsingInterval );
		memset ( query, 0, sizeof ( query ));
		snprintf ( query, sizeof (query), "select cid, unix_timestamp(timestamp), signature from event where cid > %d "
				"and unix_timestamp(timestamp) > %ld order by cid", latest_cid, latest_time );

		if ( !( res = (DB_result) DB_query ( query )))
		{
			DB_close();
			_dpd.fatalMsg ( "AIPreproc: Fatal error while executing a query on the database "
					"at %s:%d: '%s'\n", __FILE__, __LINE__, query );
		}

		if (( rows = DB_num_rows ( res )) < 0 )
		{
			DB_close();
			_dpd.fatalMsg ( "AIPreproc: Could not store the query result at %s:%d\n", __FILE__, __LINE__ );
		} else if ( rows == 0 ) {
			continue;
		}

		while (( row = (DB_row) DB_fetch_row ( res )))
		{
			if ( !( alert = ( AI_snort_alert* ) malloc ( sizeof ( AI_snort_alert )) ))
			{
				_dpd.fatalMsg ( "Fatal dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			}

			memset ( alert, 0, sizeof ( AI_snort_alert ));
			latest_cid = (row[0]) ? strtol ( row[0], NULL, 10 ) : 0;
			alert->timestamp = (row[1]) ? ( time_t ) strtol ( row[1], NULL, 10 ) : 0;

			/* Parsing gid, sid, rev, name, timestamp and priority */
			memset ( query, 0, sizeof ( query ));
			snprintf ( query, sizeof ( query ), "select sig_gid, sig_sid, sig_rev, sig_name, sig_priority from signature "
					"where sig_id='%ld'", strtol ( row[2], NULL, 0 ));

			if ( !( res2 = (DB_result) DB_query ( query )))
			{
				DB_close();
				_dpd.fatalMsg ( "AIPreproc: Fatal error while executing a query on the database "
						"at %s:%d: '%s'\n", __FILE__, __LINE__, query );
			}

			if (( rows = DB_num_rows ( res2 )) < 0 ) {
				DB_close();
				_dpd.fatalMsg ( "AIPreproc: Could not store the query result at %s:%d\n", __FILE__, __LINE__ );
			} else if ( rows > 0 ) {
				if (( row2 = (DB_row) DB_fetch_row ( res2 )))
				{
					alert->gid      = (row2[0]) ? strtol ( row2[0], NULL, 10 ) : 0;
					alert->sid      = (row2[1]) ? strtol ( row2[1], NULL, 10 ) : 0;
					alert->rev      = (row2[2]) ? strtol ( row2[2], NULL, 10 ) : 0;
					alert->desc     = (row2[3]) ? strdup ( row2[3] ) : NULL;
					alert->priority = (row2[4]) ? strtol ( row2[4], NULL, 10 ) : 0;
				}

				DB_free_result ( res2 );
			}

			/* Parsing IP header information */
			memset ( query, 0, sizeof ( query ));
			snprintf ( query, sizeof ( query ), "select ip_tos, ip_len, ip_id, ip_ttl, ip_proto, ip_src, ip_dst "
					"from iphdr where cid='%d'", latest_cid);

			if ( !( res2 = (DB_result) DB_query ( query )))
			{
				DB_close();
				_dpd.fatalMsg ( "AIPreproc: Fatal error while executing a query on the database "
						"at %s:%d: '%s'\n", __FILE__, __LINE__, query );
			}

			if (( rows = DB_num_rows ( res2 )) < 0 ) {
				DB_close();
				_dpd.fatalMsg ( "AIPreproc: Could not store the query result at %s:%d\n", __FILE__, __LINE__ );
			} else if ( rows > 0 ) {
				if (( row2 = DB_fetch_row ( res2 )))
				{
					alert->ip_tos      = (row2[0]) ? strtol ( row2[0], NULL, 10 ) : 0;
					alert->ip_len      = (row2[1]) ? htons ( strtol ( row2[1], NULL, 10 )) : 0;
					alert->ip_id       = (row2[2]) ? htons ( strtol ( row2[2], NULL, 10 )) : 0;
					alert->ip_ttl      = (row2[3]) ? strtol ( row2[3], NULL, 10 ) : 0;
					alert->ip_proto    = (row2[4]) ? strtol ( row2[4], NULL, 10 ) : 0;
					alert->ip_src_addr = (row2[5]) ? htonl ( strtoul ( row2[5], NULL, 10 )) : 0;
					alert->ip_dst_addr = (row2[6]) ? htonl ( strtoul ( row2[6], NULL, 10 )) : 0;
				}

				DB_free_result ( res2 );
			}

			/* Parsing TCP header information */
			memset ( query, 0, sizeof ( query ));
			snprintf ( query, sizeof ( query ), "select tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_flags, tcp_win "
					"from tcphdr where cid='%d'", latest_cid );

			if ( !( res2 = (DB_result) DB_query ( query )))
			{
				DB_close();
				_dpd.fatalMsg ( "AIPreproc: Fatal error while executing a query on the database "
						"at %s:%d: '%s'\n", __FILE__, __LINE__, query );
			}

			if (( rows = DB_num_rows ( res2 )) < 0 ) {
				DB_close();
				_dpd.fatalMsg ( "AIPreproc: Could not store the query result at %s:%d\n", __FILE__, __LINE__ );
			} else if ( rows > 0 ) {
				if (( row2 = DB_fetch_row ( res2 )))
				{
					alert->tcp_src_port  = (row2[0]) ? htons ( strtol  ( row2[0], NULL, 10 )) : 0;
					alert->tcp_dst_port  = (row2[1]) ? htons ( strtol  ( row2[1], NULL, 10 )) : 0;
					alert->tcp_seq       = (row2[2]) ? htonl ( strtoul ( row2[2], NULL, 10 )) : 0;
					alert->tcp_ack       = (row2[3]) ? htonl ( strtoul ( row2[3], NULL, 10 )) : 0;
					alert->tcp_flags     = (row2[4]) ? strtol  ( row2[4], NULL, 10 ) : 0;
					alert->tcp_window    = (row2[5]) ? htons ( strtol  ( row2[5], NULL, 10 )) : 0;
				}

				DB_free_result ( res2 );
			}

			/* Finding the associated stream info, if any */
			if ( alert->ip_proto == IPPROTO_TCP )
			{
				key.src_ip   = alert->ip_src_addr;
				key.dst_port = alert->tcp_dst_port;

				if (( info = AI_get_stream_by_key ( key )))
				{
					AI_set_stream_observed ( key );
					alert->stream = info;
				}
			}

			/* Creating a new alert log if it doesn't exist, or appending the current alert to the log */
			if ( !alerts )
			{
				alerts = alert;
				alerts->next = NULL;
			} else {
				for ( tmp = alerts; tmp->next; tmp = tmp->next );
				tmp->next = alert;
			}
		}
		
		DB_free_result ( res );
		latest_time = time ( NULL );
	}

	DB_close();
	pthread_exit ((void*) 0 );
	return (void*) 0;
}		/* -----  end of function AI_db_alert_parse  ----- */

/**
 * \brief  Create a copy of the alert log struct (this is done for leaving the alert log structure in this file as read-only)
 * \param  node 	Starting node (used for the recursion)
 * \return A copy of the alert log linked list
 */
PRIVATE AI_snort_alert*
_AI_db_copy_alerts ( AI_snort_alert *node )
{
	AI_snort_alert *current = NULL, *next = NULL;

	if ( !node )
	{
		return NULL;
	}

	if ( node->next )
	{
		next = _AI_db_copy_alerts ( node->next );
	}

	if ( !( current = ( AI_snort_alert* ) malloc ( sizeof ( AI_snort_alert )) ))
	{
		_dpd.fatalMsg ( "Fatal dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
	}

	memcpy ( current, node, sizeof ( AI_snort_alert ));
	current->next = next;
	return current;
}		/* -----  end of function _AI_db_copy_alerts  ----- */


/**
 * \brief  Return the alerts parsed so far as a linked list
 * \return An AI_snort_alert pointer identifying the list of alerts
 */
AI_snort_alert*
AI_db_get_alerts ()
{
	return _AI_db_copy_alerts ( alerts );
}		/* -----  end of function AI_db_get_alerts  ----- */

/** @} */

#endif

