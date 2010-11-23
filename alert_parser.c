/*
 * =====================================================================================
 *
 *       Filename:  alert_parser.c
 *
 *    Description:  Managing the parsing of Snort's alert file
 *
 *        Version:  0.1
 *        Created:  08/08/2010 09:21:57
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
#include	<sys/stat.h>
#include	<time.h>
#include	<unistd.h>

#ifdef LINUX
#include	<sys/inotify.h>
#endif

/** \defgroup alert_parser Parse the alert log into binary structures
 * @{ */

PRIVATE AI_snort_alert   *alerts           = NULL;
PRIVATE FILE             *alert_fp         = NULL;
PRIVATE pthread_mutex_t  alert_mutex;
PRIVATE pthread_mutex_t  alerts_pool_mutex;

AI_snort_alert   **alerts_pool     = NULL;
unsigned int     alerts_pool_count = 0;


/**
 * \brief  Serialize the pool of alerts in a separated thread
 * \param  arg   void* pointer to the alert to be added to the pool, if any
 */

void
AI_serializer ( AI_snort_alert *alert )
{
	unsigned int    i      = 0;

	if ( alert )
	{
		pthread_mutex_lock ( &alerts_pool_mutex );
		alerts_pool [ alerts_pool_count++ ] = alert;
		pthread_mutex_unlock ( &alerts_pool_mutex );
	}

	if ( !alert || ( alert && alerts_pool_count >= config->alert_bufsize ))
	{
		pthread_mutex_lock ( &alerts_pool_mutex );
		AI_serialize_alerts ( alerts_pool, alerts_pool_count );

		for ( i=0; i < alerts_pool_count; i++ )
		{
			alerts_pool[i] = NULL;
		}

		alerts_pool_count = 0;
		pthread_mutex_unlock ( &alerts_pool_mutex );
	}
}		/* -----  end of function AI_serializer  ----- */


/**
 * \brief  Thread for managing the buffer of alerts and serialize them at constant intervals
 */

void*
AI_alerts_pool_thread ( void *arg )
{
	pthread_t  serializer_thread;

	while ( 1 )
	{
		sleep ( config->alertSerializationInterval );

		if ( !alerts_pool || alerts_pool_count == 0 )
			continue;

		AI_serializer ( NULL );
	}

	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function AI_alerts_pool_thread  ----- */


/**
 * \brief  Thread for parsing Snort's alert file
 */

void*
AI_file_alertparser_thread ( void* arg )
{
	struct logtime  {
		unsigned short  day;
		unsigned short  month;
		unsigned short  year;
		unsigned short  hour;
		unsigned short  min;
		unsigned short  sec;
	};

	int             i;
#ifdef LINUX
	int             ifd;
	int             wd;
	struct stat     st;
#else
	int             fd = -1;
	struct stat     stats;
	time_t          last_mod_time = (time_t) 0;
#endif
	int             nmatches = 0;
	char            line[8192];
	char            strtime[256];
	char            **matches = NULL;
	time_t          stamp;
	struct tm       *_tm;
	struct logtime  ltime;
	struct pkt_key  key;
	struct pkt_info *info;

	AI_snort_alert *alert   = NULL;
	AI_snort_alert *tmp     = NULL;
	BOOL           in_alert = false;

	pthread_t      alerts_pool_thread;
	pthread_t      serializer_thread;
	pthread_t      db_thread;

	/* Initialize the mutex lock, so nobody can read the alerts while we write there */
	pthread_mutex_init ( &alert_mutex, NULL );

	/* Initialize the mutex on the alerts' pool, so that an only thread per time can write there */
	pthread_mutex_init ( &alerts_pool_mutex, NULL );

	/* Initialize the pool of alerts to be passed to the serialization thread */
	if ( !( alerts_pool = ( AI_snort_alert** ) malloc ( config->alert_bufsize * sizeof ( AI_snort_alert* ))))
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

	for ( i=0; i < config->alert_bufsize; i++ )
		alerts_pool[i] = NULL;

	/* Initialize the thread for managing the serialization of alerts' pool */
	if ( pthread_create ( &alerts_pool_thread, NULL, AI_alerts_pool_thread, NULL ) != 0 )
	{
		AI_fatal_err ( "Failed to create the alerts' pool management thread", __FILE__, __LINE__ );
	}

	while ( 1 )
	{
#ifdef LINUX
		if (( ifd = inotify_init() ) < 0 )
		{
			AI_fatal_err ( "Could not initialize an inotify object on the alert log file", __FILE__, __LINE__ );
		}

		if ( stat ( config->alertfile, &st ) < 0 )
		{
			if (( wd = inotify_add_watch ( ifd, config->alertfile, IN_CREATE )) < 0 )
			{
				AI_fatal_err ( "Could not initialize a watch descriptor on the alert log file", __FILE__, __LINE__  );
			}

			read ( ifd, line, sizeof(line) );
			inotify_rm_watch ( ifd, wd );
		} else {
			if ( !alert_fp )
			{
				if ( ! (alert_fp = fopen ( config->alertfile, "r" )) )
				{
					AI_fatal_err ( "Could not open alert log file for reading", __FILE__, __LINE__  );
				}
			}
		}

		if (( wd = inotify_add_watch ( ifd, config->alertfile, IN_MODIFY )) < 0 )
		{
			AI_fatal_err ( "Could not initialize a watch descriptor on the alert log file", __FILE__, __LINE__  );
		}

		fseek ( alert_fp, 0, SEEK_END );
		read ( ifd, line, sizeof(line) );
		inotify_rm_watch ( ifd, wd );
		close ( ifd );
#else
		/*
		 * Under Apple environments we don't have inotify capabilities, so use polling instead.
		 * TODO: Use FSEvent.
		 */
		if ( !alert_fp )
		{
			if ( ! (alert_fp = fopen ( config->alertfile, "r" )) )
			{
				AI_fatal_err ( "Could not open alert log file for reading", __FILE__, __LINE__  );
			}
			else if( fd == -1 ){
				/*
				 * Convert a FILE * to an integer file descriptor to be used with fstat.
				 */
				fd = fileno(alert_fp);
			}
		}

		/*
		 * Cause the thread to wait until a new file modification (a new alert).
		 */
		while( stats.st_mtime == last_mod_time ){
			usleep(100);
			fstats( fd, &stats );
		}

		/*
		 * The first time the thread is called, the flow exits instantly from the while,
		 * so this first time the stats structure has to be initialized properly.
		 */
		if( last_mod_time == (time_t) 0 )
		{
			fstats ( fd, &stats );
		}
		
		last_mod_time = stats.st_mtime;
		
		fseek ( alert_fp, 0, SEEK_END );
#endif
		
		pthread_mutex_lock ( &alert_mutex );

		while ( !feof ( alert_fp ))
		{
			fgets ( line, sizeof(line), alert_fp );

			for ( i = strlen(line)-1;
					i >= 0 && ( line[i] == '\n' || line[i] == '\r' || line[i] == '\t' || line[i] == ' ' );
					i++ )
			{
				line[i] = 0;
			}

			if ( strlen(line) == 0 )
			{
				if ( in_alert )
				{
					if ( alert->ip_src_addr )
					{
						if ( alert->ip_proto == IPPROTO_TCP )
						{
							memset ( &key, 0, sizeof ( key ));
							key.src_ip   = alert->ip_src_addr;
							key.dst_port = alert->tcp_dst_port;

							if (( info = AI_get_stream_by_key ( key )))
							{
								AI_set_stream_observed ( key );
								alert->stream = info;
							}
						}
					}

					if ( alerts == NULL )
					{
						alerts = alert;
						alerts->next = NULL;
					} else {
						for ( tmp = alerts; tmp->next; tmp = tmp->next );
						tmp->next = alert;
					}

					AI_serializer ( alert );

					if ( config->outdbtype != outdb_none )
					{
						AI_store_alert_to_db ( alert );
					}

					in_alert = false;
					alert = NULL;
				}

				continue;
			}

			if ( !in_alert )
			{
				if ( preg_match ( "^\\[\\*\\*\\]\\s*\\[([0-9]+):([0-9]+):([0-9]+)\\]\\s*(.*)\\s*\\[\\*\\*\\]$", line, &matches, &nmatches ) > 0 )
				{
					in_alert = true;

					if ( !( alert = ( AI_snort_alert* ) malloc ( sizeof( AI_snort_alert ))))
					{
						AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
					}

					memset ( alert, 0, sizeof(AI_snort_alert) );

					alert->gid  = strtoul ( matches[0], NULL, 10 );
					alert->sid  = strtoul ( matches[1], NULL, 10 );
					alert->rev  = strtoul ( matches[2], NULL, 10 );
					alert->desc = strdup  ( matches[3] );

					for ( i=0; i < nmatches; i++ )
						free ( matches[i] );

					free ( matches );
					matches = NULL;
				} else {
					_dpd.errMsg ( "Error: a line in the alert log cannot be associated to an alert block", __FILE__, __LINE__ );
				}
			} else if ( preg_match ( "\\[Priority:\\s*([0-9]+)\\]", line, &matches, &nmatches) > 0 ) {
				alert->priority = (unsigned short) strtoul ( matches[0], NULL, 10 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;

				if ( preg_match ( "\\[Classification:\\s*([^\\]]+)\\]", line, &matches, &nmatches) > 0 )
				{
					alert->classification = strdup ( matches[0] );

					for ( i=0; i < nmatches; i++ )
						free ( matches[i] );

					free ( matches );
					matches = NULL;
				}
			} else if ( preg_match ( "^([0-9]{2})/([0-9]{2})-([0-9]{2}):([0-9]{2}):([0-9]{2})\\.[0-9]+\\s+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}):([0-9]{1,5})\\s*"
						"->\\s*([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}):([0-9]{1,5})",
						line, &matches, &nmatches ) > 0 ) {
				stamp = time (NULL);
				_tm = localtime ( &stamp );

				ltime.year  = (unsigned short) _tm->tm_year + 1900;
				ltime.day   = (unsigned short) strtoul ( matches[1], NULL, 10 );
				ltime.month = (unsigned short) strtoul ( matches[0], NULL, 10 );
				ltime.hour  = (unsigned short) strtoul ( matches[2], NULL, 10 );
				ltime.min   = (unsigned short) strtoul ( matches[3], NULL, 10 );
				ltime.sec   = (unsigned short) strtoul ( matches[4], NULL, 10 );

				snprintf ( strtime, sizeof(strtime), "%02hu/%02hu/%04hu, %02hu:%02hu:%02hu",
					ltime.month, ltime.day, ltime.year, ltime.hour, ltime.min, ltime.sec );

				strptime ( strtime, "%m/%d/%Y, %H:%M:%S", _tm );
				alert->timestamp = mktime ( _tm );

				alert->ip_src_addr  = inet_addr ( matches[5] );
				alert->ip_dst_addr  = inet_addr ( matches[7] );
				alert->tcp_src_port = htons ( atoi( matches[6] ));
				alert->tcp_dst_port = htons ( atoi( matches[8] ));

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "^([0-9]{2})/([0-9]{2})-([0-9]{2}):([0-9]{2}):([0-9]{2})\\.[0-9]+\\s+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\s*"
						"->\\s*([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
						line, &matches, &nmatches ) > 0 ) {
				stamp = time (NULL);
				_tm = localtime ( &stamp );

				ltime.year  = (unsigned short) _tm->tm_year + 1900;
				ltime.day   = (unsigned short) strtoul ( matches[1], NULL, 10 );
				ltime.month = (unsigned short) strtoul ( matches[0], NULL, 10 );
				ltime.hour  = (unsigned short) strtoul ( matches[2], NULL, 10 );
				ltime.min   = (unsigned short) strtoul ( matches[3], NULL, 10 );
				ltime.sec   = (unsigned short) strtoul ( matches[4], NULL, 10 );

				snprintf ( strtime, sizeof(strtime), "%02hu/%02hu/%04hu, %02hu:%02hu:%02hu",
					ltime.month, ltime.day, ltime.year, ltime.hour, ltime.min, ltime.sec );

				strptime ( strtime, "%m/%d/%Y, %H:%M:%S", _tm );
				alert->timestamp = mktime ( _tm );

				alert->ip_src_addr = inet_addr ( matches[5] );
				alert->ip_dst_addr = inet_addr ( matches[6] );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "^([^\\s+]+)\\s+TTL:\\s*([0-9]+)\\s+TOS:\\s*0x([0-9A-F]+)\\s+ID:\\s*([0-9]+)\\s+IpLen:\\s*([0-9]+)",
						line, &matches, &nmatches ) > 0 ) {
				if ( !strcasecmp ( matches[0], "tcp" ) )  {
					alert->ip_proto = IPPROTO_TCP;
				} else if ( !strcasecmp ( matches[0], "udp" ) )  {
					alert->ip_proto = IPPROTO_UDP;
				} else if ( !strcasecmp ( matches[0], "icmp" ) )  {
					alert->ip_proto = IPPROTO_ICMP;
				} else {
					alert->ip_proto = IPPROTO_NONE;
				}

				alert->ip_ttl   = htons ( (uint16_t) strtoul ( matches[1], NULL, 10 ));
				alert->ip_tos   = htons ( (uint16_t) strtoul ( matches[2], NULL, 16 ));
				alert->ip_id    = htons ( (uint16_t) strtoul ( matches[3], NULL, 10 ));
				alert->ip_len   = htons ( (uint16_t) strtoul ( matches[4], NULL, 10 ));

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "^([\\*CEUAPRSF]{8})\\s+Seq:\\s*0x([0-9A-F]+)\\s+Ack:\\s*0x([0-9A-F]+)\\s+Win:\\s*0x([0-9A-F]+)\\s+TcpLen:\\s*([0-9]+)",
						line, &matches, &nmatches ) > 0 ) {
				alert->tcp_flags = 0;
				alert->tcp_flags |= ( strstr ( matches[0], "C" ) ) ? TCPHEADER_RES1 : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "E" ) ) ? TCPHEADER_RES2 : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "U" ) ) ? TCPHEADER_URG  : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "A" ) ) ? TCPHEADER_ACK  : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "P" ) ) ? TCPHEADER_PUSH : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "R" ) ) ? TCPHEADER_RST  : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "S" ) ) ? TCPHEADER_SYN  : 0;
				alert->tcp_flags |= ( strstr ( matches[0], "F" ) ) ? TCPHEADER_FIN  : 0;

				alert->tcp_seq      = htonl ( strtoul ( matches[1], NULL, 16 ));
				alert->tcp_ack      = htonl ( strtoul ( matches[2], NULL, 16 ));
				alert->tcp_window   = htons ( (uint16_t) strtoul ( matches[3], NULL, 16 ));
				alert->tcp_len      = htons ( (uint16_t) strtoul ( matches[4], NULL, 10 ));

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			}
		}

		pthread_mutex_unlock ( &alert_mutex );
	}

	free ( alerts_pool );
	pthread_mutex_destroy ( &alert_mutex );
	pthread_exit ((void*) 0 );
	return (void*) 0;
}		/* -----  end of function AI_file_alertparser_thread  ----- */


/**
 * \brief  Create a copy of the alert log struct (this is done for leaving the alert log structure in this file as read-only)
 * \param  node 	Starting node (used for the recursion)
 * \return A copy of the alert log linked list
 */
PRIVATE AI_snort_alert*
__AI_copy_alerts ( AI_snort_alert *node )
{
	AI_snort_alert *current = NULL, *next = NULL;

	if ( !node )
	{
		return NULL;
	}

	if ( node->next )
	{
		next = __AI_copy_alerts ( node->next );
	}

	if ( !( current = ( AI_snort_alert* ) malloc ( sizeof ( AI_snort_alert )) ))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	memcpy ( current, node, sizeof ( AI_snort_alert ));
	current->next = next;
	return current;
}		/* -----  end of function __AI_copy_alerts  ----- */


/**
 * \brief  Return the alerts parsed so far as a linked list
 * \return An AI_snort_alert pointer identifying the list of alerts
 */
AI_snort_alert*
AI_get_alerts ()
{
	AI_snort_alert *alerts_copy = NULL;

	pthread_mutex_lock ( &alert_mutex );
	alerts_copy = __AI_copy_alerts ( alerts );
	pthread_mutex_unlock ( &alert_mutex );

	return alerts_copy;
}		/* -----  end of function AI_get_alerts  ----- */


/**
 * \brief  Deallocate the memory of a log alert linked list
 * \param  node 	Linked list to be freed
 */
void
AI_free_alerts ( AI_snort_alert *node )
{
	int i;

	if ( !node )
		return;

	if ( node->next )
		AI_free_alerts ( node->next );

	/* if ( node->grouped_alerts ) */
	/* { */
	/* 	for ( i=0; i < node->grouped_alerts_count; i++ ) */
	/* 	{ */
	/* 		if ( node->grouped_alerts[i] ) */
	/* 		{ */
	/* 			free ( node->grouped_alerts[i] ); */
	/* 			node->grouped_alerts[i] = NULL; */
	/* 		} */
	/* 	} */

	/* 	free ( node->grouped_alerts ); */
	/* } */

	if ( node->hyperalert )
	{
		for ( i=0; i < node->hyperalert->n_preconds; i++ )
			free ( node->hyperalert->preconds[i] );
		free ( node->hyperalert->preconds );

		for ( i=0; i < node->hyperalert->n_postconds; i++ )
			free ( node->hyperalert->postconds[i] );

		free ( node->hyperalert->postconds );
		free ( node->hyperalert );
		node->hyperalert = NULL;
	}

	if ( node->parent_alerts )
		free ( node->parent_alerts );

	if ( node->derived_alerts )
		free ( node->derived_alerts );

	free ( node );
	node = NULL;
}		/* -----  end of function AI_free_alerts  ----- */

/** @} */

