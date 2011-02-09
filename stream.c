/*
 * =====================================================================================
 *
 *       Filename:  stream.c
 *
 *    Description:  It manages the streams of TCP packets, keeping them in a hashtable
 *
 *        Version:  0.1
 *        Created:  30/07/2010 15:02:54
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#include 	"spp_ai.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include 	<time.h>

PRIVATE struct pkt_info *hash = NULL;
PRIVATE time_t start_time = 0;

/** pthread mutex for managing the access of multiple readers/writers to the hash table */
PRIVATE pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

/** \defgroup stream Manage streams, sorting them into hash tables and linked lists
 * @{ */

/**
 * \brief  Remove a stream from the hash table (private function)
 * \param  stream 	Stream to be removed
 */

PRIVATE void
__AI_stream_free ( struct pkt_info* stream )
{
	struct pkt_info *tmp = NULL;

	/* If the provided stream is empty, or the hash table contains no element, just return */
	if ( !stream || !hash || HASH_COUNT(hash) == 0 )
		return;

	/* Lock the mutex over the hash table and search for a stream having the provided key */
	pthread_mutex_lock ( &hash_mutex );
	HASH_FIND ( hh, hash, &(stream->key), sizeof(struct pkt_key), tmp );
	pthread_mutex_unlock ( &hash_mutex );

	/* If that key is not there, just return */
	if ( !tmp )
		return;

	/* If the stream has no IP or TCP header, return */
	if ( stream->pkt )
	{
		if ( !stream->pkt->ip4_header )
			return;

		if ( stream->pkt->ip4_header->proto != IPPROTO_TCP || !stream->pkt->tcp_header )
			return;
	}

	/* Remove the stream from the hash table */
	pthread_mutex_lock ( &hash_mutex );
	HASH_DEL ( hash, stream );
	pthread_mutex_unlock ( &hash_mutex );

	/* Remove all the packets contained in the stream */
	while ( stream )
	{
		tmp = stream->next;

		if ( stream->pkt )
		{
			free ( stream->pkt );
			stream->pkt = NULL;
		}

		free ( stream );
		stream = tmp;
	}

	stream = NULL;
} 		/* -----  end of function __AI_stream_free  ----- */


/**
 * \brief  Thread called for cleaning up the hash table from the traffic streams older than
 *         a certain threshold
 */

void*
AI_hashcleanup_thread ( void* arg )
{
	struct pkt_info  *h, *stream, *tmp;
	time_t  max_timestamp;
	int   pkt_count, pkt_rm;
	BOOL  has_old_streams;

	if ( config->hashCleanupInterval == 0 )
	{
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	while ( 1 )  {
		/* Sleep for the specified number of seconds */
		sleep ( config->hashCleanupInterval );

		/* If the hash is empty, come back to sleep */
		if ( !hash || !HASH_COUNT(hash) )
			continue;

		has_old_streams = true;

		while ( has_old_streams )
		{
			has_old_streams = false;

			/* Check all the streams in the hash */
			for ( h = hash; h; h = (struct pkt_info*) h->next )  {
				if ( h->observed )
				{
					continue;
				}

				if ( h->next )
				{
					if ( h->next->observed )
					{
						if ( config->max_hash_pkt_number != 0 )
						{
							if ( h->next->n_packets == 0 )
							{
								for ( stream = h->next, pkt_count=0; stream; stream = (struct pkt_info*) stream->next, pkt_count++ );
								h->next->n_packets = pkt_count;
							} else {
								pkt_count = h->next->n_packets;
							}

							/* If this stream has too many packets inside, remove the oldest ones */
							if ( pkt_count > config->max_hash_pkt_number )
							{
								for ( stream = h->next, pkt_rm = 0;
										stream && pkt_rm < pkt_count - config->max_hash_pkt_number;
										stream = stream->next, pkt_rm++ )
								{
									tmp = stream->next;
									__AI_stream_free ( stream );
									stream = tmp;
								}

								h->next = stream;
							}
						}
					}
				}

				max_timestamp = 0;

				/* Find the maximum timestamp in the flow */
				for ( stream = h; stream; stream = (struct pkt_info*) stream->next )  {
					if ( stream->timestamp > max_timestamp )
						max_timestamp = stream->timestamp;
				}

				/* If the most recent packet in the stream is older than the specified threshold, remove that stream */

				if ( time (NULL) - max_timestamp > config->streamExpireInterval )  {
					has_old_streams = true;
					stream = h;

					if ( stream )
					{
						__AI_stream_free ( stream );
					}
				}
			}
		}
	}

	/* Hey we'll never reach this point unless 1 becomes != 1, but I have to place it
	 * for letting not gcc annoy us */
	pthread_exit ((void*) 0);
	return (void*) 0;
} 		/* -----  end of function AI_hashcleanup_thread  ----- */


/**
 * \brief  Function called for appending a new packet to the hash table,
 *         creating a new stream or appending it to an existing stream
 * \param  pkt 	Packet to be appended
 */

void
AI_pkt_enqueue ( SFSnortPacket* pkt )
{
	struct pkt_key  key;
	struct pkt_info *info;
	struct pkt_info *tmp;
	struct pkt_info *found = NULL;

	if ( start_time == 0 )
		start_time = time (NULL);

	/* If we are not using the stream hash table, just return */
	if ( config->use_stream_hash_table == 0 )
		return;

	/* If this is not an IP and/or TCP packet, it's not for me */
	if ( !( pkt->ip4_header && pkt->tcp_header ))
		return;

	if ( !( info = (struct pkt_info*) malloc( sizeof(struct pkt_info) )) )
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	memset ( &key, 0, sizeof(struct pkt_key));
	key.src_ip   = pkt->ip4_header->source.s_addr;
	key.dst_port = pkt->tcp_header->destination_port;

	info->key       = key;
	info->timestamp = time(NULL);
	info->observed  = false;
	info->n_packets = 0;
	info->next      = NULL;

	if ( !( info->pkt = (SFSnortPacket*) malloc ( sizeof (SFSnortPacket) )) )
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	memcpy ( info->pkt, pkt, sizeof (SFSnortPacket) );

	if ( hash )  {
		pthread_mutex_lock ( &hash_mutex );
		HASH_FIND ( hh, hash, &key, sizeof(struct pkt_key), found );
		pthread_mutex_unlock ( &hash_mutex );
	}

	/* If there is already an element of this traffic stream in my hash table,
	 * append the packet just received to this stream*/
	if ( found )  {
		/* If the current packet contains a RST or a FIN, just deallocate the stream */
		if (
			( info->pkt->tcp_header->flags & TCPHEADER_RST ) ||
			(( info->pkt->tcp_header->flags & TCPHEADER_FIN ) &&
			 ( info->pkt->tcp_header->flags & TCPHEADER_ACK ))
		)  {
			pthread_mutex_lock ( &hash_mutex );
			HASH_FIND ( hh, hash, &key, sizeof(struct pkt_key), found );
			pthread_mutex_unlock ( &hash_mutex );

			if ( found )  {
				if ( !found->observed )  {
					__AI_stream_free ( found );
				}
			}
		} else {
			tmp = NULL;

			for ( ; found->next; found = found->next )  {
				/* Stupid memory bug fixed in a stupid and unelegant way */
				if ( (unsigned long int) found->next->pkt < 0x100 )
					break;

				/* If the sequence number of the next packet in the stream
				 * is bigger than the sequence number of the current packet,
				 * place the current packet before that */
				if ( ntohl( found->next->pkt->tcp_header->sequence ) >
						ntohl( info->pkt->tcp_header->sequence ) )  {
					tmp         = found->next;
					found->next = info;
					info->next  = tmp;
					break;
				}
			}

			if ( !tmp )  {
				found->next = info;
			}
		}
	} else {
		/* If the packet contains the ACK flag, no payload and it is
		 * associated to no active stream, just ignore it */
		/* if ( pkt->tcp_header->flags & TCPHEADER_ACK )  { */
		/* 	return; */
		/* } */

		/* If there is no stream associated to this packet, create
		 * a new node in the hash table */
		pthread_mutex_lock ( &hash_mutex );
		HASH_ADD ( hh, hash, key, sizeof(struct pkt_key), info );
		pthread_mutex_unlock ( &hash_mutex );
	}

	return;
} 		/* -----  end of function AI_pkt_enqueue  ----- */


/**
 * \brief  Get a TCP stream by key
 * \param  key 	Key of the stream to be picked up (struct pkt_key)
 * \return A pkt_info pointer to the stream if found, NULL otherwise
 */

struct pkt_info* 
AI_get_stream_by_key ( struct pkt_key key )
{
	struct pkt_info *info = NULL;

	pthread_mutex_lock ( &hash_mutex );
	HASH_FIND ( hh, hash, &key, sizeof (struct pkt_key), info );
	pthread_mutex_unlock ( &hash_mutex );

	/* If no stream was found with that key, return */
	if ( info == NULL )
		return NULL;

	/* If the timestamp of the stream is older than the start time, return */
	if ( info->timestamp < start_time )
		return NULL;

	return info;
}		/* -----  end of function AI_get_stream_by_key  ----- */


/**
 * \brief  Set the flag "observed" on a stream associated to a security alert, so that it won't be removed from the hash table
 * \param  key 	Key of the stream to be set as "observed"
 */

void
AI_set_stream_observed ( struct pkt_key key )
{
	struct pkt_info *info = NULL;

	pthread_mutex_lock ( &hash_mutex );
	HASH_FIND ( hh, hash, &key, sizeof (struct pkt_key), info );
	pthread_mutex_unlock ( &hash_mutex );

	if ( info == NULL )
		return;

	pthread_mutex_lock ( &hash_mutex );
	info->observed = true;
	pthread_mutex_unlock ( &hash_mutex );
}		/* -----  end of function AI_set_stream_observed  ----- */

/** @} */

