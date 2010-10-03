/*
 * =====================================================================================
 *
 *       Filename:  alert_history.c
 *
 *    Description:  Manages the history of alerts on a binary file
 *
 *        Version:  0.1
 *        Created:  18/09/2010 21:02:15
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

/** \defgroup alert_history Manage the serialization and deserialization of alert history to the history file
 * @{ */


PRIVATE AI_alert_event  *alerts_hash = NULL;


/**
 * \brief  Free a hash table of alert events
 * \param  events  Hash table to be freed
 */

void
AI_alerts_hash_free ( AI_alert_event **events )
{
	AI_alert_event *hash_iterator = NULL,
				*list_iterator = NULL,
				*tmp           = NULL;

	while ( *events )
	{
		hash_iterator = *events;
		HASH_DEL ( *events, hash_iterator );
		list_iterator = hash_iterator;

		while ( list_iterator )
		{
			tmp = list_iterator->next;
			free ( list_iterator );
			list_iterator = tmp;
		}

		free ( hash_iterator );
	}

	*events = NULL;
}		/* -----  end of function AI_alerts_hash_free  ----- */

/**
 * \brief  Deserialize a alerts' hash table from the binary history file
 * \return A void* pointer (to be casted to AI_alert_event*) to the stored hash table
 */

void*
AI_deserialize_alerts ()
{
	FILE                 *fp = NULL;
	struct stat          st;
	unsigned int         i, j,
			           lists_count = 0,
			           items_count = 0;
	AI_alert_event       *event_iterator = NULL,
				      *event_prev     = NULL,
				      *event_list     = NULL;
	AI_alert_event_key   key;

	if ( stat ( config->alert_history_file, &st ) < 0 )
		return NULL;

	if ( ! S_ISREG ( st.st_mode ))
		AI_fatal_err ( "The specified alert history file is not a regular file", __FILE__, __LINE__ );

	if ( !( fp = fopen ( config->alert_history_file, "r" )))
		AI_fatal_err ( "Unable to read from the alert history file", __FILE__, __LINE__ );

	AI_alerts_hash_free ( &alerts_hash );

	if ( fread ( &lists_count, sizeof ( unsigned int ), 1, fp ) <= 0 )
		AI_fatal_err ( "Malformed binary history file", __FILE__, __LINE__ );

	/* Fill the hash table reading from the file */
	for ( i=0; i < lists_count; i++ )
	{
		event_iterator = NULL;
		event_prev     = NULL;

		if ( fread ( &items_count, sizeof ( unsigned int ), 1, fp ) <= 0 )
			AI_fatal_err ( "Malformed history file", __FILE__, __LINE__ );
		
		for ( j=0; j < items_count; j++ )
		{
			if ( j == 0 )
			{
				if ( !( event_list = ( AI_alert_event* ) malloc ( sizeof ( AI_alert_event ))))
					AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
				
				memset ( event_list, 0, sizeof ( AI_alert_event ));
				event_iterator = event_list;
			} else {
				if ( !( event_iterator = ( AI_alert_event* ) malloc ( sizeof ( AI_alert_event ))))
					AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
				memset ( event_iterator, 0, sizeof ( AI_alert_event ));
			}

			event_iterator->count = items_count;

			if ( fread ( &( event_iterator->key ), sizeof ( event_iterator->key ), 1, fp ) <= 0 )
				AI_fatal_err ( "Malformed alert history file", __FILE__, __LINE__ );

			if ( fread ( &( event_iterator->timestamp ), sizeof ( event_iterator->timestamp ), 1, fp ) <= 0 )
				AI_fatal_err ( "Malformed alert history file", __FILE__, __LINE__ );

			if ( event_prev )
			{
				event_prev->next = event_iterator;
			}

			event_prev = event_iterator;
		}

		key = event_iterator->key;
		HASH_ADD ( hh, alerts_hash, key, sizeof ( key ), event_list );
	}

	fclose ( fp );
	return (void*) alerts_hash;
}		/* -----  end of function AI_deserialize_alerts  ----- */


/**
 * \brief  Serialize a buffer of alerts to the binary history file
 * \param  alerts_pool Buffer of alerts to be serialized
 * \param  alerts_pool_count Number of alerts in the buffer
 */

void
AI_serialize_alerts ( AI_snort_alert **alerts_pool, unsigned int alerts_pool_count )
{
	unsigned int        i,
					hash_count      = 0,
					list_count      = 0;
	FILE                *fp             = NULL;
	AI_alert_event_key  key;
	AI_alert_event      *found          = NULL,
					*event          = NULL,
					*event_next     = NULL,
					*event_iterator = NULL;

	if ( !alerts_hash )
	{
		AI_deserialize_alerts();
	}

	for ( i=0; i < alerts_pool_count; i++ )
	{
		if ( !( event = ( AI_alert_event* ) malloc ( sizeof ( AI_alert_event ))))
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

		memset ( event, 0, sizeof ( AI_alert_event ));
		key.gid = alerts_pool[i]->gid;
		key.sid = alerts_pool[i]->sid;
		key.rev = alerts_pool[i]->rev;
		event->key = key;
		event->timestamp = alerts_pool[i]->timestamp;

		HASH_FIND ( hh, alerts_hash, &key, sizeof ( key ), found );

		if ( !found )
		{
			event->count = 1;
			event->next  = NULL;
			HASH_ADD ( hh, alerts_hash, key, sizeof ( key ), event );
		} else {
			found->count++;
			event_next = NULL;

			for ( event_iterator = found; event_iterator->next; event_iterator = event_iterator->next )
			{
				/* Insert the new event in cronological order */
				if ( event_iterator->next->timestamp > event->timestamp )
				{
					event_next = event_iterator->next;
					break;
				}
			}

			if ( event_iterator )
				event_iterator->next = event;
			
			event->next = event_next;
		}
	}
	
	hash_count = HASH_COUNT ( alerts_hash );

	if ( !( fp = fopen ( config->alert_history_file, "w" )))
		AI_fatal_err ( "Unable to write on the alert history file", __FILE__, __LINE__ );
	fwrite ( &hash_count, sizeof ( hash_count ), 1, fp );

	for ( event = alerts_hash; event; event = ( AI_alert_event* ) event->hh.next )
	{
		list_count = event->count;
		fwrite ( &list_count, sizeof ( list_count ), 1, fp );

		for ( event_iterator = event; event_iterator; event_iterator = event_iterator->next )
		{
			fwrite ( &(event_iterator->key), sizeof ( event_iterator->key ), 1, fp );
			fwrite ( &(event_iterator->timestamp), sizeof ( event_iterator->timestamp ), 1, fp );
		}
	}

	fclose ( fp );
}		/* -----  end of function AI_serialize_alerts  ----- */

/**
 * \brief  Get the sequence of alerts saved in the history file given the ID of the alert
 * \param  key  Key representing the Snort ID of the alert
 * \return The flow of events of that type of alert saved in the history
 */

const AI_alert_event*
AI_get_alert_events_by_key ( AI_alert_event_key key )
{
	AI_alert_event *found = NULL;
	HASH_FIND ( hh, alerts_hash, &key, sizeof ( key ), found );
	return found;
}         /* -----  end of function AI_get_alert_events_by_key  ----- */


/**
 * \brief  Get the number of alerts saved in the history file
 * \return The number of single alerts (not alert types) saved in the history file
 */

unsigned int
AI_get_history_alert_number ()
{
	unsigned int         alert_count     = 0;
	AI_alert_event       *event_iterator = NULL;

	if ( !alerts_hash )
	{
		AI_deserialize_alerts();
	}

	for ( event_iterator = alerts_hash; event_iterator; event_iterator = ( AI_alert_event* ) event_iterator->hh.next )
	{
		alert_count += event_iterator->count;
	}

	return alert_count;
}		/* -----  end of function AI_get_history_alert_number  ----- */

/* @} */

