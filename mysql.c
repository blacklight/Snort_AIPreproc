/*
 * =====================================================================================
 *
 *       Filename:  mysql.c
 *
 *    Description:  Interface to a MySQL database
 *
 *        Version:  0.1
 *        Created:  04/09/2010 20:16:47
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
#ifdef 	HAVE_LIBMYSQLCLIENT

#include	<mysql/mysql.h>
#include	<mysql/errmsg.h>

/** \defgroup mysql Module for the interface with a MySQL DBMS
 * @{ */

/***************************/
/* Database descriptors */
PRIVATE MYSQL *db    = NULL;
PRIVATE MYSQL *outdb = NULL;
/***************************/

/*************************************************************/
/* Private functions (operating on the database descriptors) */

PRIVATE bool
__mysql_is_init ( MYSQL *__DB )
{
	return ( __DB != NULL );
}

PRIVATE void*
__mysql_do_init ( MYSQL **__DB, bool is_out )
{
	if ( __mysql_is_init ( *__DB ) )
		return (void*) *__DB;

	if ( !( *__DB = (MYSQL*) malloc ( sizeof ( MYSQL ))))
	{
		return NULL;
	}

	if ( !( mysql_init ( *__DB )))
	{
		return NULL;
	}

	if ( is_out )
	{
		if ( !mysql_real_connect ( *__DB, config->outdbhost, config->outdbuser, config->outdbpass, NULL, 0, NULL, 0 ))
		{
			return NULL;
		}

		if ( mysql_select_db ( *__DB, config->outdbname ))
		{
			return NULL;
		}
	} else {
		if ( !mysql_real_connect ( *__DB, config->dbhost, config->dbuser, config->dbpass, NULL, 0, NULL, 0 ))
			return NULL;

		if ( mysql_select_db ( *__DB, config->dbname ))
			return NULL;
	}

	return (void*) *__DB;
}

PRIVATE void
__mysql_do_close ( MYSQL **__DB )
{
	if ( *__DB )
		mysql_close ( *__DB );

	free ( *__DB );
	*__DB = NULL;
}

PRIVATE MYSQL_RES*
__mysql_do_query ( MYSQL *__DB, const char *query )
{
	MYSQL_RES *res = NULL;

	if ( mysql_query ( __DB, query ))
	{
		return NULL;
	}

	if ( !( res = mysql_store_result ( __DB )))
		return NULL;

	return res;
}

/* End of private functions */
/****************************/

/********************/
/* Public functions */

bool
mysql_is_init ()
{
	return __mysql_is_init ( db );
}

void*
mysql_do_init ()
{
	return __mysql_do_init ( &db, false );
}

bool
mysql_is_gone ()
{
	return (( mysql_errno ( db ) == CR_SERVER_GONE_ERROR ) || ( mysql_errno ( db ) == CR_SERVER_LOST ));
}

MYSQL_RES*
mysql_do_query ( const char *query )
{
	if ( !db )
		mysql_do_init();

	return __mysql_do_query ( db, query );
}

unsigned long
mysql_do_escape_string ( char **to, const char *from, unsigned long length )
{
	if ( !from )
		return 0;

	if ( strlen ( from ) == 0 )
		return 0;

	return mysql_real_escape_string ( db, *to, from, length );
}

const char*
mysql_do_error ()
{
	return mysql_error ( db );
}

void
mysql_do_close ()
{
	__mysql_do_close ( &db );
}

/* Output database functions */

bool
mysql_is_out_init ()
{
	return __mysql_is_init ( outdb );
}

void*
mysql_do_out_init ()
{
	return __mysql_do_init ( &outdb, true );
}

bool
mysql_is_out_gone ()
{
	return (( mysql_errno ( outdb ) == CR_SERVER_GONE_ERROR ) || ( mysql_errno ( outdb ) == CR_SERVER_LOST ));
}

MYSQL_RES*
mysql_do_out_query ( const char *query )
{
	if ( !outdb )
		mysql_do_out_init();

	return __mysql_do_query ( outdb, query );
}

unsigned long
mysql_do_out_escape_string ( char **to, const char *from, unsigned long length )
{
	if ( !from )
		return 0;

	if ( strlen ( from ) == 0 )
		return 0;

	return mysql_real_escape_string ( outdb, *to, from, length );
}

const char*
mysql_do_out_error ()
{
	return mysql_error ( outdb );
}

void
mysql_do_out_close ()
{
	__mysql_do_close ( &outdb );
}

/* End of public functions */
/***************************/

/** @} */

#endif
