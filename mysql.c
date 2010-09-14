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

/** \defgroup mysql Module for the interface with a MySQL DBMS
 * @{ */

PRIVATE MYSQL     *db  = NULL;

void*
mysql_do_init ( AI_config *config )
{
	if ( !( db = (MYSQL*) malloc ( sizeof ( MYSQL ))))
		return NULL;

	if ( !( mysql_init ( db )))
		return NULL;

	if ( !mysql_real_connect ( db, config->dbhost, config->dbuser, config->dbpass, NULL, 0, NULL, 0 ))
		return NULL;

	if ( mysql_select_db ( db, config->dbname ))
		return NULL;

	return (void*) db;
}

MYSQL_RES*
mysql_do_query ( const char *query )
{
	MYSQL_RES *res = NULL;

	if ( mysql_query ( db, query ))
	{
		mysql_close ( db );
		return NULL;
	}

	if ( !( res = mysql_store_result ( db )))
	{
		mysql_close ( db );
		return NULL;
	}

	return res;
}

void
mysql_do_close ()
{
	if ( db )
		mysql_close ( db );

	free ( db );
	db = NULL;
}

/** @} */

#endif

