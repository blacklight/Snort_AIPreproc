/*
 * =====================================================================================
 *
 *       Filename:  postgresql.c
 *
 *    Description:  Interface to a PostgreSQL database
 *
 *        Version:  0.1
 *        Created:  16/09/2010 00:23:34
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
#ifdef 	HAVE_LIBPQ

#include	<alloca.h>
#include	<postgresql/libpq-fe.h>
#include	"db.h"

/** \defgroup postgresql Module for the interface with a PostgreSQL DBMS
 * @{ */

PRIVATE PGconn   *db = NULL;

void*
postgresql_do_init ( AI_config *config )
{
	char *conninfo = NULL;
	int  conninfo_max_length =
		((config->dbhost) ? strlen ( config->dbhost ) : 0) +
		((config->dbuser) ? strlen ( config->dbuser ) : 0) +
		((config->dbpass) ? strlen ( config->dbpass ) : 0) +
		((config->dbname) ? strlen ( config->dbname ) : 0) + 100;

	if ( !( conninfo = (char*) alloca ( conninfo_max_length )))
		_dpd.fatalMsg ( "AIPreproc: Fatal dynamic memory allocation error at %s:%d\n", __FILE__, __LINE__ );

	memset ( conninfo, 0, conninfo_max_length );
	snprintf ( conninfo, conninfo_max_length, "dbname=%s", config->dbname );

	if ( config->dbuser )
		sprintf ( conninfo, "%s user=%s", conninfo, config->dbuser );

	if ( config->dbpass )
		sprintf ( conninfo, "%s password=%s", conninfo, config->dbpass );

	if ( config->dbhost )
		sprintf ( conninfo, "%s hostaddr=%s", conninfo, config->dbhost );

	if ( PQstatus ( db = PQconnectdb ( conninfo )) != CONNECTION_OK )
		return NULL;

	return (void*) db;
}

PSQL_result*
postgresql_do_query ( const char *query )
{
	int i, j, ntuples, nfields;
	PSQL_result *res = NULL;

	if ( !( res = (PSQL_result*) malloc ( sizeof ( PSQL_result ))))
		_dpd.fatalMsg ( "AIPreproc: Fatal dynamic memory allocation error at %s:%d\n", __FILE__, __LINE__ );

	if ( PQresultStatus ( res->res = PQexec( db, query )) != PGRES_TUPLES_OK )
	{
		PQfinish ( db );
		return NULL;
	}

	ntuples = PQntuples ( res->res );
	res->index = 0;
	res->rows  = NULL;

	if ( !( res->rows = ( char*** ) malloc ( ntuples * sizeof ( char** ))))
		_dpd.fatalMsg ( "AIPreproc: Fatal dynamic memory allocation error at %s:%d\n", __FILE__, __LINE__ );

	for ( i=0; i < ntuples; i++ )
	{
		nfields = PQnfields ( res->res );

		if ( !( res->rows[i] = ( char** ) malloc ( nfields * sizeof ( char* ))))
			_dpd.fatalMsg ( "AIPreproc: Fatal dynamic memory allocation error at %s:%d\n", __FILE__, __LINE__ );

		for ( j=0; j < nfields; j++ )
		{
			res->rows[i][j] = PQgetvalue ( res->res, i, j );
		}
	}

	return res;
}

int
postgresql_num_rows ( PSQL_result *res )
{
	return PQntuples ( res->res );
}

char**
postgresql_fetch_row ( PSQL_result *res )
{
	if ( (res->index++) >= PQntuples ( res->res ))
		return NULL;

	return res->rows[ res->index - 1];
}

void
postgresql_free_result ( PSQL_result *res )
{
	int i, j, ntuples;

	if ( res )
	{
		ntuples = PQntuples ( res->res );

		for ( i=0; i < ntuples; i++ )
			free ( res->rows[i] );
		free ( res->rows );

		PQclear ( res->res );
		free ( res );
	}
}

void
postgresql_do_close ()
{
	if ( db )
		PQfinish ( db );

	db = NULL;
}

/* @} */

#endif

