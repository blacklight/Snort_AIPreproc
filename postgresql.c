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

/***************************/
/* Database descriptors */
PRIVATE PGconn *db    = NULL;
PRIVATE PGconn *outdb = NULL;
/***************************/

/*************************************************************/
/* Private functions (operating on the database descriptors) */

PRIVATE BOOL
__postgresql_is_init ( PGconn *__DB )
{
	return ( __DB != NULL );
}

PRIVATE void*
__postgresql_do_init ( PGconn **__DB, BOOL is_out )
{
	char *conninfo = NULL;
	int  conninfo_max_length =
		( is_out ?
		  ((config->outdbhost) ? strlen ( config->outdbhost ) : 0) +
		  ((config->outdbuser) ? strlen ( config->outdbuser ) : 0) +
		  ((config->outdbpass) ? strlen ( config->outdbpass ) : 0) +
		  ((config->outdbname) ? strlen ( config->outdbname ) : 0) :

		  ((config->dbhost) ? strlen ( config->dbhost ) : 0) +
		  ((config->dbuser) ? strlen ( config->dbuser ) : 0) +
		  ((config->dbpass) ? strlen ( config->dbpass ) : 0) +
		  ((config->dbname) ? strlen ( config->dbname ) : 0)) + 100;

	if ( postgresql_is_init ( *__DB ))
		return (void*) *__DB;
	
	if ( !( conninfo = (char*) alloca ( conninfo_max_length )))
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

	memset ( conninfo, 0, conninfo_max_length );

	if ( is_out )
	{
		snprintf ( conninfo, conninfo_max_length, "dbname=%s", config->outdbname );

		if ( config->outdbuser )
			sprintf ( conninfo, "%s user=%s", conninfo, config->outdbuser );

		if ( config->outdbpass )
			sprintf ( conninfo, "%s password=%s", conninfo, config->outdbpass );

		if ( config->outdbhost )
			sprintf ( conninfo, "%s hostaddr=%s", conninfo, config->outdbhost );
	} else {
		snprintf ( conninfo, conninfo_max_length, "dbname=%s", config->dbname );

		if ( config->dbuser )
			sprintf ( conninfo, "%s user=%s", conninfo, config->dbuser );

		if ( config->dbpass )
			sprintf ( conninfo, "%s password=%s", conninfo, config->dbpass );

		if ( config->dbhost )
			sprintf ( conninfo, "%s hostaddr=%s", conninfo, config->dbhost );
	}

	if ( PQstatus ( *__DB = PQconnectdb ( conninfo )) != CONNECTION_OK )
		return NULL;

	return (void*) *__DB;
}

PRIVATE PSQL_result*
__postgresql_do_query ( PGconn *__DB, const char *query )
{
	int i, j, ntuples, nfields;
	PSQL_result *res = NULL;

	if ( !( res = (PSQL_result*) malloc ( sizeof ( PSQL_result ))))
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

	if ( PQresultStatus ( res->res = PQexec( __DB, query )) != PGRES_TUPLES_OK )
	{
		PQfinish ( __DB );
		return NULL;
	}

	ntuples = PQntuples ( res->res );
	res->index = 0;
	res->rows  = NULL;

	if ( !( res->rows = ( char*** ) malloc ( ntuples * sizeof ( char** ))))
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

	for ( i=0; i < ntuples; i++ )
	{
		nfields = PQnfields ( res->res );

		if ( !( res->rows[i] = ( char** ) malloc ( nfields * sizeof ( char* ))))
			AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );

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

PRIVATE void
__postgresql_do_close ( PGconn **__DB )
{
	if ( *__DB )
		PQfinish ( *__DB );

	*__DB = NULL;
}

/* End of private functions */
/****************************/

/********************/
/* Public functions */

BOOL
postgresql_is_init ()
{
	return __postgresql_is_init ( db );
}

void*
postgresql_do_init ()
{
	return __postgresql_do_init ( &db, false );
}

PSQL_result*
postgresql_do_query ( const char *query )
{
	return __postgresql_do_query ( db, query );
}

void
postgresql_do_close ()
{
	__postgresql_do_close ( &db );
}

/* Output database functions */

BOOL
postgresql_is_out_init ()
{
	return __postgresql_is_init ( outdb );
}

void*
postgresql_do_out_init ()
{
	return __postgresql_do_init ( &outdb, true );
}

PSQL_result*
postgresql_do_out_query ( const char *query )
{
	return __postgresql_do_query ( outdb, query );
}

void
postgresql_do_out_close ()
{
	__postgresql_do_close ( &outdb );
}

/* End of public functions */
/***************************/

/* @} */

#endif

