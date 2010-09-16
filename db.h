/*
 * =====================================================================================
 *
 *       Filename:  db.h
 *
 *    Description:  Manages the interface to several DBMS's through macros
 *
 *        Version:  0.1
 *        Created:  04/09/2010 20:21:06
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#ifdef 	HAVE_DB
	#ifndef 	_AI_DB_H
	#define 	_AI_DB_H

#ifdef 	HAVE_LIBMYSQLCLIENT
	#include	<mysql/mysql.h>

	typedef   MYSQL_RES* 	DB_result;
	typedef 	MYSQL_ROW 	DB_row;

	#define 	DB_init 		mysql_do_init
	#define 	DB_query 		mysql_do_query
	#define 	DB_num_rows 	mysql_num_rows
	#define 	DB_fetch_row 	mysql_fetch_row
	#define 	DB_free_result mysql_free_result
	#define 	DB_close 		mysql_do_close

	DB_result* DB_query ( const char* );
#endif

#ifdef 	HAVE_LIBPQ
	#include	<postgresql/libpq-fe.h>

	typedef struct  {
		PGresult *res;
		int index;
		char ***rows;
	} PSQL_result;

	typedef 	PSQL_result* 	DB_result;
	typedef 	char** 		DB_row;

	#define 	DB_init 		postgresql_do_init
	#define 	DB_query 		postgresql_do_query
	#define 	DB_num_rows 	postgresql_num_rows
	#define 	DB_fetch_row 	postgresql_fetch_row
	#define 	DB_free_result postgresql_free_result
	#define 	DB_close 		postgresql_do_close

	int 			DB_num_rows ( PSQL_result *res );
	DB_row 		DB_fetch_row ( PSQL_result *res );
	void 		DB_free_result ( PSQL_result *res );
	DB_result 	DB_query ( const char* );
#endif

	void*      DB_init ( AI_config* );
	void       DB_close();

	#endif
#endif

