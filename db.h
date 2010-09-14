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

#ifdef 	HAVE_LIBMYSQLCLIENT
	#ifndef 	_AI_DB_H
	#define 	_AI_DB_H

	#include	<mysql/mysql.h>

	typedef   MYSQL_RES* 	DB_result;
	typedef 	MYSQL_ROW 	DB_row;

	#define 	DB_init 		mysql_do_init
	#define 	DB_query 		mysql_do_query
	#define 	DB_num_rows 	mysql_num_rows
	#define 	DB_fetch_row 	mysql_fetch_row
	#define 	DB_free_result mysql_free_result
	#define 	DB_close 		mysql_do_close

	/** Initializer for the database */
	void*      DB_init ( AI_config* );

	/** Execute a query on the database and returns the result */
	DB_result* DB_query ( const char* );

	/** Close the database descriptor */
	void       DB_close();

	#endif
#endif

