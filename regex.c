/*
 * =====================================================================================
 *
 *       Filename:  regex.c
 *
 *    Description:  Regex management for the module
 *
 *        Version:  0.1
 *        Created:  08/08/2010 11:01:01
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<regex.h>

/**
 * FUNCTION: preg_match
 * \brief  Check if a string matches a regular expression
 * \param  expr 	Regular expression to be matched
 * \param  str 	String to be checked
 * \param  matches 	Reference to a char** that will contain the submatches (NULL if you don't need it)
 * \param  nmatches Reference to a int containing the number of submatches found (NULL if you don't need it)
 * \return -1 if the regex is wrong, 0 if no match was found, 1 otherwise
 */

int
preg_match ( const char* expr, char* str, char*** matches, int *nmatches )
{
	int i;
	regex_t regex;
	regmatch_t *m = NULL;
	*nmatches = 0;

	if ( regcomp ( &regex, expr, REG_EXTENDED | REG_ICASE ) != 0 )  {
		return -1;
	}

	if ( regex.re_nsub > 0 )
	{
		if ( !(m = (regmatch_t*) malloc ( (regex.re_nsub+1) * sizeof(regmatch_t) )) )
		{
			regfree ( &regex );
			fprintf ( stderr, "\nDynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			exit ( EXIT_FAILURE );
		}

		if ( !( *matches = (char**) malloc ( (regex.re_nsub+1) * sizeof(char*) )) )
		{
			regfree ( &regex );
			free ( m );
			m = NULL;
			fprintf ( stderr, "\nDynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			exit ( EXIT_FAILURE );
		}

		if ( regexec ( &regex, str, regex.re_nsub+1, m, 0 ) == REG_NOMATCH )  {
			regfree ( &regex );
			free ( m );
			m = NULL;
			return 0;
		}
	} else {
		if ( regexec ( &regex, str, 0, NULL, 0 ) == REG_NOMATCH )  {
			regfree ( &regex );
			free ( m );
			m = NULL;
			return 0;
		}
	}

	*nmatches = regex.re_nsub;

	for ( i=0; i < regex.re_nsub; i++ )  {
		if ( !( (*matches)[i] = (char*) malloc ( m[i+1].rm_eo - m[i+1].rm_so + 1 )) )
		{
			regfree ( &regex );
			free ( m );
			m = NULL;
			fprintf ( stderr, "\nDynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			exit ( EXIT_FAILURE );
		}

		memset ( (*matches)[i], 0, m[i+1].rm_eo - m[i+1].rm_so + 1 );
		strncpy ( (*matches)[i], str + m[i+1].rm_so, m[i+1].rm_eo - m[i+1].rm_so );
	}

	regfree ( &regex );
	free ( m );
	m = NULL;
	return 1;
}		/* -----  end of function preg_match  ----- */

