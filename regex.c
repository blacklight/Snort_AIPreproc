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

#include	"spp_ai.h"
#include	"uthash.h"

#include	<alloca.h>
#include	<regex.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

/** \defgroup regex Regex management
 * @{ */

/** Compiled and cached regular expression entry */
struct regex_cache_entry {
	/** The expression itself, used as the key of the hashtable */
    char	 expression[0xFF];
	/** The compiled expression */
    regex_t *compiled;
	/** Make the struct 'hashable' */
	UT_hash_handle hh;
};

/** 
 * Regular expression cache container 
 * TODO: Free the cache at the end of program execution.
 */
static struct regex_cache_entry *reg_cache = NULL;

/**
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
	regex_t    *regex = NULL;
	regmatch_t *m = NULL;
	struct regex_cache_entry *cached_regex;

	if ( nmatches )
		*nmatches = 0;
	
	/*
	 * Search for a compiled regex in the cache.
	 */
	HASH_FIND_STR( reg_cache, expr, cached_regex );

	if( cached_regex != NULL ){
		/*
		 * Yeppa!
		 */
		regex = cached_regex->compiled;
	} else {
		/*
		 * Not found, create a new structure, compile the regexp and add it to the cache
		 * for latter use.
		 */
		regex = (regex_t *)malloc( sizeof(regex_t) );
		if ( regcomp ( regex, expr, REG_EXTENDED | REG_ICASE ) != 0 )  {
			return -1;
		}
		cached_regex = (struct regex_cache_entry *)malloc( sizeof( struct regex_cache_entry ) );
		
		strncpy( cached_regex->expression, expr, 0xFF );
		cached_regex->compiled = regex;
		/*
		 * The key is the expression itself.
		 */
		HASH_ADD_STR( reg_cache, expression, cached_regex );
	}

	if ( regex->re_nsub > 0 )
	{
		if ( !(m = (regmatch_t*) alloca ( (regex->re_nsub+1) * sizeof(regmatch_t) )) )
		{
			regfree ( regex );
			fprintf ( stderr, "\nDynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			exit ( EXIT_FAILURE );
		}

		if ( matches )
		{
			if ( !( *matches = (char**) malloc ( (regex->re_nsub+1) * sizeof(char*) )) )
			{
				regfree ( regex );
				m = NULL;
				fprintf ( stderr, "\nDynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
				exit ( EXIT_FAILURE );
			}
		}

		if ( regexec ( regex, str, regex->re_nsub+1, m, 0 ) == REG_NOMATCH )  {
			m = NULL;
			return 0;
		}
	} else {
		if ( regexec ( regex, str, 0, NULL, 0 ) == REG_NOMATCH )  {
			m = NULL;
			return 0;
		}
	}

	if ( nmatches )
		*nmatches = regex->re_nsub;

	if ( matches )
	{
		for ( i=0; i < regex->re_nsub; i++ )  {
			if ( !( (*matches)[i] = (char*) malloc ( m[i+1].rm_eo - m[i+1].rm_so + 1 )) )
			{
				regfree ( regex );
				free ( m );
				m = NULL;
				fprintf ( stderr, "\nDynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
				exit ( EXIT_FAILURE );
			}

			memset ( (*matches)[i], 0, m[i+1].rm_eo - m[i+1].rm_so + 1 );
			strncpy ( (*matches)[i], str + m[i+1].rm_so, m[i+1].rm_eo - m[i+1].rm_so );
		}
	}

	m = NULL;
	return 1;
}		/* -----  end of function preg_match  ----- */

/**
 * \brief  Replace the content of 'orig' in 'str' with 'rep'
 * \param  str 	String to work on
 * \param  orig 	String to be replaced
 * \param  rep 	Replacement for 'orig'
 * \return The string with the replacement
 */

char*
str_replace ( char *str, const char *pattern, const char *sub )
{
	char *new_s = NULL;
	unsigned int pos = 0,
			   new_len = 0;

	if ( !( pos = (unsigned int) strstr ( str, pattern )))
	{
		return strdup ( str );
	}

	pos -= (unsigned int) str;
	new_len = strlen ( str ) - strlen ( pattern ) + ((sub) ? strlen ( sub ) : 0);

	if ( !( new_s = (char*) malloc ( new_len + 1 )))
	{
		return NULL;
	}

	memset ( new_s, 0, new_len );
	strncpy ( new_s, str, pos );

	if ( sub )
	{
		if ( strlen ( sub ) > 0 )
		{
			strcat ( new_s, sub );
		}
	}

	strcat ( new_s, str + pos + strlen ( pattern ) );

	return new_s;
}		/* -----  end of function str_replace  ----- */

/* char* */
/* str_replace ( char *str, char *orig, char *rep ) */
/* { */
/* 	char         *new_s  = NULL; */
/* 	unsigned long int new_len = 0; */
/* 	unsigned long int pos     = 0; */
/*  */
/* 	if ( !( pos = (unsigned long int) strstr ( str, orig ))) */
/* 		return str; */
/*  */
/* 	new_len = strlen(str) - strlen(orig) + ((rep) ? strlen(rep) : 0) + 1; */
/*  */
/* 	if ( !( new_s = (char*) malloc ( new_len ))) */
/* 		return NULL; */
/*  */
/* 	memset ( new_s, 0, new_len ); */
/* 	strncpy ( new_s, str, pos - (unsigned long int) str ); */
/* 	new_s[ pos - (unsigned long int) str] = 0; */
/*  */
/* 	if ( rep ) */
/* 	{ */
/* 		if ( strlen ( rep ) != 0 ) */
/* 			sprintf ( new_s + pos - (unsigned long int) str, "%s%s", rep, (char*) pos + strlen ( orig )); */
/* 		else */
/* 			sprintf ( new_s + pos - (unsigned long int) str, "%s", (char*) pos + strlen ( orig )); */
/* 	} else { */
/* 		sprintf ( new_s + pos - (unsigned long int) str, "%s", (char*) pos + strlen ( orig )); */
/* 	} */
/*  */
/* 	return new_s; */
/* } */

/**
 * \brief  Replace all of the occurrences of 'orig' in 'str' with 'rep'
 * \param  str 	String to work on
 * \param  orig 	String to be replaced
 * \param  rep 	Replacement for 'orig'
 * \return The string with the replacement
 */

char*
str_replace_all ( char *str, const char *orig, const char *rep )
{
	char *buf = strdup ( str );
	char *tmp = NULL;

	while ( strstr ( buf, orig ))
	{
		if ( tmp )
			free ( tmp );

		tmp = buf;
		buf = str_replace ( buf, orig, rep );
	}

	return buf;
}		/* -----  end of function str_replace_all  ----- */

/** @} */

