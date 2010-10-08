/*
 * =====================================================================================
 *
 *       Filename:  webserv.c
 *
 *    Description:  Web server for managing the web interface of the module
 *
 *        Version:  0.1
 *        Created:  05/10/2010 14:12:24
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

#include	<alloca.h>
#include 	<pthread.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/stat.h>
#include	<time.h>
#include	<unistd.h>

/** \defgroup webserv Web server managing the web interface of the module
 * @{ */

#define 	HTTP_RESPONSE_HEADERS_FORMAT 	"%s %d %s\r\n" \
								"Date: %s\r\n" \
								"Server: %s\r\n" \
								"Content-Type: %s\r\n" \
								"Content-Length: %u\r\n\r\n"

#define 	HTTP_CGI_RESPONSE_HEADERS_FORMAT 	"%s %d %s\r\n" \
									"Date: %s\r\n" \
									"Server: %s\r\n" \
									"Content-Length: %u\r\n"

#define 	HTTP_ERR_RESPONSE_FORMAT 	"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n" \
								"<html><head>\n" \
								"<title>%u %s</title>\n" \
								"</head><body>\n" \
								"<h1>%s</h1>\n" \
								"<p>%s</p>\n" \
								"<hr>\n" \
								"<i>%s</i>\n" \
								"</body></html>\n\n"

typedef struct  {
	int sd;
	struct sockaddr_in client;
} conn_info;

/**
 * \brief  Escape a string to be used or included in an URL
 * \param  str 	String to be escaped
 * \param  out 	Pointer to the string containing the output (its length must be at least 3*length(str) + 2)
 * \param  str_len 	Length of the input string
 * \return The length of the output string after the operation
 */

size_t
__AI_url_escape ( char *str, char **out, size_t str_len )
{
	char   escape_seq[5] = { 0 };
	size_t i,
		  out_len = 0;

	for ( i=0; i < str_len; i++ )
	{
		if (
				( str[i] >= 'a' && str[i] <= 'z' ) ||
				( str[i] >= 'A' && str[i] <= 'Z' ) ||
				( str[i] >= '0' && str[i] <= '9' ) ||
				str[i] == '_' || str[i] == '.' || str[i] == '/' ||
				str[i] == '?' || str[i] == '=' )
		{
			(*out)[out_len++] = str[i];
		} else {
			snprintf ( escape_seq, sizeof ( escape_seq ), "%%%.2X", str[i] );
			(*out)[out_len++] = escape_seq[0];
			(*out)[out_len++] = escape_seq[1];
			(*out)[out_len++] = escape_seq[2];
		}
	}

	(*out)[out_len] = 0;
	return out_len;
}		/* -----  end of function __AI_url_escape  ----- */

/**
 * \brief  Unescape a string in URL format
 * \param  str 	String to be unescaped
 * \param  out 	Pointer to the string containing the output (its length must be at least the same of str + 1)
 * \param  str_len 	Length of the input string
 * \return The length of the output string after the operation
 */

PRIVATE size_t
__AI_url_unescape ( char *str, char **out, size_t str_len )
{
	char   escape_seq[5] = { 0 };
	size_t i,
		  out_len = 0;

	for ( i=0; i < str_len; i++ )
	{
		if ( str[i] == '%' && i < str_len-2 )
		{
			if (
					(( str[i+1] >= '0' && str[i+1] <= '9' ) ||
					(  str[i+1] >= 'a' && str[i+1] <= 'z' ) ||
					(  str[i+1] >= 'A' && str[i+1] <= 'Z' )) &&
					(( str[i+2] >= '0' && str[i+2] <= '9' ) ||
					(  str[i+2] >= 'a' && str[i+2] <= 'z' ) ||
					(  str[i+2] >= 'A' && str[i+2] <= 'Z' )))
			{
				escape_seq[0] = str[i+1];
				escape_seq[1] = str[i+2];
				escape_seq[2] = 0;
				(*out)[out_len++] = (char) strtoul ( escape_seq, NULL, 16 );
				i += 2;
				continue;
			}
		}

		(*out)[out_len++] = str[i];
	}

	(*out)[out_len] = 0;
	return out_len;
}		/* -----  end of function __AI_url_unescape  ----- */

/**
 * \brief  Read a line from a file descriptor
 * \param  fp  FILE descriptor
 * \return A char* pointer to the read line (to be free-ed!!!)
 */

PRIVATE char*
__AI_getline ( FILE *fp )
{
	char ch;
	char *line  = NULL;
	int  nbytes = 1;

	if ( !feof ( fp ))
	{
		while (( ch = fgetc ( fp )) != '\n' && ch != '\0' && !feof ( fp ))
		{
			if ( ch == '\r' )
				continue;

			if ( !( line = (char*) realloc ( line, ++nbytes )))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation", __FILE__, __LINE__ );
			}

			line[ nbytes - 2 ] = ch;
		}
	}

	if ( nbytes > 1 )
	{
		line[ nbytes - 1 ] = 0;
	}

	return line;
} 			/* -----  end of function __AI_getline  ----- */

/**
 * \brief  Manage a client connection
 * \param  arg 	void* reference to the client socket
 */

PRIVATE void*
__AI_webservlet_thread ( void *arg )
{
	time_t ltime     = time ( NULL );
	struct stat st;
	BOOL   is_cgi    = false;

	FILE *sock = NULL,
		*fp   = NULL,
		*pipe = NULL;

	int  i,
		http_response_len = 0,
		sd = ((conn_info*) arg)->sd,
		nlines   = 0,
		nmatches = 0,
		max_content_length = 0,
		max_headers_length = 0,
		req_file_absolute_path_size = 0;

	char ch,
		client_addr[INET_ADDRSTRLEN] = { 0 },
		client_port[10] = { 0 },
		*line          = NULL,
		*unescaped     = NULL,
		*cgi_cmd       = NULL,
		*query_string  = NULL,
		*http_response = NULL,
		*http_headers  = NULL,
		*strtime       = NULL,
		**matches      = NULL,
		*req_file_absolute_path = NULL,
		content_type[108] = { 0 },
		extension[100]    = { 0 },
		http_ver[10]      = { 0 },
		req_file[1024]    = { 0 };

	max_content_length = strlen ( HTTP_ERR_RESPONSE_FORMAT ) + strlen ( config->webserv_banner ) + 1000;
	max_headers_length = strlen ( HTTP_RESPONSE_HEADERS_FORMAT ) + strlen ( config->webserv_banner ) + 1000;

	/* Setting environment variables */
	inet_ntop ( AF_INET, &(((conn_info*) arg)->client.sin_addr.s_addr), client_addr, INET_ADDRSTRLEN );
	snprintf ( client_port, sizeof ( client_port ), "%d", htons (((conn_info*) arg)->client.sin_port) );

	setenv ( "CLIENT_PROTOCOL", "HTTP", 1 );
	setenv ( "DOCUMENT_ROOT", config->webserv_dir, 1 );
	setenv ( "GATEWAY_INTERFACE", "CGI/1.1", 1 );
	setenv ( "REMOTE_ADDR", client_addr, 1 );
	setenv ( "REMOTE_PORT", client_port, 1 );

	if ( !( http_response = (char*) alloca ( max_content_length )))
	{
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	if ( !( http_headers = (char*) alloca ( max_headers_length )))
	{
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	if ( !( sock = fdopen ( sd, "r+" )))
	{
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	req_file_absolute_path_size = sizeof ( req_file ) + strlen ( config->webserv_dir ) + 1;

	if ( !( req_file_absolute_path = (char*) alloca ( req_file_absolute_path_size )))
	{
		pthread_exit ((void*) 0);
		return (void*) 0;
	}

	for ( nlines=0; ( line = __AI_getline ( sock )); nlines++ )
	{
		if ( preg_match ( "^\\s*(GET|POST|HEAD)\\s+(/[^ \\?#]*)(\\?|#)?([^ ]+)?\\s*(HTTP/[0-9]\\.[0-9])?", line, &matches, &nmatches ) > 0 )
		{
			setenv ( "REQUEST_METHOD", matches[0], 1 );

			if ( !strcmp ( matches[2], "?" ))
			{
				if ( strlen ( matches[3] ) > 0 )
				{
					query_string = strdup ( matches[3] );
					setenv ( "QUERY_STRING", query_string, 1 );
				}
			}

			if ( strlen ( matches[4] ) > 0 )
			{
				strncpy ( http_ver, matches[4], sizeof ( http_ver ));
			} else {
				strncpy ( http_ver, "HTTP/1.0", sizeof ( http_ver ));
			}

			setenv ( "SERVER_PROTOCOL", http_ver, 1 );

			if ( !strcmp ( matches[1], "/" ))
			{
				free ( matches[1] );
				matches[1] = strdup ( "/index.html" );
			}

			setenv ( "DOCUMENT_URI", matches[1], 1 );
			setenv ( "DOCUMENT_URL", matches[1], 1 );
			setenv ( "REQUEST_URI", matches[1], 1 );
			setenv ( "URI", matches[1], 1 );
			setenv ( "URL", matches[1], 1 );

			snprintf ( req_file_absolute_path, req_file_absolute_path_size, "%s%s", config->webserv_dir, matches[1] );

			if ( strcmp ( http_ver, "HTTP/1.0" ) && strcmp ( http_ver, "HTTP/1.1" ))
			{
				snprintf ( http_response, max_content_length, HTTP_ERR_RESPONSE_FORMAT,
					400, "Bad Request", "Bad Request",
					"The request could not be understood by the server due to malformed syntax",
					config->webserv_banner );

				ltime = time ( NULL );
				strtime = strdup ( ctime ( &ltime ));
				strtime [ strlen(strtime) - 1 ] = 0;
				snprintf ( http_headers, max_headers_length, HTTP_RESPONSE_HEADERS_FORMAT,
					"HTTP/1.1", 400, "Bad Request", strtime,
					config->webserv_banner, "text/html", strlen ( http_response ));
				free ( strtime );
				free ( line );
				line = NULL;
				continue;
			}

			for ( i=0; i < nmatches; i++ )
			{
				free ( matches[i] );
			}

			free ( matches );
			matches = NULL;

			if ( !( unescaped = (char*) alloca ( strlen ( req_file_absolute_path ) + 2 )))
			{
				pthread_exit ((void*) 0);
				return (void*) 0;
			}

			/* Avoid directory traversal */
			__AI_url_unescape ( req_file_absolute_path, &unescaped, strlen ( req_file_absolute_path ));
			unescaped = str_replace_all ( unescaped, "../", "" );
			strncpy ( req_file_absolute_path, unescaped, req_file_absolute_path_size );
			free ( unescaped );

			if ( stat ( req_file_absolute_path, &st ) < 0 )
			{
				snprintf ( http_response, max_content_length, HTTP_ERR_RESPONSE_FORMAT,
						404, "Not Found", "Not Found",
						"The requested resource was not found on the server",
						config->webserv_banner );

				ltime = time ( NULL );
				strtime = strdup ( ctime ( &ltime ));
				strtime [ strlen(strtime) - 1 ] = 0;
				snprintf ( http_headers, max_headers_length, HTTP_RESPONSE_HEADERS_FORMAT,
						http_ver, 404, "Not Found", strtime,
						config->webserv_banner, "text/html", strlen ( http_response ));
				free ( strtime );
				free ( line );
				line = NULL;
				continue;
			}

			if ( !( fp = fopen ( req_file_absolute_path, "r" ))) {
				snprintf ( http_response, max_content_length, HTTP_ERR_RESPONSE_FORMAT,
						403, "Forbidden", "Forbidden",
						"The client does not have enough permissions for accessing the requested resource on the server",
						config->webserv_banner );

				ltime = time ( NULL );
				strtime = strdup ( ctime ( &ltime ));
				strtime [ strlen(strtime) - 1 ] = 0;
				snprintf ( http_headers, max_headers_length, HTTP_RESPONSE_HEADERS_FORMAT,
						http_ver, 403, "Forbidden", strtime,
						config->webserv_banner, "text/html", strlen ( http_response ));
				free ( strtime );
				free ( line );
				line = NULL;
				continue;
			}

			if ( preg_match ( "\\.([a-zA-Z0-9]+)$", req_file_absolute_path, &matches, &nmatches ) > 0 )
			{
				if ( strlen ( matches[0] ) < sizeof ( extension ))
				{
					strncpy ( extension, matches[0], sizeof ( extension ));
				}
			}

			if ( !strcasecmp ( extension, "html" ))
			{
				strncpy ( content_type, "text/html", sizeof ( content_type ));
			} else if ( !strcasecmp ( extension, "css" )) {
				strncpy ( content_type, "text/css", sizeof ( content_type ));
			} else if ( !strcasecmp ( extension, "js" )) {
				strncpy ( content_type, "application/x-javascript", sizeof ( content_type ));
			} else if ( !strcasecmp ( extension, "json" )) {
				strncpy ( content_type, "application/json", sizeof ( content_type ));
			} else if ( !strcasecmp ( extension, "jpg" ) || !strcasecmp ( extension, "jpeg" )) {
				strncpy ( content_type, "image/jpeg", sizeof ( content_type ));
			} else if ( !strcasecmp ( extension, "cgi" )) {
				/* If it's not executable, it's not a CGI */
				if ( !( st.st_mode & S_IXOTH ))
					strncpy ( content_type, "text/plain", sizeof ( content_type ));
				else {
					is_cgi = true;
					http_response = NULL;
					http_response_len = 1;

					if ( !( cgi_cmd = (char*) alloca ( strlen ( req_file_absolute_path ) + 20 )))
					{
						pthread_exit ((void*) 0);
						return (void*) 0;
					}

					sprintf ( cgi_cmd, "/bin/sh -c %s", req_file_absolute_path );

					if ( !( pipe = popen ( cgi_cmd, "r" )))
					{
						pthread_exit ((void*) 0);
						return (void*) 0;
					}

					while ( fread ( &ch, 1, 1, pipe ) > 0 )
					{
						if ( !( http_response = (char*) realloc ( http_response, ++http_response_len )))
						{
							pthread_exit ((void*) 0);
							return (void*) 0;
						}

						http_response [ http_response_len - 2 ] = ch;
					}

					http_response [ http_response_len - 1 ] = 0;
					pclose ( pipe );

					if ( !http_response )
					{
						if ( !( http_response = (char*) malloc ( 2 )))
						{
							pthread_exit ((void*) 0);
							return (void*) 0;
						}

						http_response[0] = 0;
					}
				}
			} else if ( !strcasecmp ( extension, "gif" ) || !strcasecmp ( extension, "png" ) ||
					!strcasecmp ( extension, "bmp" ) || !strcasecmp ( extension, "tif" ) ||
					!strcasecmp ( extension, "ppm" ))  {
				snprintf ( content_type, sizeof ( content_type ),
						"image/%s", extension );
			} else {
				strncpy ( content_type, "text/plain", sizeof ( content_type ));
			}

			if ( !is_cgi )
			{
				if ( !( http_response = (char*) alloca ( st.st_size + 2 )))
				{
					pthread_exit ((void*) 0);
					return (void*) 0;
				}

				memset ( http_response, 0, st.st_size + 2 );
				fread ( http_response, st.st_size, 1, fp );
				fclose ( fp );
			}

			ltime = time ( NULL );
			strtime = strdup ( ctime ( &ltime ));
			strtime [ strlen(strtime) - 1 ] = 0;

			if ( is_cgi )
			{
				snprintf ( http_headers, max_headers_length, HTTP_CGI_RESPONSE_HEADERS_FORMAT,
						http_ver, 200, "Found", strtime, config->webserv_banner, strlen ( http_response ));
			} else {
				snprintf ( http_headers, max_headers_length, HTTP_RESPONSE_HEADERS_FORMAT,
						http_ver, 200, "Found", strtime, config->webserv_banner,
						content_type, strlen ( http_response ));
			}

			free ( strtime );
			free ( line );
			line = NULL;
			continue;
		} else {
			if ( nlines == 0 )
			{
				snprintf ( http_response, max_content_length, HTTP_ERR_RESPONSE_FORMAT,
						405, "Method Not Allowed", "Method Not Allowed",
						"The requested HTTP method is not allowed",
						config->webserv_banner );

				ltime = time ( NULL );
				strtime = strdup ( ctime ( &ltime ));
				strtime [ strlen(strtime) - 1 ] = 0;
				snprintf ( http_headers, max_headers_length, HTTP_RESPONSE_HEADERS_FORMAT,
						"HTTP/1.1", 405, "Method Not Allowed", strtime, "text/html",
						config->webserv_banner, strlen ( http_response ));
				free ( strtime );
				free ( line );
				line = NULL;
				continue;
			} else if ( preg_match ( "\\s*Content-Length\\s*:\\s*([0-9]+)", line, &matches, &nmatches ) > 0 ) {
				setenv ( "CONTENT_LENGTH", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Content-Type\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "CONTENT_TYPE", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Accept\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_ACCEPT", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Accept-Charset\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_ACCEPT_CHARSET", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Accept-Encoding\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_ACCEPT_ENCODING", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Accept-Language\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_ACCEPT_LANGUAGE", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Connection\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_CONNECTION", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Cookie\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_COOKIE", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Reason\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_REASON", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*User-Agent\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_USER_AGENT", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			} else if ( preg_match ( "\\s*Referrer\\s*:\\s*(.+?)\r?\n?$", line, &matches, &nmatches ) > 0 ) {
				setenv ( "HTTP_REFERRER", matches[0], 1 );

				for ( i=0; i < nmatches; i++ )
					free ( matches[i] );

				free ( matches );
				matches = NULL;
			}
		}

		free ( line );
		line = NULL;
	}

	fprintf ( sock, "%s%s", http_headers, http_response );
	fclose ( sock );
	close ( sd );
	free ( arg );

	if ( query_string )
		free ( query_string );

	if ( is_cgi )
		free ( http_response );

	pthread_exit ( 0 );
	return (void*) 0;
}		/* -----  end of function __AI_webservlet_thread  ----- */

/**
 * \brief  Thread running the code of the web server for the web interface of the module
 */

void*
AI_webserv_thread ( void *arg )
{
	int on = 1,
	    sd,
	    sockaddr_size;

	struct sockaddr_in addr;
	pthread_t servlet_thread;
	pthread_attr_t attr;
	conn_info *conn;

	if (( sd = socket ( AF_INET, SOCK_STREAM, 0 )) < 0 )
	{
		AI_fatal_err ( "Error while creating webserver socket", __FILE__, __LINE__ );
	}

	if ( setsockopt ( sd, SOL_SOCKET, SO_REUSEADDR, (void*) &on, sizeof ( on )) < 0 )
	{
		AI_fatal_err ( "Error while setting SO_REUSEADDR on the socket", __FILE__, __LINE__ );
	}

	memset ( &addr, 0, sizeof ( struct sockaddr_in ));
	addr.sin_family = AF_INET;
	addr.sin_port = htons ( config->webserv_port );
	addr.sin_addr.s_addr = INADDR_ANY;

	if ( bind ( sd, (struct sockaddr*) &addr, sizeof ( addr )) < 0 )
	{
		AI_fatal_err ( "Error while binding socket", __FILE__, __LINE__ );
	}

	if ( listen ( sd, 100 ) < 0 )
	{
		AI_fatal_err ( "Error while setting the socket in listen mode", __FILE__, __LINE__ );
	}

	pthread_attr_init ( &attr );
	pthread_attr_setdetachstate ( &attr, PTHREAD_CREATE_DETACHED );

	while ( 1 )
	{
		if ( !( conn = (conn_info*) malloc ( sizeof ( conn_info ))))
			continue;

		memset ( conn, 0, sizeof ( conn ));

		if (( conn->sd = accept ( sd, (struct sockaddr*) &(conn->client), (socklen_t*) &sockaddr_size )) < 0 )
			continue;

		if ( pthread_create ( &servlet_thread, &attr, __AI_webservlet_thread, (void*) conn ) != 0 )
		{
			AI_fatal_err ( "Error while creating the webservlet thread", __FILE__, __LINE__ );
		}
	}

	close ( sd );
	pthread_exit ((void*) 0);
	return (void*) 0;
}		/* -----  end of function AI_webserv_thread  ----- */

/** @} */

