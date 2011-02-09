/*
 * =====================================================================================
 *
 *       Filename:  geo.c
 *
 *    Description:  Get the coordinates of an IP using www.hostip.info
 *
 *        Version:  0.1
 *        Created:  01/12/2010 17:18:21
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

#include	<arpa/inet.h>
#include	<netdb.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/socket.h>
#include	<unistd.h>

/** \defgroup geoinfo Geographic info management given an IP address using geoinfo.c
 * @{ */

/**
 * \brief  Get latitude and longitude
 * \param  ip 	IP address
 * \param  coord 	double[2] object (NULL or not) that will contain latitude and longitude
 * \return 1 if the coordinates were found, -1 otherwise
 */

int
AI_geoinfobyaddr ( const char *ip, double **coord )
{
	int i, sd, n_read, n_matches;
	char buf[1024] = { 0 },
		hostip[INET_ADDRSTRLEN] = { 0 },
		query[100] = { 0 };

	char **matches = NULL;
	FILE *fp = NULL;
	struct hostent *host = NULL;
	struct sockaddr_in addr;

	if ( *coord == NULL )
	{
		if ( !( *coord = (double*) calloc ( 2, sizeof ( double ))))
		{
			return -1;
		}
	}

	if (( sd = socket ( AF_INET, SOCK_STREAM, IPPROTO_IP )) < 0 )
	{
		return -1;
	}

	if ( !( host = gethostbyname ( "www.hostip.info" )))
	{
		return -1;
	}

	inet_ntop ( AF_INET, host->h_addr_list[0], hostip, sizeof ( hostip ));
	memset ( &addr, 0, sizeof ( addr ));

	addr.sin_family = AF_INET;
	addr.sin_port = htons ( 80 );
	addr.sin_addr.s_addr = inet_addr ( hostip );

	if ( connect ( sd, (struct sockaddr*) &addr, sizeof ( struct sockaddr )) < 0 )
	{
		return -1;
	}

	if ( !( fp = fdopen ( sd, "r+" )))
	{
		close ( sd );
		return -1;
	}

	snprintf ( query, sizeof ( query ), "spip=%s&submit=Go", ip );
	fprintf ( fp,
		"POST /index.html HTTP/1.1\r\n"
		"Host: www.hostip.info\r\n"
		"Content-Length: %lu\r\n"
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"
		"Connection: close\r\n\r\n"
		"%s\r\n",
		(unsigned long int) strlen ( query ), query
	);

	do
	{
		memset ( buf, 0, sizeof ( buf ));
		n_read = fread ( buf, sizeof ( buf ), 1, fp );

		if ( preg_match ( "new GLatLng.([^,]+), ([^\\)]+)", buf, &matches, &n_matches ) > 0 )
		{
			(*coord)[0] = strtod ( matches[0], NULL );
			(*coord)[1] = strtod ( matches[1], NULL );

			for ( i=0; i < n_matches; i++ )
			{
				free ( matches[i] );
			}

			free ( matches );
			matches = NULL;

			fclose ( fp );
			close ( sd );

			if ( (*coord)[0] == 0.0 && (*coord)[1] == 0.0 )
			{
				return -1;
			} else {
				return 1;
			}
		}

		for ( i=0; i < n_matches; i++ )
		{
			free ( matches[i] );
		}

		free ( matches );
		matches = NULL;
	} while ( n_read > 0 );

	fclose ( fp );
	close ( sd );
	return -1;
}		/* -----  end of function AI_geoinfobyaddr  ----- */

/** @} */

