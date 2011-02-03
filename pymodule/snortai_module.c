/*
 * =====================================================================================
 *
 *       Filename:  snortai_module.c
 *
 *    Description:  Python module for interfacing to SnortAI
 *
 *        Version:  0.1
 *        Created:  28/01/2011 21:33:57
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

/* This is the old C-based module for Python interface to SnortAI
 * and it is now completely *DEPRECATED* and kept only for
 * back-compatibility purposes. Use the pure Python interface
 * instead, running python setup.py build && sudo python setup.py install
 * will build and install the new Python module */

#ifndef HAVE_LIBPYTHON2_6
#define HAVE_LIBPYTHON2_6 1
#endif

#include	"spp_ai.h"

#include	<libxml/xmlreader.h>
#include	<netdb.h>
#include	<netinet/in.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<structmember.h>
#include	<sys/socket.h>

#ifndef LIBXML_READER_ENABLED
#error  "libxml2 reader not enabled\n"
#endif

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif

#ifndef DEFAULT_WEBSERV
#define DEFAULT_WEBSERV "localhost"
#endif

#ifndef DEFAULT_WEBPORT
#define DEFAULT_WEBPORT 7654
#endif

#ifndef DEFAULT_RESOURCE
#define DEFAULT_RESOURCE "/alerts.cgi"
#endif

/** Enumeration for managing XML response tags */
enum  { inAlerts, inAlert, ALERT_TAG_NUM };

static PyObject* Py_alerts ( PyObject *self, PyObject *args );
static PyObject* PyAlert_new ( PyTypeObject *type, PyObject *args, PyObject *kwds );
static int PyAlert_init ( PyAlert *self, PyObject *args, PyObject *kwds );
static void PyAlerts_free ( PyAlert *self );
PyMODINIT_FUNC initsnortai ( void );

char resource[1024] = DEFAULT_RESOURCE;
char webserv[1024] = DEFAULT_WEBSERV;
short int webport = DEFAULT_WEBPORT;
PyObject *exception = NULL;

/** Members of the Python binded alert object */
static PyMemberDef alert_members[] = {
	{ "gid", T_INT, offsetof ( PyAlert, gid ), 0, "Snort alert gID" },
	{ "sid", T_INT, offsetof ( PyAlert, sid ), 0, "Snort alert sID" },
	{ "rev", T_INT, offsetof ( PyAlert, rev ), 0, "Snort alert revision number" },
	{ "priority", T_INT, offsetof ( PyAlert, priority ), 0, "Snort alert priority" },
	{ "description", T_OBJECT_EX, offsetof ( PyAlert, desc ), 0, "Snort alert description" },
	{ "classification", T_OBJECT_EX, offsetof ( PyAlert, classification ), 0, "Snort alert classification" },
	{ "timestamp", T_INT, offsetof ( PyAlert, timestamp ), 0, "Snort alert timestamp" },
	{ "from", T_OBJECT_EX, offsetof ( PyAlert, ip_src_addr ), 0, "Source IP address" },
	{ "to", T_OBJECT_EX, offsetof ( PyAlert, ip_dst_addr ), 0, "Destination IP address" },
	{ "from_port", T_INT, offsetof ( PyAlert, tcp_src_port ), 0, "Source port" },
	{ "to_port", T_INT, offsetof ( PyAlert, tcp_dst_port ), 0, "Destination port" },
	{ "latitude", T_DOUBLE, offsetof ( PyAlert, latitude ), 0, "Geographical latitude, if available" },
	{ "longitude", T_DOUBLE, offsetof ( PyAlert, longitude ), 0, "Geographical longitude, if available" },
	{ "alert_count", T_INT, offsetof ( PyAlert, clusteredAlertsCount ), 0, "Number of alerts clustered in this object" },
	{ NULL }
};

/** Methods inside of the Python binded alert object */
static PyMethodDef alert_methods[] = {{ NULL }};

/** Module methods */
static PyMethodDef module_methods[] = {
	{ "alerts", (PyCFunction) Py_alerts, METH_VARARGS, "Return the list of SnortAI alerts" },
	{ NULL, NULL, 0, NULL }
};

/** Definition of the Python binded alert object */
static PyTypeObject alert_type = {
	PyObject_HEAD_INIT(NULL)
	0,                         /* ob_size*/
	"snortai.__alert",         /* tp_name*/
	sizeof(PyAlert),           /* tp_basicsize*/
	0,                         /* tp_itemsize*/
	(destructor)PyAlerts_free, /* tp_dealloc*/
	0,                         /* tp_print*/
	0,                         /* tp_getattr*/
	0,                         /* tp_setattr*/
	0,                         /* tp_compare*/
	0,                         /* tp_repr*/
	0,                         /* tp_as_number*/
	0,                         /* tp_as_sequence*/
	0,                         /* tp_as_mapping*/
	0,                         /* tp_hash */
	0,                         /* tp_call*/
	0,                         /* tp_str*/
	0,                         /* tp_getattro*/
	0,                         /* tp_setattro*/
	0,                         /* tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags*/
	"SnortAI alert type",      /*  tp_doc */
	0,                         /*  tp_traverse */
	0,                         /*  tp_clear */
	0,                         /*  tp_richcompare */
	0,                         /*  tp_weaklistoffset */
	0,                         /*  tp_iter */
	0,                         /*  tp_iternext */
	alert_methods,             /*  tp_methods */
	alert_members,             /*  tp_members */
	0,                         /*  tp_getset */
	0,                         /*  tp_base */
	0,                         /*  tp_dict */
	0,                         /*  tp_descr_get */
	0,                         /*  tp_descr_set */
	0,                         /*  tp_dictoffset */
	(initproc)PyAlert_init,    /*  tp_init */
	0,                         /*  tp_alloc */
	PyAlert_new,               /*  tp_new */
};

static PyObject*
Py_alerts ( PyObject *module, PyObject *args )
{
	int i, sd, len = 0, xml_offset = -1;
	char addr[INET_ADDRSTRLEN] = { 0 };
	char *response = NULL;
	unsigned int response_len = 1;
	unsigned int n_alerts = 0;
	FILE *fsock = NULL;
	struct sockaddr_in server;
	struct hostent *host;
	PyAlert *alerts = NULL, *cur_alert = NULL, *prev_alert = NULL;
	PyObject *self = NULL;

	BOOL xmlFlags[ALERT_TAG_NUM] = { false };
	xmlTextReaderPtr xml;
	const xmlChar *tagname;

	/* Connect to the web server and get the XML containing the alerts */
	if ( !( host = gethostbyname ( webserv )))
	{
		PyErr_SetString ( exception, "Could not resolve web server name" );
		return NULL;
	}

	if ( !( host->h_addr ))
	{
		PyErr_SetString ( exception, "Could not resolve web server name" );
		return NULL;
	}

	snprintf ( addr, sizeof ( addr ), "%u.%u.%u.%u",
		(unsigned char) host->h_addr[0],
		(unsigned char) host->h_addr[1],
		(unsigned char) host->h_addr[2],
		(unsigned char) host->h_addr[3] );

	if (( sd = socket ( AF_INET, SOCK_STREAM, IPPROTO_IP )) < 0 )
	{
		PyErr_SetString ( exception, "Could not initialize the socket" );
		return NULL;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons ( webport );
	server.sin_addr.s_addr = inet_addr ( addr );

	if ( connect ( sd, ( struct sockaddr* ) &server, sizeof ( struct sockaddr )) < 0 )
	{
		PyErr_SetString ( exception, "Could not connect to the web server" );
		close ( sd );
		return NULL;
	}

	if ( !( fsock = fdopen ( sd, "r+" )))
	{
		PyErr_SetString ( exception, "Could not open the socket" );
		close ( sd );
		return NULL;
	}

	fprintf ( fsock,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Python SnortAI request\r\n"
		"Connection: close\r\n\r\n",
		resource, webserv );

	while ( !feof ( fsock ))
	{
		if ( !( response = (char*) realloc ( response, ++response_len )))
		{
			PyErr_SetString ( exception, "Dynamic memory allocation error" );
			fclose ( fsock );
			close ( sd );
			return NULL;
		}

		response[ response_len - 2 ] = fgetc ( fsock );
	}

	response[ (--response_len) - 1 ] = 0;
	fclose ( fsock );
	close ( sd );
	/*****************************/

	/* Remove the HTTP headers from the response */
	if (( xml_offset = (int) strstr ( response, "\n\n" ) - (int) response ) >= 0 ) {}
	else if (( xml_offset = (int) strstr ( response, "\r\n\r\n" ) - (int) response ) >= 0 ) {}
	else {
		PyErr_SetString ( exception, "The HTTP response provided by the server has no valid HTTP header" );
		free ( response );
		return NULL;
	}

	len = strlen ( response );

	for ( i=0; i < len - xml_offset; i++ )
	{
		response[i] = response [i + xml_offset];
	}

	response [len - xml_offset] = 0;

	for ( xml_offset=0; response[xml_offset] != '<'; xml_offset++ );
	for ( i=0; i < len - xml_offset; i++ )
	{
		response[i] = response[i + xml_offset];
	}

	response [len - xml_offset] = 0;
	/*****************************/

	/* Parse the XML document */
	LIBXML_TEST_VERSION

	if ( !( xml = xmlReaderForMemory ( response, strlen ( response ), NULL, NULL, 0 )))
	{
		PyErr_SetString ( exception, "Could not initialize the XML reader object" );
		free ( response );
		return NULL;
	}

	while ( xmlTextReaderRead ( xml ))
	{
		if ( !( tagname = xmlTextReaderConstName ( xml )))
			continue;

		if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_ELEMENT )
		{
			if ( !strcasecmp ((const char*) tagname, "alerts" ))
			{
				if ( xmlFlags[inAlerts] )
				{
					PyErr_SetString ( exception, "Parse error in received XML: 'alerts' tag opened twice" );
					free ( response );
					return NULL;
				} else {
					xmlFlags[inAlerts] = true;
				}
			} else if ( !strcasecmp ((const char*) tagname, "alert" ))
			{
				if ( xmlFlags[inAlert] )
				{
					PyErr_SetString ( exception, "Parse error in received XML: 'alert' tag opened inside of another 'alert' tag" );
						free ( response );
					return NULL;
				} else {
					xmlFlags[inAlert] = true;

					/* Fill the PyObject */
					if ( !( cur_alert = (PyAlert*) alert_type.tp_alloc ( &alert_type, 0 )))
					{
						PyErr_SetString ( exception, "Could not initialize the PyAlert object" );
						free ( response );
						return NULL;
					}

					if ( !alerts )
					{
						alerts = cur_alert;
					}

					if ( prev_alert )
					{
						prev_alert->next = cur_alert;
					}

					n_alerts++;
					cur_alert->next = NULL;

					cur_alert->id = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "id" )) ?
						(unsigned int) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "id" ), NULL, 10 ) : 0;
					cur_alert->gid = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" )) ?
						(unsigned int) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "gid" ), NULL, 10 ) : 0;
					cur_alert->sid = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" )) ?
						(unsigned int) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "sid" ), NULL, 10 ) : 0;
					cur_alert->rev = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" )) ?
						(unsigned int) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "rev" ), NULL, 10 ) : 0;
					cur_alert->priority = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "priority" )) ?
						(unsigned int) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "priority" ), NULL, 10 ) : 0;
					cur_alert->timestamp = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "timestamp" )) ?
						(time_t) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "timestamp" ), NULL, 10 ) : (time_t) 0;
					cur_alert->tcp_src_port = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "from_port" )) ?
						(unsigned short) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "from_port" ), NULL, 10 ) : 0;
					cur_alert->tcp_dst_port = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "to_port" )) ?
						(unsigned short) strtol ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "to_port" ), NULL, 10 ) : 0;
					cur_alert->latitude = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "latitude" )) ?
						strtod ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "latitude" ), NULL ) : 0.0;
					cur_alert->longitude = ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "longitude" )) ?
						strtod ((const char*) xmlTextReaderGetAttribute ( xml, (const xmlChar*) "longitude" ), NULL ) : 0.0;

					if ( !( cur_alert->desc = 
						xmlTextReaderGetAttribute ( xml, (const xmlChar*) "label" ) ?
						PyString_FromString ((char*) ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "label" ))) : Py_None ))
					{
						PyErr_SetString ( exception, "Could not initialize a field in PyAlert object" );
						free ( response );
						return NULL;
					}

					if ( !( cur_alert->classification = 
						xmlTextReaderGetAttribute ( xml, (const xmlChar*) "classification" ) ?
						PyString_FromString ((char*) ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "classification" ))) : Py_None ))
					{
						PyErr_SetString ( exception, "Could not initialize a field in PyAlert object" );
						free ( response );
						return NULL;
					}

					if ( !( cur_alert->ip_src_addr = 
						xmlTextReaderGetAttribute ( xml, (const xmlChar*) "from" ) ?
						PyString_FromString ((char*) ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "from" ))) : Py_None ))
					{
						PyErr_SetString ( exception, "Could not initialize a field in PyAlert object" );
						free ( response );
						return NULL;
					}

					if ( !( cur_alert->ip_dst_addr = 
						xmlTextReaderGetAttribute ( xml, (const xmlChar*) "to" ) ?
						PyString_FromString ((char*) ( xmlTextReaderGetAttribute ( xml, (const xmlChar*) "to" ))) : Py_None ))
					{
						PyErr_SetString ( exception, "Could not initialize a field in PyAlert object" );
						free ( response );
						return NULL;
					}

					prev_alert = cur_alert;
				}
			} else {
				PyErr_SetString ( exception, "Unrecognized XML tag in received response" );
				free ( response );
				return NULL;
			}
		} else if ( xmlTextReaderNodeType ( xml ) == XML_READER_TYPE_END_ELEMENT ) {
			if ( !strcasecmp ((const char*) tagname, "alerts" ))
			{
				if ( !xmlFlags[inAlerts] )
				{
					PyErr_SetString ( exception, "'alerts' tag closed, but never opened" );
					free ( response );
					return NULL;
				} else {
					xmlFlags[inAlerts] = false;
				}
			} else if ( !strcasecmp ((const char*) tagname, "alert" )) {
				if ( !xmlFlags[inAlert] )
				{
					PyErr_SetString ( exception, "'alert' tag closed, but never opened" );
					free ( response );
					return NULL;
				} else {
					xmlFlags[inAlert] = false;
				}
			}
		}
	}

	xmlFreeTextReader ( xml );
	xmlCleanupParser();
	free ( response );
	/*****************************/

	/* Build the alerts tuple */
	if ( n_alerts > 0 )
	{
		if ( !( self = PyTuple_New ( n_alerts )))
		{
			PyErr_SetString ( exception, "Could not initialize the vector of alerts" );
			return NULL;
		}

		for ( i=0, cur_alert = alerts; cur_alert; cur_alert = cur_alert->next, i++ )
		{
			PyTuple_SetItem ( self, i, Py_BuildValue ( "O", cur_alert ));
			Py_INCREF ((PyObject*) cur_alert );
		}
	} else {
		Py_RETURN_NONE;
	}

	return self;
}

static int
PyAlert_init ( PyAlert *self, PyObject *args, PyObject *kwds )
{
	static char *kwlist[] = {
		"gid", "sid", "rev",
		"priority", "description", "classifcation",
		"timestamp", "from", "to", "from_port", "to_port",
		"latitude", "longitude", "alert_count", NULL
	};

	if ( !( PyArg_ParseTupleAndKeywords ( args, kwds, "|iiiiOOiOOiiddi", kwlist,
		&self->gid, &self->sid, &self->rev, &self->priority, &self->desc,
		&self->classification, &self->timestamp,
		&self->ip_src_addr, &self->ip_dst_addr, &self->tcp_src_port, &self->tcp_dst_port,
		&self->latitude, &self->longitude, &self->clusteredAlertsCount )))
	{
		PyErr_SetString ( exception, "Could not initialize a PyAlert object" );
		return -1;
	}

	return 0;
}

static PyObject*
PyAlert_new ( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
	PyAlert *self = NULL;

	if ( !( self = (PyAlert*) type->tp_alloc ( type, 0 )))
	{
		PyErr_SetString ( exception, "Could not allocate a PyAlert object" );
		return NULL;
	}

	return (PyObject*) self;
}

static void
PyAlerts_free ( PyAlert *self )
{
	Py_XDECREF ( self->classification );
	Py_XDECREF ( self->desc );
	self->ob_type->tp_free (( PyObject* ) self );
}

PyMODINIT_FUNC
initsnortai ( void )
{
	PyObject *m = NULL;

	if ( PyType_Ready ( &alert_type ) < 0 )
	{
		return;
	}

	if ( !( m = Py_InitModule ( "snortai", module_methods )))
	{
		return;
	}

	if ( !exception )
	{
		exception = PyErr_NewException ( "snortai.error", NULL, NULL );
		Py_INCREF ( exception );
	}

	Py_INCREF ( &alert_type );
	PyModule_AddObject ( m, "resource", PyString_FromString ( resource ));
	PyModule_AddObject ( m, "webserv", PyString_FromString ( webserv ));
	PyModule_AddObject ( m, "webport", PyInt_FromLong ((long int) webport ));
	/* PyModule_AddObject ( m, "alerts", (PyObject*) &alert_type ); */
}

