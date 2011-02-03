/*
 * =====================================================================================
 *
 *       Filename:  modules.c
 *
 *    Description:  Support for extra correlation modules
 *
 *        Version:  0.1
 *        Created:  26/10/2010 01:11:25
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

#include	<dirent.h>
#include	<dlfcn.h>
#include	<stdlib.h>
#include	<unistd.h>

/** \defgroup modules Software component for loading extra user-provided modules for correlating alerts
 * @{ */

PRIVATE double (**corr_functions)(const AI_snort_alert*, const AI_snort_alert*) = NULL;
PRIVATE size_t n_corr_functions = 0;

PRIVATE double (**weight_functions)() = NULL;
PRIVATE size_t n_weight_functions = 0;

#ifdef HAVE_LIBPYTHON2_6

PRIVATE PyObject **py_corr_functions = NULL;
PRIVATE size_t   n_py_corr_functions = 0;

PRIVATE PyObject **py_weight_functions = NULL;
PRIVATE size_t   n_py_weight_functions = 0;

#endif

/**
 * \brief  Get the correlation functions from the extra correlation modules as array of function pointers
 * \param  n_functions 	Number of function pointers in the array
 * \return The array of correlation functions
 */

double
(**AI_get_corr_functions ( size_t *n_functions )) (const AI_snort_alert*, const AI_snort_alert*)
{
	*n_functions = n_corr_functions;
	return corr_functions;
}		/* -----  end of function AI_get_corr_functions  ----- */

/**
 * \brief  Get the weights of the correlation extra modules as array of function pointers
 * \param  n_functions 	Number of function pointers in the array
 * \return The array of correlation weights functions
 */

double
(**AI_get_corr_weights ( size_t *n_functions )) ()
{
	*n_functions = n_weight_functions;
	return weight_functions;
}		/* -----  end of function AI_get_corr_weights  ----- */

#ifdef HAVE_LIBPYTHON2_6
/**
 * \brief  Get the correlation functions from the Python modules, if Python support is enabled
 * \param  n_functions 	Reference to the number of functions in the array
 * \return The array of Python correlation functions as PyObject**
 */

PyObject**
AI_get_py_functions ( size_t *n_functions )
{
	*n_functions = n_py_corr_functions;
	return py_corr_functions;
}		/* -----  end of function AI_get_py_functions  ----- */

/**
 * \brief  Get the correlation index weights from the Python modules, if Python support is enabled
 * \param  n_functions 	Reference to the number of correlation weight functions in the array
 * \return The array of correlation weight functions as PyObject**
 */

PyObject**
AI_get_py_weights ( size_t *n_functions )
{
	*n_functions = n_py_weight_functions;
	return py_weight_functions;
}		/* -----  end of function AI_get_py_weights  ----- */

/**
 * \brief  Convert an AI_snort_alert object to a PyAlert object that can be managed by a Python module
 * \param  alert 	AI_snort_alert object to be converted
 * \return A PyAlert object wrapping the original AI_snort_alert object
 */

PyAlert*
AI_alert_to_pyalert ( AI_snort_alert *alert )
{
	PyAlert *pyalert = NULL;
	char src_addr[INET_ADDRSTRLEN] = { 0 },
		dst_addr[INET_ADDRSTRLEN] = { 0 };
	
	if ( !( pyalert = (PyAlert*) malloc ( sizeof ( PyAlert ))))
	{
		AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
	}

	inet_ntop ( AF_INET, &(alert->ip_src_addr), src_addr, INET_ADDRSTRLEN );
	inet_ntop ( AF_INET, &(alert->ip_dst_addr), dst_addr, INET_ADDRSTRLEN );

	pyalert->classification = alert->classification ? PyString_FromString ( alert->classification ) : Py_None;
	pyalert->clusteredAlertsCount = alert->grouped_alerts_count;
	pyalert->desc = alert->desc ? PyString_FromString ( alert->desc ) : Py_None;
	pyalert->gid = alert->gid;
	pyalert->ip_src_addr = ( strlen ( src_addr ) > 0 ) ? PyString_FromString ( src_addr ) : Py_None;
	pyalert->ip_dst_addr = ( strlen ( dst_addr ) > 0 ) ? PyString_FromString ( dst_addr ) : Py_None;
	pyalert->priority = alert->priority;
	pyalert->rev = alert->rev;
	pyalert->sid = alert->sid;
	pyalert->tcp_src_port = ntohs ( alert->tcp_src_port );
	pyalert->tcp_dst_port = ntohs ( alert->tcp_dst_port );
	pyalert->timestamp = alert->timestamp;

	return pyalert;
}		/* -----  end of function AI_alert_to_pyalert  ----- */
#endif

/**
 * \brief  Initialize the extra modules provided by the user
 */

void
AI_init_corr_modules ()
{
	void   **dl_handles = NULL;
	DIR    *dir         = NULL;
	char   *err         = NULL;
	char   *fname       = NULL;
	size_t n_dl_handles = 0;
	struct dirent *dir_info = NULL;

	#ifdef HAVE_LIBPYTHON2_6
	char     *pyPath  = NULL;
	PyObject *pObj    = NULL;
	BOOL     isPyInit = false;
	#endif

	if ( !( dir = opendir ( config->corr_modules_dir )))
	{
		return;
	}

	while (( dir_info = readdir ( dir )))
	{
		if ( preg_match ( "(\\.(l|s)o)|(\\.l?a)", dir_info->d_name, NULL, NULL ))
		{
			if ( !( dl_handles = (void**) realloc ( dl_handles, (++n_dl_handles) * sizeof ( void* ))))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			if ( !( fname = (char*) malloc ( strlen ( config->corr_modules_dir ) + strlen ( dir_info->d_name ) + 4 )))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			sprintf ( fname, "%s/%s", config->corr_modules_dir, dir_info->d_name );

			if ( !( dl_handles[n_dl_handles-1] = dlopen ( fname, RTLD_LAZY )))
			{
				if (( err = dlerror() ))
				{
					_dpd.errMsg ( "dlopen: %s\n", err );
				}

				AI_fatal_err ( "dlopen error", __FILE__, __LINE__ );
			}

			free ( fname );
			fname = NULL;

			if ( !( corr_functions = (double(**)(const AI_snort_alert*, const AI_snort_alert*))
						realloc ( corr_functions, (++n_corr_functions) * sizeof ( double(*)(const AI_snort_alert*, const AI_snort_alert*) ))))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			*(void**) (&(corr_functions[ n_corr_functions - 1 ])) = dlsym ( dl_handles[n_dl_handles-1], "AI_corr_index" );

			if ( !corr_functions[ n_corr_functions - 1 ] )
			{
				if (( err = dlerror() ))
				{
					_dpd.errMsg ( "dlsym: %s\n", err );
				}

				AI_fatal_err ( "dlsym error", __FILE__, __LINE__ );
			}

			if ( !( weight_functions = (double(**)()) realloc ( weight_functions, (++n_weight_functions) * sizeof ( double(*)() ))))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			*(void**) (&(weight_functions[ n_weight_functions - 1 ])) = dlsym ( dl_handles[n_dl_handles-1], "AI_corr_index_weight" );

			if ( !weight_functions[ n_weight_functions - 1 ] )
			{
				if (( err = dlerror() ))
				{
					_dpd.errMsg ( "dlsym: %s\n", err );
				}

				AI_fatal_err ( "dlsym error", __FILE__, __LINE__ );
			}
		} else if ( preg_match ( "\\.py$", dir_info->d_name, NULL, NULL )) {
			#ifdef HAVE_LIBPYTHON2_6

			if ( !( pyPath = (char*) malloc ( strlen ( config->corr_modules_dir ) + strlen ( Py_GetPath() ) + 4 )))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			fname = strdup ( dir_info->d_name );
			fname[strlen ( fname ) - 3] = 0;

			if ( !isPyInit )
			{
				Py_Initialize();
				isPyInit = true;
			}

			sprintf ( pyPath, "%s:%s", config->corr_modules_dir, Py_GetPath() );
			PySys_SetPath ( pyPath );

			if ( !( pObj = PyImport_ImportModule ( fname )))
			{
				PyErr_Print();
				AI_fatal_err ( "Could not load a Python correlation module", __FILE__, __LINE__ );
			}

			free ( fname );
			fname = NULL;

			if ( !( py_corr_functions = (PyObject**) realloc ( py_corr_functions, (++n_py_corr_functions) * sizeof ( PyObject* ))))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			if ( !( py_corr_functions[ n_py_corr_functions - 1 ] = PyObject_GetAttrString ( pObj, "AI_corr_index" )))
			{
				AI_fatal_err ( "AI_corr_index() method not found in the Python correlation module", __FILE__, __LINE__ );
			}

			if ( !( py_weight_functions = (PyObject**) realloc ( py_weight_functions, (++n_py_weight_functions) * sizeof ( PyObject* ))))
			{
				AI_fatal_err ( "Fatal dynamic memory allocation error", __FILE__, __LINE__ );
			}

			if ( !( py_weight_functions[ n_py_weight_functions - 1 ] = PyObject_GetAttrString ( pObj, "AI_corr_index_weight" )))
			{
				AI_fatal_err ( "AI_corr_index_weight() method not found in the Python correlation module", __FILE__, __LINE__ );
			}

			Py_DECREF ( pObj );

			#endif
		}
	}

	closedir ( dir );
}		/* -----  end of function AI_init_corr_modules  ----- */

/** @} */

