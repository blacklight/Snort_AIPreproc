/*
 * =====================================================================================
 *
 *       Filename:  cluster.c
 *
 *    Description:  Module for managing alarm clustering and cluter hierarchies
 *
 *        Version:  0.1
 *        Created:  12/08/2010 12:43:28
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

#include	<stdio.h>
#include	<unistd.h>
#include	<limits.h>
#include 	<pthread.h>

/** \defgroup cluster Manage the clustering of alarms
 * @{ */

/** Identifier key for a cluster attribute value */
typedef struct  {
	int min;
	int max;
} attribute_key;

/** Representation of a cluster attribute value */
typedef struct  {
	attribute_key   key;
	cluster_type    type;
	unsigned int    count;
	UT_hash_handle  hh;
} attribute_value;


PRIVATE hierarchy_node *h_root[CLUSTER_TYPES] = { NULL };
PRIVATE AI_config      *_config               = NULL;
PRIVATE AI_snort_alert *alert_log             = NULL;


/**
 * \brief  Function that picks up the heuristic value for a clustering attribute in according to Julisch's heuristic (ACM, Vol.2, No.3, 09 2002, pag.124)
 * \param  type 	Attribute type
 * \return The heuristic coefficient for that attribute, -1 if no clustering information is available for that attribute
 */

PRIVATE int
_heuristic_func ( cluster_type type )
{
	AI_snort_alert  *alert_iterator;
	attribute_key   key;
	attribute_value *values = NULL;
	attribute_value *value  = NULL;
	attribute_value *found  = NULL;
	int             max     = 0;
	
	if ( type == none || !alert_log || !h_root[type] )
		return -1;

	for ( alert_iterator = alert_log; alert_iterator; alert_iterator = alert_iterator->next )
	{
		if ( !alert_iterator->h_node[type] )
			continue;

		key.min = alert_iterator->h_node[type]->min_val;
		key.max = alert_iterator->h_node[type]->max_val;

		if ( values )
		{
			HASH_FIND ( hh, values, &key, sizeof ( attribute_key ), found );
		}

		if ( !found )
		{
			if ( !( value = ( attribute_value* ) malloc ( sizeof ( attribute_value )) ))
			{
				_dpd.fatalMsg ( "Fatal dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
			}

			memset ( value, 0, sizeof ( attribute_value ));
			value->key   = key;
			value->type  = type;
			value->count = 1;
			HASH_ADD ( hh, values, key, sizeof ( attribute_key ), value );
		} else {
			found->count++;
		}
	}

	for ( value = values; value; value = ( attribute_value* ) value->hh.next )
	{
		if ( value->count > max )
		{
			max = value->count;
		}
	}

	while ( values )
	{
		value = values;
		HASH_DEL ( values, value );
		free ( value );
	}

	return max;
}		/* -----  end of function _heuristic_func  ----- */

/**
 * \brief  Create a new clustering hierarchy node
 * \param  label 	Label for the node
 * \param  min_val 	Minimum value for the range represented by the node
 * \param  max_val 	Maximum value for the range represented by the node
 * \return The brand new node if the allocation was ok, otherwise abort the application
 */

PRIVATE hierarchy_node*
_hierarchy_node_new ( char *label, int min_val, int max_val )
{
	hierarchy_node *n = NULL;

	if ( !( n = ( hierarchy_node* ) malloc ( sizeof ( hierarchy_node )) ))
	{
		_dpd.fatalMsg ( "Dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
	}

	n->min_val    = min_val;
	n->max_val    = max_val;
	n->nchildren  = 0;
	n->children   = NULL;
	n->parent     = NULL;
	strncpy ( n->label, label, sizeof ( n->label ));

	return n;
}		/* -----  end of function _hierarchy_node_new  ----- */


/**
 * \brief  Append a node to a clustering hierarchy node
 * \param  parent 	Parent node
 * \param  child 	Child node
 */

PRIVATE void
_hierarchy_node_append ( hierarchy_node *parent, hierarchy_node *child )
{
	if ( !( parent->children = ( hierarchy_node** ) realloc ( parent->children, (++(parent->nchildren)) * sizeof ( hierarchy_node* )) ))
	{
		_dpd.fatalMsg ( "Dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
	}

	parent->children[ parent->nchildren - 1 ] = child;
	child->parent = parent;
}		/* -----  end of function _hierarchy_node_append  ----- */


/**
 * \brief  Get the minimum node in a hierarchy tree that matches a certain value
 * \param  val 	Value to be matched in the range
 * \param  root 	Root of the hierarchy
 * \return The minimum node that matches the value if any, NULL otherwise
 */
PRIVATE hierarchy_node*
_AI_get_min_hierarchy_node ( int val, hierarchy_node *root )
{
	int i;
	hierarchy_node *next = NULL;

	if ( !root )
	{
		return NULL;
	}

	if ( (unsigned) val < (unsigned) root->min_val || (unsigned) val > (unsigned) root->max_val )
	{
		return NULL;
	}

	for ( i=0; i < root->nchildren && !next; i++ )
	{
		if ( root->children[i]->min_val <= val && root->children[i]->max_val >= val )
		{
			next = root->children[i];
		}
	}

	if ( !next )
		return root;
	
	return _AI_get_min_hierarchy_node ( val, next );
}		/* -----  end of function _AI_get_min_hierarchy_node  ----- */

/**
 * \brief  Check if two alerts are semantically equal
 * \param  a1 	First alert
 * \param  a2 	Second alert
 * \return True if they are equal, false otherwise
 */

PRIVATE BOOL
_AI_equal_alarms ( AI_snort_alert *a1, AI_snort_alert *a2 )
{
	if ( a1->gid != a2->gid || a1->sid != a2->sid || a1->rev != a2->rev )
	{
		return false;
	}

	if ( a1->h_node[src_addr] && a2->h_node[src_addr] )
	{
		if ( a1->h_node[src_addr]->min_val != a2->h_node[src_addr]->min_val ||
				a1->h_node[src_addr]->max_val != a2->h_node[src_addr]->max_val )
			return false;
	}

	if ( a1->h_node[dst_addr] && a2->h_node[dst_addr] )
	{
		if ( a1->h_node[dst_addr]->min_val != a2->h_node[dst_addr]->min_val ||
				a1->h_node[dst_addr]->max_val != a2->h_node[dst_addr]->max_val )
			return false;
	}

	if ( a1->h_node[src_port] && a2->h_node[src_port] )
	{
		if ( a1->h_node[src_port]->min_val != a2->h_node[src_port]->min_val ||
				a1->h_node[src_port]->max_val != a2->h_node[src_port]->max_val )
			return false;
	}

	if ( a1->h_node[dst_port] && a2->h_node[dst_port] )
	{
		if ( a1->h_node[dst_port]->min_val != a2->h_node[dst_port]->min_val ||
				a1->h_node[dst_port]->max_val != a2->h_node[dst_port]->max_val )
			return false;
	}

	return true;
}		/* -----  end of function _AI_equal_alarms  ----- */


/**
 * \brief  Merge the alerts marked as equal in the log
 * \param  log 	Alert log reference
 * \return The number of merged couples
 */

PRIVATE int
_AI_merge_alerts ( AI_snort_alert **log )
{
	AI_snort_alert *tmp, *tmp2, *tmp3;
	int count = 0;

	for ( tmp = *log; tmp; tmp = tmp->next )
	{
		for ( tmp2 = *log; tmp2; )
		{
			if ( tmp2->next )
			{
				if ( tmp != tmp2->next )
				{
					if ( _AI_equal_alarms ( tmp, tmp2->next ))
					{
						tmp3 = tmp2->next->next;
						free ( tmp2->next );
						tmp2->next = tmp3;

						tmp->grouped_alarms_count++;
						count++;
					}
				}

				tmp2 = tmp2->next;
			} else
				break;
		}
	}

	return count;
}		/* -----  end of function _AI_merge_alerts  ----- */


/**
 * \brief  Print the clustered alerts to a log file
 * \param  log 	Log containing the alerts
 * \param  fp 		File pointer where the alerts will be printed
 */

PRIVATE void
_AI_print_clustered_alerts ( AI_snort_alert *log, FILE *fp )
{
	AI_snort_alert *tmp;
	char ip[INET_ADDRSTRLEN];
	char *timestamp;

	for ( tmp = log; tmp; tmp = tmp->next )
	{
		fprintf ( fp, "[**] [%d:%d:%d] %s [**]\n", tmp->gid, tmp->sid, tmp->rev, tmp->desc );

		if ( tmp->classification )
			fprintf ( fp, "[Classification: %s] ", tmp->classification );

		fprintf ( fp, "[Priority: %d]\n", tmp->priority );

		timestamp = ctime ( &tmp->timestamp );
		timestamp[ strlen(timestamp)-1 ] = 0;
		fprintf ( fp, "[Grouped alerts: %d] [Starting from: %s]\n", tmp->grouped_alarms_count, timestamp );

		if ( h_root[src_addr] && tmp->h_node[src_addr] )
		{
			fprintf ( fp, "[%s]:", (tmp->h_node[src_addr]->label) ? tmp->h_node[src_addr]->label : "no label" );
		} else {
			inet_ntop ( AF_INET, &(tmp->ip_src_addr), ip, INET_ADDRSTRLEN );
			fprintf ( fp, "%s:", ip );
		}

		if ( h_root[src_port] && tmp->h_node[src_port] )
		{
			fprintf ( fp, "[%s] -> ", (tmp->h_node[src_port]->label) ? tmp->h_node[src_port]->label : "no label" );
		} else {
			fprintf ( fp, "%d -> ", htons ( tmp->tcp_src_port ));
		}

		if ( h_root[dst_addr] && tmp->h_node[dst_addr] )
		{
			fprintf ( fp, "[%s]:", (tmp->h_node[dst_addr]->label) ? tmp->h_node[dst_addr]->label : "no label" );
		} else {
			inet_ntop ( AF_INET, &(tmp->ip_dst_addr), ip, INET_ADDRSTRLEN );
			fprintf ( fp, "%s:", ip );
		}

		if ( h_root[dst_port] && tmp->h_node[dst_port] )
		{
			fprintf ( fp, "[%s]\n", (tmp->h_node[dst_port]->label) ? tmp->h_node[dst_port]->label : "no label" );
		} else {
			fprintf ( fp, "%d\n", htons ( tmp->tcp_dst_port ));
		}

		fprintf ( fp, "\n" );
	}
}		/* -----  end of function _AI_print_clustered_alerts  ----- */


/**
 * \brief  Thread for periodically clustering the log information
 */
PRIVATE void*
_AI_cluster_thread ( void* arg )
{
	AI_snort_alert *tmp;
	hierarchy_node *node, *child;
	cluster_type   type;
	cluster_type   best_type;
	BOOL           has_small_clusters = true;
	FILE           *cluster_fp;
	char           label[256];
	int            hostval;
	int            netval;
	int            minval;
	int            heuristic_val;
	int            cluster_min_size = 2;
	int            alert_count = 0;
	int            old_alert_count = 0;

	while ( 1 )
	{
		/* Between an execution of the thread and the next one, sleep for alert_clustering_interval seconds */
		sleep ( _config->alertClusteringInterval );

		/* Free the current alert log and get the latest one */
		AI_free_alerts ( alert_log );
		
		if ( !( alert_log = get_alerts() ))
		{
			continue;
		}

		has_small_clusters = true;

		for ( tmp = alert_log, alert_count=0; tmp; tmp = tmp->next, alert_count++ )
		{
			/* If an alert has an unitialized "grouped alarms count", set its counter to 1 (it only groupes the current alert) */
			if ( tmp->grouped_alarms_count == 0 )
			{
				tmp->grouped_alarms_count = 1;
			}

			/* If the current alarm already group at least min_size alarms, then no need to do further clusterization */
			if ( tmp->grouped_alarms_count >= cluster_min_size )
			{
				has_small_clusters = false;
			}

			/* Initialize the clustering hierarchies in the current alert */
			for ( type=0; type < CLUSTER_TYPES; type++ )
			{
				/* If "type" is a valid clustering hierarchy but the corresponding node in the alert is not initialized, initialize it */
				if ( h_root[type] && !tmp->h_node[type] )
				{
					switch ( type )
					{
						case src_addr:
						case dst_addr:
							netval  = ( type == src_addr ) ? tmp->ip_src_addr : tmp->ip_dst_addr;
							hostval = ntohl ( netval );
							inet_ntop ( AF_INET, &(netval), label, INET_ADDRSTRLEN );
							break;

						case src_port:
						case dst_port:
							netval  = ( type == src_port ) ? tmp->tcp_src_port : tmp->tcp_dst_port;
							hostval = ntohs ( netval );
							snprintf ( label, sizeof(label), "%d", hostval );
							break;

						default:
							pthread_exit (( void* ) 0 );
							return (void*) 0;
					}

					node = _AI_get_min_hierarchy_node ( hostval, h_root[type] );

					if ( node )
					{
						if ( node->min_val < node->max_val )
						{
							child = _hierarchy_node_new ( label, hostval, hostval);
							_hierarchy_node_append ( node, child );
							node = child;
						}

						tmp->h_node[type] = node;
					}
				}
			}
		}

		alert_count -= _AI_merge_alerts ( &alert_log );

		/* while ( has_small_clusters && alert_count > cluster_min_size ) */
		do
		{
			old_alert_count = alert_count;
			minval = INT_MAX;
			best_type = none;

			/* Choose the best attribute to cluster using the heuristic function */
			for ( type = 0; type < CLUSTER_TYPES; type++ )
			{
				if ( type != none && h_root[type] )
				{
					if (( heuristic_val = _heuristic_func ( type )) > 0 && heuristic_val < minval )
					{
						minval = heuristic_val;
						best_type = type;
					}
				}
			}

			/* For all the alerts, the corresponing clustering value is the parent of the current one in the hierarchy */
			for ( tmp = alert_log; tmp; tmp = tmp->next )
			{
				if ( tmp->grouped_alarms_count < cluster_min_size && tmp->h_node[best_type] )
				{
					if ( tmp->h_node[best_type]->parent )
					{
						tmp->h_node[best_type] = tmp->h_node[best_type]->parent;
					}
				}
			}

			alert_count -= _AI_merge_alerts ( &alert_log );

			/* if ( old_alert_count == alert_count ) */
			/* 	break; */
		} while ( old_alert_count != alert_count );

		if ( !( cluster_fp = fopen ( _config->clusterfile, "w" )) )
		{
			pthread_exit ((void*) 0 );
			return (void*) 0;
		}

		_AI_print_clustered_alerts ( alert_log, cluster_fp );
		fclose ( cluster_fp );
	}

	pthread_exit ((void*) 0 );
	return (void*) 0;
}		/* -----  end of function AI_cluster_thread  ----- */


/**
 * \brief  Check if a certain node's range (minimum and maximum value) are already present in a clustering hierarchy
 * \param  node 	Node to be checked
 * \param  root 	Clustering hierarchy
 * \return True if 'node' is already in 'root', false otherwise
 */

PRIVATE BOOL
_AI_check_duplicate ( hierarchy_node *node, hierarchy_node *root )
{
	int i;
	
	if ( !node || !root )
		return false;

	if ( root->min_val == node->min_val && root->max_val == node->max_val )
		return true;

	for ( i=0; i < root->nchildren; i++ )
	{
		if ( _AI_check_duplicate ( node, root->children[i] ))
			return true;
	}

	return false;
}		/* -----  end of function _AI_check_duplicate  ----- */


/**
 * \brief  Build the clustering hierarchy trees
 * \param  conf 	Reference to the configuration of the module
 * \param  nodes 	Nodes containing the information about the clustering ranges
 * \param  n_nodes 	Number of nodes
 */

void
AI_hierarchies_build ( AI_config *conf, hierarchy_node **nodes, int n_nodes )
{
	int  i, j;
	int  min_range = 0;
	pthread_t      cluster_thread;
	hierarchy_node *root  = NULL;
	hierarchy_node *cover = NULL;
	_config = conf;

	for ( i=0; i < n_nodes; i++ )
	{
		switch ( nodes[i]->type )
		{
			case src_port:
			case dst_port:
				if ( !h_root[ nodes[i]->type ] )
					h_root[ nodes[i]->type ] = _hierarchy_node_new ( "1-65535", 1, 65535 );

				min_range = 65534;
				break;

			case src_addr:
			case dst_addr:
				if ( !h_root[ nodes[i]->type ] )
					h_root[ nodes[i]->type ] = _hierarchy_node_new ( "0.0.0.0/0", 0x0, 0xffffffff );
				
				min_range = 0xffffffff;
				break;

			/* TODO Manage ranges for timestamps (and something more?) */
			default:
				return;
		}

		root = h_root[ nodes[i]->type ];
		cover = NULL;

		if ( _AI_check_duplicate ( nodes[i], root ))
		{
			_dpd.fatalMsg ( "AIPreproc: Parse error: duplicate cluster range '%d-%d' in configuration\n", nodes[i]->min_val, nodes[i]->max_val );
		}

		for ( j=0; j < n_nodes; j++ )
		{
			if ( i != j )
			{
				if ( (unsigned) nodes[j]->min_val <= (unsigned) nodes[i]->min_val &&
						(unsigned) nodes[j]->max_val >= (unsigned) nodes[i]->max_val )
				{
					if (( (unsigned) nodes[i]->min_val - (unsigned) nodes[j]->min_val +
								(unsigned) nodes[j]->max_val - (unsigned) nodes[i]->max_val ) <= min_range )
					{
						cover = nodes[j];
						min_range = nodes[i]->min_val - nodes[j]->min_val +
							nodes[j]->max_val - nodes[i]->max_val;
					}
				}
			}
		}

		if ( cover )
		{
			_hierarchy_node_append ( cover, nodes[i] );
		} else {
			if ( (unsigned) nodes[i]->min_val >= (unsigned) root->min_val && (unsigned) nodes[i]->max_val <= (unsigned) root->max_val &&
					( (unsigned) nodes[i]->min_val != (unsigned) root->min_val || (unsigned) nodes[i]->max_val != (unsigned) root->max_val ))
			{
				_hierarchy_node_append ( root, nodes[i] );
			}
		}
	}

	if ( pthread_create ( &cluster_thread, NULL, _AI_cluster_thread, NULL ) != 0 )
	{
		_dpd.fatalMsg ( "Failed to create the hash cleanup thread\n" );
	}
}		/* -----  end of function AI_hierarchies_build  ----- */


/**
 * \brief Return a copy of the clustered alerts
 * \return An AI_snort_alert pointer identifying the list of clustered alerts
 */

PRIVATE AI_snort_alert*
_AI_copy_clustered_alerts ( AI_snort_alert *node )
{
	AI_snort_alert *current = NULL, *next = NULL;

	if ( !node )
	{
		return NULL;
	}

	if ( node->next )
	{
		next = _AI_copy_clustered_alerts ( node->next );
	}

	if ( !( current = ( AI_snort_alert* ) malloc ( sizeof ( AI_snort_alert )) ))
	{
		_dpd.fatalMsg ( "Fatal dynamic memory allocation failure at %s:%d\n", __FILE__, __LINE__ );
	}

	memcpy ( current, node, sizeof ( AI_snort_alert ));
	current->next = next;
	return current;
}		/* -----  end of function _AI_copy_clustered_alerts  ----- */


/**
 * \brief  Return the alerts parsed so far as a linked list
 * \return An AI_snort_alert pointer identifying the list of clustered alerts
 */

AI_snort_alert*
AI_get_clustered_alerts ()
{
	return _AI_copy_clustered_alerts ( alert_log );
}		/* -----  end of function AI_get_clustered_alerts  ----- */

/** @} */

