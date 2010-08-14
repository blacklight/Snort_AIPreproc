/*
 * =====================================================================================
 *
 *       Filename:  cluster.c
 *
 *    Description:  Module for managing alarm clustering and cluter hierarchies
 *
 *        Version:  1.0
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
#include	<pthread.h>

PRIVATE hierarchy_node *src_port_root = NULL;
PRIVATE hierarchy_node *src_addr_root = NULL;
PRIVATE hierarchy_node *dst_port_root = NULL;
PRIVATE hierarchy_node *dst_addr_root = NULL;
PRIVATE AI_config      *_config       = NULL;
PRIVATE AI_snort_alert *alert_log     = NULL;


/**
 * FUNCTION: _hierarchy_node_new
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
 * FUNCTION: _hierarchy_node_append
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


/* PRIVATE void */
/* _hierarchy_node_free ( hierarchy_node *n ) */
/* { */
/* 	int i; */
/*  */
/* 	if ( !n ) */
/* 		return; */
/*  */
/* 	for ( i=0; i < n->nchildren; i++ ) */
/* 	{ */
/* 		if ( n->children[i] ) */
/* 			_hierarchy_node_free ( n->children[i] ); */
/* 	} */
/*  */
/* 	free ( n ); */
/* 	n = NULL; */
/* } */


/**
 * FUNCTION: _AI_get_min_hierarchy_node
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
 * FUNCTION: _AI_cluster_thread
 * \brief  Thread for periodically clustering the log information
 */
PRIVATE void*
_AI_cluster_thread ( void* arg )
{
	AI_snort_alert *tmp;
	hierarchy_node *node, *child;
	char           label[256];

	while ( 1 )
	{
		sleep ( _config->alertClusteringInterval );
		
		if ( !( alert_log = AI_get_alerts() ))
		{
			continue;
		}

		FILE *fp = fopen ( "/home/blacklight/LOG", "a" );

		for ( tmp = alert_log; tmp; tmp = tmp->next )
		{
			if ( src_addr_root && !tmp->src_addr_node )
			{
				node = _AI_get_min_hierarchy_node ( ntohl ( tmp->src_addr ), src_addr_root );

				if ( node )
				{
					if ( node->min_val < node->max_val )
					{
						inet_ntop ( AF_INET, &(tmp->src_addr), label, INET_ADDRSTRLEN );
						child = _hierarchy_node_new ( label, ntohl ( tmp->src_addr ), ntohl ( tmp->src_addr ));
						_hierarchy_node_append ( node, child );
						node = child;
					}

					tmp->src_addr_node = node;
					fprintf ( fp, "minimum range holding %s: %s (prev: %s)\n", label, tmp->src_addr_node->label, tmp->src_addr_node->parent->label );
				}
			}

			if ( dst_addr_root && !tmp->dst_addr_node )
			{
				node = _AI_get_min_hierarchy_node ( ntohl ( tmp->dst_addr ), dst_addr_root );

				if ( node )
				{
					if ( node->min_val < node->max_val )
					{
						/* snprintf ( label, sizeof(label), "%d", ntohl ( tmp->dst_addr )); */
						inet_ntop ( AF_INET, &(tmp->src_addr), label, INET_ADDRSTRLEN );
						child = _hierarchy_node_new ( label, ntohl ( tmp->dst_addr ), ntohl ( tmp->dst_addr ));
						_hierarchy_node_append ( node, child );
						node = child;
					}

					tmp->dst_addr_node = node;
				}
			}

			if ( src_port_root && !tmp->src_port_node )
			{
				node = _AI_get_min_hierarchy_node ( ntohs ( tmp->src_port ), src_port_root );

				if ( node )
				{
					if ( node->min_val < node->max_val )
					{
						snprintf ( label, sizeof(label), "%d", ntohs ( tmp->src_port ));
						child = _hierarchy_node_new ( label, ntohs ( tmp->src_port ), ntohs ( tmp->src_port ));
						_hierarchy_node_append ( node, child );
						node = child;
					}

					tmp->src_port_node = node;
					fprintf ( fp, "minimum range holding %d: %s (prev: %s)\n", ntohs(tmp->src_port), tmp->src_port_node->label, tmp->src_port_node->parent->label );
				}
			}

			if ( dst_port_root && !tmp->dst_port_node )
			{
				node = _AI_get_min_hierarchy_node ( ntohs ( tmp->dst_port ), dst_port_root );

				if ( node )
				{
					if ( node->min_val < node->max_val )
					{
						snprintf ( label, sizeof(label), "%d", ntohs ( tmp->dst_port ));
						child = _hierarchy_node_new ( label, ntohs ( tmp->dst_port ), ntohs ( tmp->dst_port ));
						_hierarchy_node_append ( node, child );
						node = child;
					}

					tmp->dst_port_node = node;
					fprintf ( fp, "minimum range holding %d: %s (prev: %s)\n", ntohs(tmp->dst_port), tmp->dst_port_node->label, tmp->dst_port_node->parent->label );
				}
			}
		}

		fclose ( fp );
	}

	return (void*) 0;
}		/* -----  end of function AI_cluster_thread  ----- */


/**
 * FUNCTION: AI_hierarchies_build
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
				if ( !src_port_root )
					src_port_root = _hierarchy_node_new ( "1-65535", 1, 65535 );

				root = src_port_root;
				min_range = 65534;
				break;

			case dst_port:
				if ( !dst_port_root )
					dst_port_root = _hierarchy_node_new ( "1-65535", 1, 65535 );

				root = dst_port_root;
				min_range = 65534;
				break;

			case src_addr:
				if ( !src_addr_root )
					src_addr_root = _hierarchy_node_new ( "0.0.0.0/0",
							0x0, 0xffffffff );
				
				root = src_addr_root;
				min_range = 0xffffffff;
				break;

			case dst_addr:
				if ( !dst_addr_root )
					dst_addr_root = _hierarchy_node_new ( "0.0.0.0/0",
							0x0, 0xffffffff );

				root = dst_addr_root;
				min_range = 0xffffffff;
				break;

			/* TODO Manage range for timestamps (and something more?) */
			default:
				break;
		}

		cover = NULL;

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

