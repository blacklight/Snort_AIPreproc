/*
 * =====================================================================================
 *
 *       Filename:  kmeans.c
 *
 *    Description:  k-means clusterization algorithm implementation in C
 *
 *        Version:  1.0
 *        Created:  12/11/2010 10:43:28
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#include	"kmeans.h"

#include	<alloca.h>
#include	<float.h>
#include	<limits.h>
#include	<math.h>
#include	<stdio.h>
#include	<stdlib.h>

/**
 * \brief  Initialize the centers of the clusters taking the K most distant elements in the dataset
 * \param  km 	k-means object
 */

static void
__kmeans_init_centers ( kmeans_t *km )
{
	int i, j, k, l,
	    index_found = 0,
	    max_index = 0,
	    assigned_centers = 0,
	    *assigned_centers_indexes = NULL;

	double dist = 0.0,
		  max_dist = 0.0;

	for ( i=0; i < km->dataset_size; i++ )
	{
		dist = 0.0;

		for ( j=0; j < km->dataset_dim; j++ )
		{
			dist += ( km->dataset[i][j] ) * ( km->dataset[i][j] );
		}

		if ( dist > max_dist )
		{
			max_dist = dist;
			max_index = i;
		}
	}

	for ( i=0; i < km->dataset_dim; i++ )
	{
		km->centers[0][i] = km->dataset[max_index][i];
	}

	if ( !( assigned_centers_indexes = (int*) realloc ( assigned_centers_indexes, (++assigned_centers) * sizeof ( int ))))
	{
		return;
	}

	assigned_centers_indexes[ assigned_centers - 1 ] = max_index;

	for ( i=1; i < km->k; i++ )
	{
		max_dist = 0.0;
		max_index = 0;

		for ( j=0; j < km->dataset_size; j++ )
		{
			index_found = 0;
			
			for ( k=0; k < assigned_centers && !index_found; k++ )
			{
				if ( assigned_centers_indexes[k] == j )
				{
					index_found = 1;
				}
			}

			if ( index_found )
				continue;

			dist = 0.0;

			for ( k=0; k < assigned_centers; k++ )
			{
				for ( l=0; l < km->dataset_dim; l++ )
				{
					dist += ( km->dataset[j][l] - km->centers[k][l] ) * ( km->dataset[j][l] - km->centers[k][l] );
				}
			}

			if ( dist > max_dist )
			{
				max_dist = dist;
				max_index = j;
			}
		}

		for ( j=0; j < km->dataset_dim; j++ )
		{
			km->centers[i][j] = km->dataset[max_index][j];
		}

		if ( !( assigned_centers_indexes = (int*) realloc ( assigned_centers_indexes, (++assigned_centers) * sizeof ( int ))))
		{
			return;
		}

		assigned_centers_indexes[ assigned_centers - 1 ] = max_index;
	}

	free ( assigned_centers_indexes );
}		/* -----  end of function kmeans_init_centers  ----- */

/**
 * \brief  Create a new k-means object
 * \param  dataset 		Dataset to be clustered
 * \param  dataset_size 	Number of elements in the dataset
 * \param  dataset_dim 	Dimension of each element of the dataset
 * \param  K 			Number of clusters
 * \return Reference to the newly created k-means object, if successfull, NULL otherwise
 */

kmeans_t*
kmeans_new ( double **dataset, const int dataset_size, const int dataset_dim, const int K )
{
	int i, j;
	kmeans_t *km = NULL;

	if ( !( km = (kmeans_t*) malloc ( sizeof ( kmeans_t ))))
	{
		return NULL;
	}

	if ( !( km->dataset = (double**) calloc ( dataset_size, sizeof ( double* ))))
	{
		return NULL;
	}

	for ( i=0; i < dataset_size; i++ )
	{
		if ( !( km->dataset[i] = (double*) calloc ( dataset_dim, sizeof ( double ))))
		{
			return NULL;
		}

		for ( j=0; j < dataset_dim; j++ )
		{
			km->dataset[i][j] = dataset[i][j];
		}
	}

	km->dataset_size = dataset_size;
	km->dataset_dim = dataset_dim;
	km->k = K;

	if ( !( km->clusters = (double***) calloc ( K, sizeof ( double** ))))
	{
		return NULL;
	}

	if ( !( km->cluster_sizes = (int*) calloc ( K, sizeof ( int* ))))
	{
		return NULL;
	}

	if ( !( km->centers = (double**) calloc ( K, sizeof ( double* ))))
	{
		return NULL;
	}

	for ( i=0; i < K; i++ )
	{
		if ( !( km->centers[i] = (double*) calloc ( dataset_dim, sizeof ( double ))))
		{
			return NULL;
		}
	}

	__kmeans_init_centers ( km );
	return km;
}		/* -----  end of function kmeans_new  ----- */

/**
 * \brief  Function that performs a single step for k-means algorithm
 * \param  km 	k-means object
 * \return 0 if no changes were performed by this step, 1 otherwise, -1 in case of error
 */

static int
__kmeans_step ( kmeans_t *km )
{
	int i, j, k,
	    best_center = 0;

	double dist = 0.0,
		  min_dist = DBL_MAX,
		  **old_centers = NULL;

	if ( km->clusters[0] )
	{
		for ( i=0; i < km->k; i++ )
		{
			for ( j=0; j < km->cluster_sizes[i]; j++ )
			{
				free ( km->clusters[i][j] );
				km->clusters[i][j] = NULL;
			}

			free ( km->clusters[i] );
			km->clusters[i] = NULL;
			km->cluster_sizes[i] = 0;
		}
	}

	if ( !( old_centers = (double**) alloca ( km->k * sizeof ( double* ))))
	{
		return -1;
	}

	for ( i=0; i < km->k; i++ )
	{
		if ( !( old_centers[i] = (double*) alloca ( km->dataset_dim * sizeof ( double ))))
		{
			return -1;
		}

		for ( j=0; j < km->dataset_dim; j++ )
		{
			old_centers[i][j] = km->centers[i][j];
		}
	}

	for ( i=0; i < km->dataset_size; i++ )
	{
		min_dist = DBL_MAX;
		best_center = 0;

		for ( j=0; j < km->k; j++ )
		{
			dist = 0.0;

			for ( k=0; k < km->dataset_dim; k++ )
			{
				dist += ( km->dataset[i][k] - km->centers[j][k] ) * ( km->dataset[i][k] - km->centers[j][k] );
			}

			if ( dist < min_dist )
			{
				min_dist = dist;
				best_center = j;
			}
		}

		if ( !( km->clusters[best_center] = (double**) realloc ( km->clusters[best_center], (++(km->cluster_sizes[best_center])) * sizeof ( double* ))))
		{
			return -1;
		}

		if ( !( km->clusters [best_center] [km->cluster_sizes[best_center]-1] = (double*) calloc ( km->dataset_dim, sizeof ( double ))))
		{
			return -1;
		}

		for ( j=0; j < km->dataset_dim; j++ )
		{
			km->clusters [best_center] [km->cluster_sizes[best_center]-1] [j] = km->dataset[i][j];
		}
	}

	for ( i=0; i < km->k; i++ )
	{
		for ( j=0; j < km->dataset_dim; j++ )
		{
			km->centers[i][j] = 0.0;

			for ( k=0; k < km->cluster_sizes[i]; k++ )
			{
				km->centers[i][j] += km->clusters[i][k][j];
			}

			if ( km->cluster_sizes[i] != 0 )
			{
				km->centers[i][j] /= (double) km->cluster_sizes[i];
			}
		}
	}

	for ( i=0; i < km->k; i++ )
	{
		for ( j=0; j < km->dataset_dim; j++ )
		{
			if ( km->centers[i][j] != old_centers[i][j] )
			{
				return 1;
			}
		}
	}

	return 0;
}		/* -----  end of function __kmeans_step  ----- */

/**
 * \brief  Perform the k-means algorithm over a k-means object
 * \param  km 	k-means object
 */

void
kmeans ( kmeans_t *km )
{
	while ( __kmeans_step ( km ) != 0 );
}		/* -----  end of function kmeans  ----- */

/**
 * \brief  Compute the heuristic coefficient associated to the current number of clusters through Schwarz's criterion
 * \param  km 	k-means object
 * \return Real value expressing how well that number of clusters models the dataset
 */

static double
__kmeans_heuristic_coefficient ( kmeans_t *km )
{
	int i, j, k;
	double distorsion = 0.0;

	for ( i=0; i < km->k; i++ )
	{
		for ( j=0; j < km->cluster_sizes[i]; j++ )
		{
			for ( k=0; k < km->dataset_dim; k++ )
			{
				distorsion += ( km->centers[i][k] - km->clusters[i][j][k] ) * ( km->centers[i][k] - km->clusters[i][j][k] );
			}
		}
	}

	return distorsion + km->k * log ( km->dataset_size );
}		/* -----  end of function __kmeans_heuristic_coefficient  ----- */

/**
 * \brief  Remove a k-means object
 * \param  km 	k-means object to be deallocaed
 */

void
kmeans_free ( kmeans_t *km )
{
	int i, j;

	for ( i=0; i < km->k; i++ )
	{
		for ( j=0; j < km->cluster_sizes[i]; j++ )
		{
			free ( km->clusters[i][j] );
			km->clusters[i][j] = NULL;
		}

		free ( km->clusters[i] );
		km->clusters[i] = NULL;
	}

	free ( km->clusters );
	km->clusters = NULL;

	free ( km->cluster_sizes );
	km->cluster_sizes = NULL;

	for ( i=0; i < km->k; i++ )
	{
		free ( km->centers[i] );
		km->centers[i] = NULL;
	}

	free ( km->centers );
	km->centers = NULL;

	for ( i=0; i < km->dataset_size; i++ )
	{
		free ( km->dataset[i] );
		km->dataset[i] = NULL;
	}

	free ( km->dataset );
	km->dataset = NULL;

	free ( km );
	km = NULL;
}		/* -----  end of function kmeans_free  ----- */

/**
 * \brief  Perform a k-means clustering over a dataset automatically choosing the best value of k using Schwarz's criterion
 * \param  dataset 		Dataset to be clustered
 * \param  dataset_size 	Number of elements in the dataset
 * \param  dataset_dim 	Dimension of each element of the dataset
 * \return Reference to the newly created k-means object, if successfull, NULL otherwise
 */

kmeans_t*
kmeans_auto ( double **dataset, int dataset_size, int dataset_dim )
{
	int i;

	double heuristic = 0.0,
		  best_heuristic = DBL_MAX;

	kmeans_t *km = NULL,
		    *best_km = NULL;

	for ( i=1; i <= dataset_size; i++ )
	{
		if ( !( km = kmeans_new ( dataset, dataset_size, dataset_dim, i )))
			return NULL;

		kmeans ( km );
		heuristic = __kmeans_heuristic_coefficient ( km );

		if ( heuristic < best_heuristic )
		{
			if ( best_km )
			{
				kmeans_free ( best_km );
			}

			best_km = km;
			best_heuristic = heuristic;
		} else {
			kmeans_free ( km );
		}
	}
	
	return best_km;
}		/* -----  end of function kmeans_auto  ----- */

