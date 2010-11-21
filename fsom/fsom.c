/*
 * =====================================================================================
 *
 *       Filename:  fsom.c
 *
 *    Description:  Manage a self-organizing map (SOM) as a neural network
 *
 *        Version:  0.1
 *        Created:  15/10/2010 13:53:31
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#include	"fsom.h"

#include	<alloca.h>
#include	<float.h>
#include	<limits.h>
#include	<math.h>
#include	<memory.h>
#include	<stdio.h>
#include	<stdlib.h>

#ifndef 	M_E
#define 	M_E		2.7182818284590452354
#endif

/**
 * \brief  Create a new synapsis between two neurons
 * \param  input_neuron 		Input neuron for the synapsis
 * \param  output_neuron 	Output neuron for the synapsis
 * \param  weight 			Weight of the synapsis (set it to 0 for a random value between 0 and 1)
 * \return A pointer representing the new synapsis
 */

static som_synapsis_t*
som_synapsis_new ( som_neuron_t *input_neuron, som_neuron_t *output_neuron, double weight )
{
	som_synapsis_t  *synapsis = NULL;

	if ( !( synapsis = ( som_synapsis_t* ) malloc ( sizeof ( som_synapsis_t ))))
	{
		return NULL;
	}

	synapsis->neuron_in  = input_neuron;
	synapsis->neuron_out = output_neuron;

	if ( weight == 0.0 )
	{
		synapsis->weight = (double) rand() / (double) UINT_MAX;
	} else {
		synapsis->weight = weight;
	}

	if ( !( input_neuron->synapses = ( som_synapsis_t** ) realloc ( input_neuron->synapses, (++( input_neuron->synapses_count )) * sizeof ( som_synapsis_t ))))
	{
		free ( synapsis );
		return NULL;
	}
	
	if ( !( output_neuron->synapses = ( som_synapsis_t** ) realloc ( output_neuron->synapses, (++( output_neuron->synapses_count )) * sizeof ( som_synapsis_t ))))
	{
		free ( synapsis );
		return NULL;
	}

	input_neuron->synapses[ input_neuron->synapses_count - 1 ] = synapsis;
	output_neuron->synapses[ output_neuron->synapses_count - 1 ] = synapsis;
	return synapsis;
}		/* -----  end of function som_synapsis_new  ----- */


/**
 * \brief  Create a new neuron
 * \return The new neuron
 */

static som_neuron_t*
som_neuron_new ()
{
	som_neuron_t  *neuron = NULL;

	if ( !( neuron = ( som_neuron_t* ) malloc ( sizeof ( som_neuron_t ))))
	{
		return NULL;
	}

	neuron->output = 0.0;
	neuron->input  = 0.0;
	neuron->synapses = NULL;
	neuron->synapses_count = 0;

	return neuron;
}		/* -----  end of function som_neuron_new  ----- */

/**
 * \brief  Deallocate a neuron
 * \param  neuron 	Neuron to be deallocated
 */

static void
som_neuron_destroy ( som_neuron_t *neuron )
{
	if ( !neuron )
	{
		return;
	}

	free ( neuron );
	neuron = NULL;
}		/* -----  end of function som_neuron_destroy  ----- */

/**
 * \brief  Create a new input layer
 * \param  neurons_count 	Number of neurons in the new input layer
 * \return The new layer
 */

static som_input_layer_t*
som_input_layer_new ( size_t neurons_count )
{
	size_t i = 0,
		  j = 0;

	som_input_layer_t *layer = NULL;

	if ( !( layer = ( som_input_layer_t* ) malloc ( sizeof ( som_input_layer_t ))))
	{
		return NULL;
	}

	layer->neurons_count = neurons_count;

	if ( !( layer->neurons = ( som_neuron_t** ) malloc ( neurons_count * sizeof ( som_neuron_t* ))))
	{
		free ( layer );
		return NULL;
	}
	
	for ( i=0; i < neurons_count; i++ )
	{
		if ( !( layer->neurons[i] = som_neuron_new() ))
		{
			for ( j=0; j < i; j++ )
			{
				som_neuron_destroy ( layer->neurons[j] );
				layer->neurons[j] = NULL;
			}

			free ( layer->neurons );
			free ( layer );
			return NULL;
		}
	}

	return layer;
}		/* -----  end of function som_input_layer_new  ----- */

/**
 * \brief  Create a new output layer
 * \param  neurons_rows 	Number of rows in the matrix of output neurons
 * \param  neurons_cols 	Number of cols in the matrix of output neurons
 * \return The new layer
 */

static som_output_layer_t*
som_output_layer_new ( size_t neurons_rows, size_t neurons_cols )
{
	size_t i = 0,
		  j = 0,
		  k = 0,
		  l = 0;

	som_output_layer_t *layer = NULL;

	if ( !( layer = ( som_output_layer_t* ) malloc ( sizeof ( som_output_layer_t ))))
	{
		return NULL;
	}

	layer->neurons_rows = neurons_rows;
	layer->neurons_cols = neurons_cols;

	if ( !( layer->neurons = ( som_neuron_t*** ) malloc ( neurons_rows * neurons_cols * sizeof ( som_neuron_t** ))))
	{
		free ( layer );
		return NULL;
	}

	for ( i=0; i < neurons_rows; i++ )
	{
		if ( !( layer->neurons[i] = ( som_neuron_t** ) malloc ( neurons_cols * sizeof ( som_neuron_t* ))))
		{
			for ( j=0; j < i; j++ )
			{
				free ( layer->neurons[j] );
				layer->neurons[j] = NULL;
			}

			free ( layer->neurons );
			free ( layer );
			return NULL;
		}
	}

	for ( i=0; i < neurons_rows; i++ )
	{
		for ( j=0; j < neurons_cols; j++ )
		{
			if ( !( layer->neurons[i][j] = som_neuron_new() ))
			{
				for ( k=0; k < i; k++ )
				{
					for ( l=0; l < j; l++ )
					{
						som_neuron_destroy ( layer->neurons[k][l] );
						layer->neurons[k][l] = NULL;
					}

					free ( layer->neurons[k] );
					layer->neurons[k] = NULL;
				}

				free ( layer->neurons );
				return NULL;
			}
		}
	}

	return layer;
}		/* -----  end of function som_output_layer_new  ----- */

/**
 * \brief  Connect two layers of a neural SOM
 * \param  input_layer 	Reference to the input layer
 * \param  output_layer 	Reference to the output layer
 */

static void
som_connect_layers ( som_input_layer_t **input_layer, som_output_layer_t **output_layer )
{
	size_t i = 0,
		  j = 0,
		  k = 0;

	for ( i=0; i < (*output_layer)->neurons_rows; i++ )
	{
		for ( j=0; j < (*output_layer)->neurons_cols; j++ )
		{
			for ( k=0; k < (*input_layer)->neurons_count; k++ )
			{
				if ( !( som_synapsis_new ( (*input_layer)->neurons[k], (*output_layer)->neurons[i][j], 0.0 )))
				{
					return;
				}
			}
		}
	}
}		/* -----  end of function som_connect_layers  ----- */

/**
 * \brief  Initialize a new SOM neural network
 * \param  input_neurons 		Number of neurons in the input layer
 * \param  output_neurons_rows 	Number of rows of neurons in the output layer
 * \param  output_neurons_cols 	Number of cols of neurons in the output layer
 * \return The new SOM neural network
 */

som_network_t*
som_network_new ( size_t input_neurons, size_t output_neurons_rows, size_t output_neurons_cols )
{
	som_network_t *net = NULL;
	srand ( time ( NULL ));

	if ( !( net = ( som_network_t* ) malloc ( sizeof ( som_network_t ))))
	{
		return NULL;
	}

	memset ( net, 0, sizeof ( som_network_t ));

	if ( !( net->input_layer = som_input_layer_new ( input_neurons )))
	{
		free ( net );
		return NULL;
	}

	if ( !( net->output_layer = som_output_layer_new ( output_neurons_rows, output_neurons_cols )))
	{
		free ( net->input_layer );
		free ( net );
		return NULL;
	}

	net->T_learning_param = 0.0;
	net->serialization_time = ( time_t ) 0;
	som_connect_layers ( &( net->input_layer ), &( net->output_layer ));
	return net;
}		/* -----  end of function som_network_new  ----- */

/**
 * \brief  Deallocate an input layer
 * \param  net 	Network whose input layer should be deallocated
 */

static void
som_input_layer_destroy ( som_network_t *net )
{
	size_t i = 0,
		  j = 0,
		  k = 0;

	if ( !( net->input_layer ))
	{
		return;
	}

	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		for ( j=0; j < net->input_layer->neurons[i]->synapses_count; j++ )
		{
			if ( (int) j < 0 )
			{
				break;
			}

			if ( net->input_layer->neurons[i]->synapses )
			{
				if ( net->input_layer->neurons[i]->synapses[j] )
				{
					if ( net->input_layer->neurons[i]->synapses[j]->neuron_out )
					{
						/* net->input_layer->neurons[i]->synapses[j]->neuron_out->synapses[k]->neuron_in = NULL; */

						for ( k=0; k < net->input_layer->neurons[i]->synapses[j]->neuron_out->synapses_count; k++ )
						{
							if ( net->input_layer->neurons[i]->synapses[j]->neuron_out->synapses[k] )
							{
								net->input_layer->neurons[i]->synapses[j]->neuron_out->synapses[k]->neuron_in = NULL;
								net->input_layer->neurons[i]->synapses[j]->neuron_out->synapses[k] = NULL;
							}
						}
					}

					free ( net->input_layer->neurons[i]->synapses[j] );
					net->input_layer->neurons[i]->synapses[j] = NULL;
				}

				free ( net->input_layer->neurons[i]->synapses );
				net->input_layer->neurons[i]->synapses = NULL;
			}
		}

		som_neuron_destroy ( net->input_layer->neurons[i] );
		net->input_layer->neurons[i] = NULL;
	}

	free ( net->input_layer->neurons );
	net->input_layer->neurons = NULL;

	free ( net->input_layer );
	net->input_layer = NULL;
}		/* -----  end of function som_input_layer_destroy  ----- */

/**
 * \brief  Deallocate an output layer
 * \param  net 	Network whose output layer should be deallocated
 */

static void
som_output_layer_destroy ( som_network_t *net )
{
	size_t i = 0,
		  j = 0,
		  k = 0;

	if ( !( net->output_layer ))
	{
		return;
	}

	for ( i=0; i < net->output_layer->neurons_rows; i++ )
	{
		for ( j=0; j < net->output_layer->neurons_cols; j++ )
		{
			for ( k=0; k < net->output_layer->neurons[i][j]->synapses_count; k++ )
			{
				if ( net->output_layer->neurons[i][j]->synapses )
				{
					if ( net->output_layer->neurons[i][j]->synapses[k] )
					{
						free ( net->output_layer->neurons[i][j]->synapses[k] );
						net->output_layer->neurons[i][j]->synapses[k] = NULL;
					}

					free ( net->output_layer->neurons[i][j]->synapses );
					net->output_layer->neurons[i][j]->synapses = NULL;
				}
			}

			som_neuron_destroy ( net->output_layer->neurons[i][j] );
			net->output_layer->neurons[i][j] = NULL;
		}

		free ( net->output_layer->neurons[i] );
		net->output_layer->neurons[i] = NULL;
	}

	free ( net->output_layer->neurons );
	net->output_layer->neurons = NULL;

	free ( net->output_layer );
	net->output_layer = NULL;
}		/* -----  end of function som_output_layer_destroy  ----- */

/**
 * \brief  Deallocate a SOM neural network
 * \param  net 	Network to be deallocated
 */

void
som_network_destroy ( som_network_t *net )
{
	if ( !net )
	{
		return;
	}

	som_input_layer_destroy  ( net );
	som_output_layer_destroy ( net );
	free ( net );
	net = NULL;
}		/* -----  end of function som_network_destroy  ----- */

/**
 * \brief  Set a vector as input for the network
 * \param  net 	SOM neural network
 * \param  data 	Vector to be passed as input for the network
 */

void
som_set_inputs ( som_network_t *net, double *data )
{
	size_t i = 0;

	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		net->input_layer->neurons[i]->input = data[i];
	}
}		/* -----  end of function som_set_inputs  ----- */

/**
 * \brief  Get the coordinates of the output neuron closest to the current input data
 * \param  net 	SOM neural network
 * \param  x 		Reference to the X coordinate of the best output neuron
 * \param  y 		Reference to the Y coordinate of the best output neuron
 * \return The value of the module ||X-W|| (squared euclidean distance) for the best neuron
 */

double
som_get_best_neuron_coordinates ( som_network_t *net, size_t *x, size_t *y )
{
	size_t i = 0,
		  j = 0,
		  k = 0;

	double mod = 0.0,
		  best_dist = 0.0;

	for ( i=0; i < net->output_layer->neurons_rows; i++ )
	{
		for ( j=0; j < net->output_layer->neurons_cols; j++ )
		{
			mod = 0.0;

			for ( k=0; k < net->output_layer->neurons[i][j]->synapses_count; k++ )
			{
				mod += ( net->input_layer->neurons[k]->input - net->output_layer->neurons[i][j]->synapses[k]->weight ) *
					( net->input_layer->neurons[k]->input - net->output_layer->neurons[i][j]->synapses[k]->weight );
			}

			if (( i == 0 && j == 0 ) || ( mod < best_dist ))
			{
				best_dist = mod;
				*x = i;
				*y = j;
			}
		}
	}

	return mod;
}		/* -----  end of function som_get_best_neuron_coordinates  ----- */

/**
 * \brief  Get the n-th approximated step of the analytic continuation of the Lambert W-function of a real number x (see "Numerical Evaluation of the Lambert W Function and Application to Generation of Generalized Gaussian Noise With Exponent 1/2" from Chapeau-Blondeau and Monir, IEEE Transactions on Signal Processing, vol.50, no.9, Sep.2002)
 * \param  x 	Input variable of which we're going to compute W[-1](x)
 * \param  n 	Number of steps in the series computation
 * \return W[-1](x)
 */

static double
lambert_W1_function ( double x, int n )
{
	int j = 0,
	    k = 0;

	double *alphas = NULL,
		  *mus = NULL,
		  p = 0.0,
		  res = 0.0;

	if ( !( alphas = (double*) alloca ( (n+1) * sizeof ( double ))))
		return 0.0;

	if ( !( mus = (double*) alloca ( (n+1) * sizeof ( double ))))
		return 0.0;

	p = - sqrt ( 2 * ( M_E * x + 1 ));

	for ( k=0; k < n; k++ )
	{
		if ( k == 0 )
		{
			mus[k] = -1;
			alphas[k] = 2;
		} else if ( k == 1 ) {
			mus[k] = 1;
			alphas[k] = -1;
		} else {
			alphas[k] = 0.0;

			for ( j=2; j < k; j++ )
			{
				alphas[k] += mus[j] * mus[k-j+1];
			}

			mus[k] = ((double) ( k - 1 ) / (double) ( k + 1 )) * ( (mus[k-2] / 2.0) + (alphas[k-2] / 4.0) ) - ( alphas[k] / 2.0 ) - ( mus[k-1] / ((double) k + 1 ));
		}

		res += ( mus[k] * pow ( p, (double) k ));
	}

	return res;
}		/* -----  end of function lambert_W1_function  ----- */

/**
 * \brief  Get the learning rate of a step of the learning process in function of the current iteration number
 * \param  net 	SOM neural network
 * \param  t 		Iteration number
 * \param  M 		Maximum value for the learning rate (in [0:1])
 * \param  N 		Iteration number after which the function equals the "cutoff" value (0.01), i.e. the learning rate becomes almost meaningless
 * \return Learning rate
 */

static double
som_learning_rate ( som_network_t* net, size_t t, double M, size_t N )
{
	double value = 0.0,
		  T = 0.0,
		  K = 0.0,
		  W = 0.0,
		  W_arg = 0.0;

	if ( net->T_learning_param == 0.0 )
	{
		K = ( M * (double) N * M_E ) / 0.01;
		W_arg = -((double) N ) / K;
		W = lambert_W1_function ( W_arg, 1000 );
		T = K * exp ( W );
		net->T_learning_param = T;
	} else {
		T = net->T_learning_param;
	}

	value = M * ( (double) t / T) * exp ( 1 - ( (double) t / T ));
	return value;
}		/* -----  end of function som_learning_rate  ----- */

/**
 * \brief  Training iteration for the network given a single input data set
 * \param  net 	SOM neural network
 * \param  data 	Input data
 * \param  iter 	Iteration number
 */

static void
som_train_iteration ( som_network_t *net, double *data, size_t iter )
{
	size_t x = 0,
		  y = 0,
		  i = 0,
		  j = 0,
		  k = 0,
		  dist = 0;

	double l_rate = 0.0;

	l_rate = som_learning_rate ( net, iter, 0.8, 200 );
	som_set_inputs ( net, data );
	som_get_best_neuron_coordinates ( net, &x, &y );

	for ( i=0; i < net->output_layer->neurons_rows; i++ )
	{
		for ( j=0; j < net->output_layer->neurons_cols; j++ )
		{
			dist = abs ( x-i ) + abs ( y-j );
			dist = dist * dist * dist * dist;

			for ( k=0; k < net->input_layer->neurons_count; k++ )
			{
				net->output_layer->neurons[i][j]->synapses[k]->weight +=
					(( 1.0 / ((double) dist + 1) ) *
					  l_rate * ( net->input_layer->neurons[k]->input - net->output_layer->neurons[i][j]->synapses[k]->weight ));
			}
		}
	}
}		/* -----  end of function som_train_loop  ----- */

/**
 * \brief  Initialize the synaptical weights of the network using the algorithm proposed in "Improving the Self-Organization Feature Map Algorithm Using an Efficient Initialization Scheme", by Su, Liu and Chang, on "Tamkang Journal of Science and Engineering", vol.5, no.1, pp.35-48, 2002
 * \param  net 	SOM neural network
 * \param  data 	Input data set
 * \param  n_data 	Number of vectors in the input set
 */

void
som_init_weights ( som_network_t *net, double **data, size_t n_data )
{
	size_t i = 0,
		  j = 0,
		  k = 0,
		  out_rows = 0,
		  out_cols = 0,
		  in_size  = 0,
		  max_i = 0,
		  max_j = 0,
		  medium_i = 0,
		  medium_j = 0;

	double dist = 0.0,
		  max_dist = 0.0;

	double *avg_data = NULL;

	if ( !( avg_data = (double*) alloca ( net->input_layer->neurons_count * sizeof ( double ))))
	{
		return;
	}

	/* Find the couple of data sets with the maximum distance */
	for ( i=0; i < n_data; i++ )
	{
		for ( j=0; j < n_data; j++ )
		{
			if ( i != j )
			{
				dist = 0.0;

				for ( k=0; k < net->input_layer->neurons_count; k++ )
				{
					dist += fabs ( data[i][k] - data[j][k] );
				}

				if ( dist > max_dist )
				{
					max_dist = dist;
					max_i = i;
					max_j = j;
				}
			}
		}
	}

	/* Compute the avg_data vector as the vector containing the average values of (data[max_i], data[max_j]) */
	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		avg_data[i] = fabs ( data[max_i][i] + data[max_j][i] ) / 2.0;
	}

	/* Initialize the upper-right and bottom-left vertex of the output matrix with these values */
	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		net->output_layer->neurons[0][ net->output_layer->neurons_cols - 1 ]->synapses[i]->weight = data[max_i][i];
		net->output_layer->neurons[ net->output_layer->neurons_rows - 1 ][0]->synapses[i]->weight = data[max_j][i];
	}

	/* Find the vector having the maximum distance from the maximum distance vectors */
	max_dist = DBL_MAX;

	for ( i=0; i < n_data; i++ )
	{
		if ( i != max_i && i != max_j )
		{
			dist = 0.0;

			for ( k=0; k < net->input_layer->neurons_count; k++ )
			{
				dist += fabs ( data[i][k] - avg_data[i] );

				if ( dist < max_dist )
				{
					max_dist = dist;
					medium_i = i;
				}
			}
		}
	}

	/* Initialize the upper-left corner with the values of this vector */
	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		net->output_layer->neurons[0][0]->synapses[i]->weight = data[medium_i][i];
	}

	/* avg_data contains the average values of the 3 vectors computed above */
	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		avg_data[i] = fabs ( data[max_i][i] + data[max_j][i] + data[medium_i][i] ) / 3.0;
	}

	/* Find the vector having the maximum distance from the 3 vectors above */
	max_dist = DBL_MAX;

	for ( i=0; i < n_data; i++ )
	{
		if ( i != max_i && i != max_j && i != medium_i )
		{
			dist = 0.0;

			for ( k=0; k < net->input_layer->neurons_count; k++ )
			{
				dist += fabs ( data[i][k] - avg_data[i] );

				if ( dist < max_dist )
				{
					max_dist = dist;
					medium_j = i;
				}
			}
		}
	}

	/* Initialize the bottom-right corner with the values of this vector */
	for ( i=0; i < net->input_layer->neurons_count; i++ )
	{
		net->output_layer->neurons[ net->output_layer->neurons_rows - 1 ][ net->output_layer->neurons_cols - 1 ]->synapses[i]->weight = data[medium_j][i];
	}

	/* Initialize the weights on the 4 edges */
	out_rows = net->output_layer->neurons_rows;
	out_cols = net->output_layer->neurons_cols;
	in_size  = net->input_layer->neurons_count;

	for ( j=1; j < out_cols - 1; j++ )
	{
		for ( k=0; k < in_size; k++ )
		{
			net->output_layer->neurons[0][j]->synapses[k]->weight =
				( ((double) j - 1) / ( out_cols - 1 )) * net->output_layer->neurons[0][ out_cols - 1 ]->synapses[k]->weight +
				( (double) ( out_cols - j ) / ((double) out_cols - 1 )) * net->output_layer->neurons[0][0]->synapses[k]->weight;
		}
	}

	for ( j=1; j < out_cols - 1; j++ )
	{
		for ( k=0; k < in_size; k++ )
		{
			net->output_layer->neurons[ out_rows - 1 ][j]->synapses[k]->weight =
				( ((double) j - 1) / ((double) out_cols - 1 )) * net->output_layer->neurons[ out_rows - 1 ][ out_cols - 1 ]->synapses[k]->weight +
				( (double) ( out_cols - j ) / ((double) out_cols - 1 )) * net->output_layer->neurons[ out_rows - 1 ][0]->synapses[k]->weight;
		}
	}

	for ( i=1; i < out_rows - 1; i++ )
	{
		for ( k=0; k < in_size; k++ )
		{
			net->output_layer->neurons[i][0]->synapses[k]->weight =
				( ((double) i - 1) / ((double) out_rows - 1 )) * net->output_layer->neurons[ out_rows-1 ][0]->synapses[k]->weight +
				( (double) ( out_rows - i ) / ((double) out_rows - 1 )) * net->output_layer->neurons[0][0]->synapses[k]->weight;
		}
	}

	for ( i=1; i < out_rows - 1; i++ )
	{
		for ( k=0; k < in_size; k++ )
		{
			net->output_layer->neurons[i][ out_cols - 1 ]->synapses[k]->weight =
				( ((double) i - 1) / ((double) out_rows - 1 )) * net->output_layer->neurons[ out_rows - 1 ][ out_cols - 1 ]->synapses[k]->weight +
				( (double) ( out_rows - i ) / ((double) out_rows - 1 )) * net->output_layer->neurons[0][ out_cols - 1 ]->synapses[k]->weight;
		}
	}

	/* Initialize the weights in the middle of the matrix */
	for ( i=1; i < out_rows - 1; i++ )
	{
		for ( j=1; j < out_cols - 1; j++ )
		{
			for ( k=0; k < in_size; k++ )
			{
				net->output_layer->neurons[i][j]->synapses[k]->weight =
					( (((double) j - 1)*((double) i - 1)) / (((double) out_rows - 1)*((double) out_cols - 1))) * net->output_layer->neurons[ out_rows - 1 ][ out_cols - 1 ]->synapses[k]->weight +
					( (((double) j - 1)*(double) (out_rows - i)) / (((double) out_rows - 1)*((double) out_cols - 1))) * net->output_layer->neurons[0][ out_cols - 1 ]->synapses[k]->weight +
					( ((double) (out_cols - j)*((double) i - 1)) / (((double) out_rows - 1)*((double) out_cols - 1))) * net->output_layer->neurons[ out_rows - 1 ][0]->synapses[k]->weight +
					( ((double) (out_cols - j)*(double) (out_rows - i)) / (((double) out_rows - 1)*((double) out_cols - 1))) * net->output_layer->neurons[0][0]->synapses[k]->weight;
			}
		}
	}
}		/* -----  end of function som_init_weights  ----- */

/**
 * \brief  Train the self-organizing map through a data set
 * \param  net 	SOM neural network
 * \param  data 	Data set (set of input vectors)
 * \param  n_data 	Number of input vectors in data
 * \param  iter 	Number of iterations
 */

void
som_train ( som_network_t *net, double **data, size_t n_data, size_t iter )
{
	size_t n = 0,
		  k = 0,
		  x = 0,
		  y = 0;

	for ( n=0; n < n_data; n++ )
	{
		for ( k=1; k <= iter; k++ )
		{
			som_train_iteration ( net, data[n], k );

			if ( som_get_best_neuron_coordinates ( net, &x, &y ) == 0.0 )
				break;
		}
	}
}		/* -----  end of function som_train  ----- */

/**
 * \brief  Serialize a neural network on a binary file
 * \param  net 	SOM network to be serialized
 * \param  fname 	Output file name
 */

void
som_serialize ( som_network_t *net, const char *fname )
{
	FILE *fp = NULL;
	size_t i = 0,
		  j = 0,
		  k = 0;
	
	if ( !( fp = fopen ( fname, "w" )))
	{
		return;
	}

	net->serialization_time = time ( NULL );
	fwrite ( &(net->serialization_time), sizeof ( time_t ), 1, fp );
	fwrite ( &(net->T_learning_param), sizeof ( double ), 1, fp );
	fwrite ( &(net->input_layer->neurons_count), sizeof ( size_t ), 1, fp );
	fwrite ( &(net->output_layer->neurons_rows), sizeof ( size_t ), 1, fp );
	fwrite ( &(net->output_layer->neurons_cols), sizeof ( size_t ), 1, fp );

	for ( i=0; i < net->output_layer->neurons_rows; i++ )
	{
		for ( j=0; j < net->output_layer->neurons_cols; j++ )
		{
			for ( k=0; k < net->output_layer->neurons[i][j]->synapses_count; k++ )
			{
				fwrite ( &(net->output_layer->neurons[i][j]->synapses[k]->weight), sizeof ( double ), 1, fp );
			}
		}
	}

	fclose ( fp );
}		/* -----  end of function som_serialize  ----- */

/**
 * \brief  Initialize a SOM neural network from a serialized one on a file
 * \param  fname 	Binary file containing the network
 * \return The initialized network in case of success, NULL otherwise
 */

som_network_t*
som_deserialize ( const char* fname )
{
	som_network_t *net = NULL;
	FILE *fp = NULL;
	double weight = 0.0;
	size_t i = 0,
		  j = 0,
		  k = 0,
		  input_neurons = 0,
		  output_neurons_rows = 0,
		  output_neurons_cols = 0;

	if ( !( fp = fopen ( fname, "r" )))
	{
		return NULL;
	}

	if ( !( net = ( som_network_t* ) malloc ( sizeof ( som_network_t ))))
	{
		fclose ( fp );
		return NULL;
	}

	memset ( net, 0, sizeof ( som_network_t ));

	fread ( &(net->serialization_time), sizeof ( time_t ), 1, fp );
	fread ( &(net->T_learning_param ), sizeof ( double ), 1, fp );
	fread ( &input_neurons, sizeof ( size_t ), 1, fp );
	fread ( &output_neurons_rows, sizeof ( size_t ), 1, fp );
	fread ( &output_neurons_cols, sizeof ( size_t ), 1, fp );

	if ( !( net->input_layer = som_input_layer_new ( input_neurons )))
	{
		free ( net );
		fclose ( fp );
		return NULL;
	}

	if ( !( net->output_layer = som_output_layer_new ( output_neurons_rows, output_neurons_cols )))
	{
		free ( net->input_layer );
		free ( net );
		fclose ( fp );
		return NULL;
	}

	for ( i=0; i < output_neurons_rows; i++ )
	{
		for ( j=0; j < output_neurons_cols; j++ )
		{
			for ( k=0; k < input_neurons; k++ )
			{
				fread ( &weight, sizeof ( double ), 1, fp );

				if ( !( som_synapsis_new ( net->input_layer->neurons[k], net->output_layer->neurons[i][j], weight )))
				{
					som_input_layer_destroy ( net );
					som_output_layer_destroy ( net );
					fclose ( fp );
					return NULL;
				}
			}
		}
	}

	fclose ( fp );
	return net;
}		/* -----  end of function som_deserialize  ----- */

