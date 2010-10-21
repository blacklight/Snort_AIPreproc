/*
 * =====================================================================================
 *
 *       Filename:  neural_som.h
 *
 *    Description:  Header file for neural_som mini-library
 *
 *        Version:  0.1
 *        Created:  15/10/2010 15:31:50
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#ifndef 	__NEURAL_SOM_H
#define 	__NEURAL_SOM_H

#include	<stddef.h>
#include	<time.h>

typedef struct  {
	double                 output;
	double                 input;

	struct som_synapsis_s  **synapses;
	size_t                 synapses_count;
} som_neuron_t;

typedef struct som_synapsis_s  {
	som_neuron_t    *neuron_in;
	som_neuron_t    *neuron_out;
	double          weight;
} som_synapsis_t;

typedef struct  {
	som_neuron_t    **neurons;
	size_t          neurons_count;
} som_input_layer_t;

typedef struct  {
	som_neuron_t    ***neurons;
	size_t          neurons_rows;
	size_t          neurons_cols;
} som_output_layer_t;

typedef struct  {
	som_input_layer_t   *input_layer;
	som_output_layer_t  *output_layer;
	double              T_learning_param;
	time_t              serialization_time;
} som_network_t;

void                 som_network_destroy ( som_network_t* );
void                 som_set_inputs ( som_network_t*, double* );
void                 som_train ( som_network_t*, double**, size_t, size_t );
void                 som_serialize ( som_network_t*, const char* );
double               som_get_best_neuron_coordinates ( som_network_t*, size_t*, size_t* );
som_network_t*       som_deserialize ( const char* );
som_network_t*       som_network_new ( size_t, size_t, size_t );

#endif

