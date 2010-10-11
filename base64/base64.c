#include	<string.h>
#include	"cencode.h"
#include	"cdecode.h"

/**
 * \brief  base64-encode an input buffer
 * \param  in 		Sequence of bytes to be encoded
 * \param  in_len 	Length of the input sequence
 * \param  out 	Pointer to the buffer that will contain the output (its length must be at least 2*in_len + 1)
 */

void
base64_encode ( const char *in, size_t in_len, char **out )
{
	char pad[100] = { 0 };
	base64_encodestate e_state;

	base64_init_encodestate ( &e_state );
	base64_encode_block ( in, in_len, *out, &e_state );
	base64_encode_blockend ( pad, &e_state );
	
	pad[ strlen(pad) - 1 ] = 0;
	strcat ( *out, pad );
}		/* -----  end of function base64_encode  ----- */

/**
 * \brief  base64-decode a base64 string
 * \param  in 		base64 string to be decoded
 * \param  out 	Pointer to the buffer that will contain the output (its length should be at least the same like the length of in)
 */

void
base64_decode ( const char *in, char **out )
{
	base64_decodestate d_state;

	base64_init_decodestate ( &d_state );
	base64_decode_block ( in, strlen ( in ), *out, &d_state );
}		/* -----  end of function base64_decode  ----- */

