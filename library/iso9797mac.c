/*
 *  Retail MAC Implemention from ANSI
 *  ISO 9797-Alg3 CBC-MAC Algorithm compliant implementation
 *
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Definition of CMAC:
 * http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
 * RFC 4493 "The AES-CMAC Algorithm"
 */




#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_RETAILMAC_C)

#include "mbedtls/retailmac.h"
#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

void print_hex(char* name, char* s, int l) {
	if(name != NULL){
		mbedtls_printf("Name: %s\n", name);
	}
	for(int i = 0;  i < l; i++) {
		if(i != 0 && (i +1) % 16 == 0){
			mbedtls_printf("%02hhX\n", s[i]);
		}
		else if(i != 0 && (i +1) % 8 == 0){
			mbedtls_printf("%02hhX  ", s[i]);
		} else if(i != 0 && (i +1) % 4 == 0){
			mbedtls_printf("%02hhX ", s[i]);
		}
		else{
			mbedtls_printf("%02hhX", s[i]);
		}
	}
	mbedtls_printf("\n");
}

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Initialize context
 */
void mbedtls_retailmac_init( mbedtls_retailmac_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_retailmac_context ) );
}

/*
 * Free context
 */
void mbedtls_retailmac_free( mbedtls_retailmac_context *ctx )
{
	mbedtls_des_free( &ctx->key_1_ctx );
	mbedtls_des_free( &ctx->key_2_ctx );
    mbedtls_zeroize( ctx, sizeof( mbedtls_retailmac_context ) );
}

/*
 * Set key and prepare context for use
 */
int mbedtls_retailmac_setkey( mbedtls_retailmac_context *ctx,
                         const unsigned char key_1[8],
			 const unsigned char key_2[8]){
	int ret;
	if(key_1 == NULL || key_2 == NULL)
		return MBEDTLS_ERR_RETAILMAC_BAD_INPUT;
	mbedtls_des_init( &ctx->key_1_ctx);
	mbedtls_des_init( &ctx->key_2_ctx);

	if( (ret = mbedtls_des_setkey_enc( &ctx->key_1_ctx, key_1) ) != 0)
		return(ret);
	if( (ret = mbedtls_des_setkey_dec( &ctx->key_2_ctx, key_2) ) != 0)
		return(ret);
	return 0;
}

/*
 * Create padded last block from (partial) last block.
 */
static int cbcmac_pad_alg1( unsigned char* padded_block_out,
		              size_t padded_block_out_len,
                      const unsigned char *upadded_block_in,
                      size_t upadded_block_in_len)
{
	if(padded_block_out_len < upadded_block_in_len)
		return 1;
    size_t j;
    for( j = 0; j < padded_block_out_len; j++ )
    {
        if( j < upadded_block_in_len )
        	padded_block_out[j] = upadded_block_in[j];
        else
        	padded_block_out[j] = 0x00;
    }
    return 0;
}

/*
 * XOR 64-bit
 * Here, macro results in smaller compiled code than static inline function
 */

#define XOR_BLOCK( o, i1, i2, blocksize )                                                \
    for( i = 0; i < (blocksize); i++ )                                               \
        ( o )[i] = ( i1 )[i] ^ ( i2 )[i];



/*
 * Update the Retail MAC state using an input block x
 * XOR_64( state, ( x ), state );
 */
#define UPDATE_RETAILAMAC( x,blocksize )                                                    \
do {                                                                        \
	XOR_BLOCK( state, ( x ), state, (blocksize) );\
    if( ( ret = mbedtls_des_crypt_ecb( &ctx->key_1_ctx,                    \
    		state, state ) ) != 0 )   \
        return( ret );                                                      \
} while( 0 )

/*
 * Generate tag on complete message
 */
int mbedtls_cbcmac_alg3_generate( mbedtls_retailmac_context *ctx,
                            const unsigned char *input, size_t in_len,
                            unsigned char* tag,  size_t tag_len)

{
	size_t blocksize = 8;
    unsigned char* state = malloc(blocksize*sizeof(char));
    memset( state, 0, blocksize );
    unsigned char* M_last =  malloc(blocksize*sizeof(char));
    int     n, i, j, ret, needs_padding;
    size_t olen;

    if( tag_len < 0 || tag_len > blocksize  )
        return( MBEDTLS_ERR_RETAILMAC_BAD_INPUT );
    if( in_len == 0 )
        needs_padding = 1;
    else
        needs_padding = in_len % blocksize != 0;

    n = in_len / blocksize ;

    for( j = 0; j < n ; j++ )
    {
    	//print_hex("Next Block", input + 8 * j, 8);
    	UPDATE_RETAILAMAC( (input + blocksize * j), (blocksize) );
    	//print_hex("State", state, 8);
    	//printf("\n");
    }

    if(needs_padding){
    	cbcmac_pad_alg1( M_last, blocksize, input + blocksize *  n , in_len % blocksize );
    	//cbcmac_pad_alg1( M_last, input + blocksize *  n , in_len % blocksize );
    	UPDATE_RETAILAMAC( M_last, (blocksize) );
    	//print_hex("State after padded block", state, 8);
    }

    //printf("\n");
    mbedtls_des_crypt_ecb( &ctx->key_2_ctx, state, state);
    //print_hex("Decrypt", state, 8);
    mbedtls_des_crypt_ecb( &ctx->key_1_ctx, state, state);
    //print_hex("Rencrypt", state, 8);
    memcpy( tag, state, tag_len );

    free(state);
    free(M_last);

    return( 0 );

}


#undef XOR_64
#undef UPDATE_RETAILAMC

/*
 * Generate tag on complete message
 * Retail MAC has a 4 byte tag per ANS X9-19
 */
int mbedtls_retailmac_generate( mbedtls_retailmac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char tag[4])

{
	return mbedtls_cbcmac_alg3_generate(ctx, input, in_len, tag, 4);
}


#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_DES_C)

// ISO/IEC 9797-1:2011
// Appendix B.4
// Algorithm 3
// Padding option 1
// Example 1

static const unsigned char key_1[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};
static const unsigned char test_data_1[] = {
  0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
  0x69, 0x6d, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20
};
static const unsigned int test_data_1_len = 24;

static const unsigned char result_1[] = {
		  0xa1, 0xc7, 0x2e, 0x74, 0xea, 0x3f, 0xa9, 0xb6
};
unsigned int result_1_len = 8;

// ISO/IEC 9797-1:2011
// Appendix B.4
// Algorithm 3
// Padding option 1
// Example 2
// Key is the same as Example 1
static const unsigned char key_2[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};
static const unsigned char test_data_2[] = {
	0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
	0x69, 0x6d, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x69, 0x74

};
static const unsigned int test_data_2_len = 22;
static const unsigned char result_2[] = {
	0x2E, 0x2B, 0x14, 0x28, 0xCC, 0x78, 0x25, 0x4F
};
static const unsigned int result_2_len = 8;

// ANSI X9.19:1996
// Example 3
static const unsigned char key_3[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};
static const unsigned char test_data_3[] = {
		0x31, 0x31, 0x1C, 0x39, 0x31, 0x38, 0x32, 0x37, 0x33, 0x36, 0x34, 0x35, 0x1C,
		0x1C, 0x35, 0x38, 0x31, 0x34, 0x33, 0x32, 0x37, 0x36, 0x1C, 0x1C, 0x3B, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
		0x35, 0x36, 0x3D, 0x39, 0x39, 0x31, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x3F,
		0x1C, 0x30, 0x30, 0x30, 0x31, 0x32, 0x35, 0x30, 0x30, 0x1c, 0x39, 0x37, 0x38,
		0x36, 0x35, 0x33, 0x34, 0x31, 0x32, 0x34, 0x38, 0x37, 0x36, 0x39, 0x32, 0x33,
		0x1C, 0x00,
};
static const unsigned int test_data_3_len = 80;
static const unsigned char result_3[] = {
		0xC2, 0x09, 0xCC, 0xB7, 0x8E, 0xE1, 0xB6, 0x06
};
static const unsigned int result_3_len = 8;



int mbedtls_retailmac_self_test( int verbose )
{
    mbedtls_retailmac_context ctx;

    int i;
    int ret;

    mbedtls_retailmac_init( &ctx );

    if( mbedtls_retailmac_setkey( &ctx, key_1, &(key_1[8]) ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  Retail Mac: setup failed\n" );

        return( 1 );
    }
    unsigned char tag[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    mbedtls_printf("\n\033[1mTest 1\033[0m\n");
    ret = mbedtls_cbcmac_alg3_generate(&ctx, test_data_1, test_data_1_len,tag,8);
    int res1 = memcmp(result_1, tag, 8);
    if(ret + res1== 0) mbedtls_printf("test 1 passed\n"); else mbedtls_printf("test 1 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_printf("\n\033[1mTest 2\033[0m\n");
    ret = mbedtls_cbcmac_alg3_generate(&ctx, test_data_2, test_data_2_len,tag,8);
    int res2 = memcmp(result_2, tag, 8);
    if(ret + res2 == 0) mbedtls_printf("test 2 passed\n"); else mbedtls_printf("test 2 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_printf("\n\033[1mTest 3\033[0m\n");
    ret = mbedtls_cbcmac_alg3_generate(&ctx, test_data_3, test_data_3_len,tag,8);
    int res3 = memcmp(result_3, tag, 8);
    if(ret +res3 == 0) mbedtls_printf("test 3 passed\n"); else mbedtls_printf("test 3 FAILED\n");
    print_hex("tag", tag, 4);
    mbedtls_retailmac_free(&ctx);


    return ret + res1 + res2 + res3;
}

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_DES_C */


#endif /* defined(MBEDTLS_RETAILMAC_C) */
