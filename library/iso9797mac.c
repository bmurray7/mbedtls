/*
 *                **** WARNING ****
 *   This file has NOT submitted to mbedTLS upstream
 */


/*
 *  Retail MAC Implementation from ANSI
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

#if defined(MBEDTLS_ISO9797MAC_C)

#include "../include/mbedtls/iso9797mac.h"
#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && (defined(MBEDTLS_AES_C) || defined(MBEDTLS_DES_C))
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* defined(MBEDTLS_SELF_TEST) && (defined(MBEDTLS_AES_C) || defined(MBEDTLS_DES_C))*/

void print_hex( char* name, unsigned char* s, int l) {
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
void mbedtls_retailmac_init( mbedtls_is9797_retail_mac_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_is9797_retail_mac_context ) );
}
/*
 * Initialize context
 */
void mbedtls_cbcmac_init(mbedtls_is9797_cbc_mac_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_is9797_cbc_mac_context ) );
}

/*
 * Free retail mac context
 */
void mbedtls_retailmac_free( mbedtls_is9797_retail_mac_context *ctx )
{
	mbedtls_cipher_free( &ctx->cipher1_ctx );
	mbedtls_cipher_free( &ctx->cipher2_ctx );
    mbedtls_zeroize( ctx, sizeof( mbedtls_is9797_retail_mac_context ) );
}
/*
 * Free cbc mac context
 */
void mbedtls_cbcmac_free( mbedtls_is9797_cbc_mac_context *ctx )
{
	mbedtls_cipher_free( &ctx->cipher1_ctx );
    mbedtls_zeroize( ctx, sizeof( mbedtls_is9797_cbc_mac_context ) );
}

/*
 * Set key and prepare context for use
 */
int mbedtls_retailmac_setkey( mbedtls_is9797_retail_mac_context *ctx,
		                 mbedtls_cipher_id_t cipher1_id,
                         const unsigned char *key1,
						 unsigned int key1_bits,
						 mbedtls_cipher_id_t cipher2_id,
						 const unsigned char *key2,
						 unsigned int key2_bits
						 )
{
	int ret;
    const mbedtls_cipher_info_t *cipher_info1;
    const mbedtls_cipher_info_t *cipher_info2;

	if(key1 == NULL || key2 == NULL)
		return MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
	if(key1_bits != key2_bits)
		return MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
	if(cipher1_id != cipher2_id)
		return MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;


    cipher_info1 = mbedtls_cipher_info_from_values( cipher1_id, key1_bits,
                                                   MBEDTLS_MODE_ECB );
    cipher_info2 = mbedtls_cipher_info_from_values( cipher2_id, key2_bits,
                                                   MBEDTLS_MODE_ECB );

    if(cipher_info1 == NULL || cipher_info2 == NULL)
		return MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;

    if( cipher_info1->block_size != cipher_info2->block_size )
        return  MBEDTLS_ERR_ISO9797MAC_BAD_INPUT ;
    ctx->cipher_block_size = cipher_info1->block_size;


    if( ( ret = mbedtls_cipher_setup( &ctx->cipher1_ctx, cipher_info1 ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_cipher_setup( &ctx->cipher2_ctx, cipher_info2 ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher1_ctx, key1, key1_bits,
                               MBEDTLS_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher2_ctx, key2, key2_bits,
                               MBEDTLS_DECRYPT ) ) != 0 )
    {
        return( ret );
    }
	return 0;
}

/*
 * Set key and prepare context for use
 */
int mbedtls_cbcmac_setkey( mbedtls_is9797_cbc_mac_context *ctx,
		                 mbedtls_cipher_id_t cipher_id,
                         const unsigned char *key,
						 unsigned int key_bits
						 )
{
	int ret;
    const mbedtls_cipher_info_t *cipher_info;

	if(key == NULL)
		return MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;

    cipher_info= mbedtls_cipher_info_from_values( cipher_id, key_bits,
                                                   MBEDTLS_MODE_ECB );

    if(cipher_info == NULL )
		return MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;

    ctx->cipher_block_size = cipher_info->block_size;


    if( ( ret = mbedtls_cipher_setup( &ctx->cipher1_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher1_ctx, key, key_bits,
                               MBEDTLS_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

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
	size_t j;

	if(padded_block_out_len < upadded_block_in_len)
		return 1;
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
 * XOR cipher block
 * Here, macro results in smaller compiled code than static inline function
 */

#define XOR_BLOCK( o, i1, i2 )                                                \
    for( i = 0; i < (ctx->cipher_block_size); i++ )                                               \
        ( o )[i] = ( i1 )[i] ^ ( i2 )[i];


/*
 * Update the Retail MAC state using an input block x
 * XOR_64( state, ( x ), state );
 */

#define PROCESS_BLOCK( x )                                                    \
do {                                                                        \
	XOR_BLOCK( state, ( x ), state  );\
    if( ( ret = mbedtls_cipher_update( &ctx->cipher1_ctx,                    \
    		state, ctx->cipher_block_size , state, &ctx->cipher_block_size) ) != 0 )   \
        goto exit;                                                      \
} while( 0 )



/*
 * Generate tag on complete message
 */
int mbedtls_cbcmac_generate( mbedtls_is9797_cbc_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len)
{

    unsigned char* state;
    unsigned char* M_last;
    int     ret, needs_padding;
    size_t i, j, n;
    ret = 0;

    if(ctx == NULL || tag == NULL || input==NULL)
    {
    	ret = MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
    	goto exit;
    }
    if( tag_len > ctx->cipher_block_size )
    {
    	ret = MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
        goto exit;
    }

    M_last =  mbedtls_calloc(ctx->cipher_block_size , sizeof(unsigned char));
    state = mbedtls_calloc(ctx->cipher_block_size ,  sizeof(unsigned char));

    if(M_last == NULL || state == NULL)
    {
    		    	ret = MBEDTLS_ERR_ISO9797MAC_ALLOC_FAILED;
    		    	goto exit;
    }

    if( tag_len > ctx->cipher_block_size )
    {
    	ret = MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
    	goto exit;
    }

    if( in_len == 0 )
        needs_padding = 1;
    else
        needs_padding = (in_len % ctx->cipher_block_size  != 0) ;

    n = in_len / ctx->cipher_block_size  ;

    for( j = 0; j < n; j++ )
    {
    	PROCESS_BLOCK( (input + ctx->cipher_block_size * j) );
    }

    if(needs_padding) {
    	cbcmac_pad_alg1( M_last, ctx->cipher_block_size , input + ctx->cipher_block_size  *  n , in_len % ctx->cipher_block_size  );
    	PROCESS_BLOCK( M_last );
    }
 /*
    if( ( ret = mbedtls_cipher_update( &ctx->cipher2_ctx,
    		state, ctx->cipher_block_size ,
			state, &ctx->cipher_block_size  ) ) != 0 )
    {
    	goto exit;
    }
    if( ( ret = mbedtls_cipher_update( &ctx->cipher1_ctx,
    		state, ctx->cipher_block_size ,
			state, &ctx->cipher_block_size  ) ) != 0 )
    {
    	goto exit;
    }
*/
    memcpy( tag, state, tag_len );


    exit:
		mbedtls_printf("Exiting\n");
		if(state != NULL)
			mbedtls_zeroize(state, sizeof( unsigned char) * (ctx->cipher_block_size) );
		if(M_last != NULL)
      		mbedtls_zeroize(M_last, sizeof( unsigned char) * (ctx->cipher_block_size) );
		free(M_last);
		free(state);
    	return ret;

}

int mbedtls_retail_mac_generate( mbedtls_is9797_retail_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len)
{

    unsigned char* state;
    unsigned char* M_last;
    int     ret, needs_padding;
    size_t i, j, n;
    ret = 0;

    if(ctx == NULL || tag == NULL || input==NULL)
    {
    	ret = MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
    	goto exit;
    }
    if( tag_len > ctx->cipher_block_size )
    {
    	ret = MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
        goto exit;
    }

    M_last =  mbedtls_calloc(ctx->cipher_block_size , sizeof(unsigned char));
    state = mbedtls_calloc(ctx->cipher_block_size ,  sizeof(unsigned char));

    if(M_last == NULL || state == NULL)
    {
    		    	ret = MBEDTLS_ERR_ISO9797MAC_ALLOC_FAILED;
    		    	goto exit;
    }

    if( tag_len > ctx->cipher_block_size )
    {
    	ret = MBEDTLS_ERR_ISO9797MAC_BAD_INPUT;
    	goto exit;
    }

    if( in_len == 0 )
        needs_padding = 1;
    else
        needs_padding = (in_len % ctx->cipher_block_size  != 0) ;

    n = in_len / ctx->cipher_block_size  ;

    for( j = 0; j < n; j++ )
    {
    	PROCESS_BLOCK( (input + ctx->cipher_block_size * j) );
    }

    if(needs_padding) {
    	cbcmac_pad_alg1( M_last, ctx->cipher_block_size , input + ctx->cipher_block_size  *  n , in_len % ctx->cipher_block_size  );
    	PROCESS_BLOCK( M_last );
    }

    if( ( ret = mbedtls_cipher_update( &ctx->cipher2_ctx,
    		state, ctx->cipher_block_size ,
			state, &ctx->cipher_block_size  ) ) != 0 )
    {
    	goto exit;
    }
    if( ( ret = mbedtls_cipher_update( &ctx->cipher1_ctx,
    		state, ctx->cipher_block_size ,
			state, &ctx->cipher_block_size  ) ) != 0 )
    {
    	goto exit;
    }

    memcpy( tag, state, tag_len );


    exit:
		mbedtls_printf("Exiting\n");
		if(state != NULL)
			mbedtls_zeroize(state, sizeof( unsigned char) * (ctx->cipher_block_size) );
		if(M_last != NULL)
      		mbedtls_zeroize(M_last, sizeof( unsigned char) * (ctx->cipher_block_size) );
		free(M_last);
		free(state);
    	return ret;

}

#undef XOR_BLOCK
#undef UPDATE_RETAILAMC


int mbedtls_retailmac_verify( mbedtls_is9797_retail_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len)
{
    int ret;
    unsigned char *check_tag;
    unsigned char i;
    int diff;

    check_tag = mbedtls_calloc( ctx->cipher1_ctx.cipher_info->block_size,
                                sizeof( unsigned char ) );
    if( check_tag == NULL )
    {
        ret = MBEDTLS_ERR_ISO9797MAC_ALLOC_FAILED;
        goto exit;
    }

    if( ( ret = mbedtls_retail_mac_generate( ctx, input, in_len,
                                       check_tag, tag_len ) ) != 0 )
    {
        goto exit;
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
    {
        ret = MBEDTLS_ERR_ISO9797MAC_VERIFY_FAILED;
        goto exit;
    }
    else
    {
        ret = 0;
        goto exit;
    }

    exit:
        mbedtls_free( check_tag );
        return( ret );
}

int mbedtls_cbcmac_verify( mbedtls_is9797_cbc_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len)
{
    int ret;
    unsigned char *check_tag;
    unsigned char i;
    int diff;

    check_tag = mbedtls_calloc( ctx->cipher1_ctx.cipher_info->block_size,
                                sizeof( unsigned char ) );
    if( check_tag == NULL )
    {
        ret = MBEDTLS_ERR_ISO9797MAC_ALLOC_FAILED;
        goto exit;
    }

    if( ( ret = mbedtls_cbcmac_generate( ctx, input, in_len,
                                       check_tag, tag_len ) ) != 0 )
    {
        goto exit;
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
    {
        ret = MBEDTLS_ERR_ISO9797MAC_VERIFY_FAILED;
        goto exit;
    }
    else
    {
        ret = 0;
        goto exit;
    }

    exit:
        mbedtls_free( check_tag );
        return( ret );
}



#if defined(MBEDTLS_SELF_TEST) && (defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C))

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

static const unsigned char result_1_retailmac[] = {
		  0xa1, 0xc7, 0x2e, 0x74, 0xea, 0x3f, 0xa9, 0xb6
};
unsigned int result_1_len_retailmac = 8;
// Same but Algorithm 1
static const unsigned char result_1_cbcmac[] = {
		0x70, 0xA3, 0x06, 0x40, 0xCC, 0x76, 0xDD, 0x8B
};
unsigned int result_1_len_cbcmac = 8;

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
static const unsigned char result_2_retailmac[] = {
	0x2E, 0x2B, 0x14, 0x28, 0xCC, 0x78, 0x25, 0x4F
};
static const unsigned int result_2_len_retailmac = 8;
// Same but Algorithm 1
static const unsigned char result_2_cbcmac[] = {
		0xE4, 0x5B, 0x3A, 0xD2, 0xB7, 0xCC, 0x08, 0x56
};
unsigned int result_2_len_cbcmac = 8;


// ANSI X9.19:1996
// Example 3
// Retail Mac only
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
static const unsigned char result_3_retailmac[] = {
		0xC2, 0x09, 0xCC, 0xB7, 0x8E, 0xE1, 0xB6, 0x06
};
static const unsigned int result_3_len_retailmac = 8;

static const unsigned char key4[] = {
  0x69, 0xec, 0xfa, 0x9b, 0x0a, 0x41, 0xfd, 0xf9, 0x90, 0xf4, 0xcc, 0x16,
  0x7b, 0x98, 0x78, 0x70
};


//taken from BOTON Source
static const unsigned int key4_len = 16;
static const unsigned char test_data_4[] = {
0x2F, 0x66, 0xCA, 0x7A, 0x49, 0xD1, 0xBF, 0xBF, 0xE3, 0x33, 0x98, 0x5F, 0x2C,
0x3B, 0x09, 0xD5, 0x47, 0x1D, 0x32, 0x1E, 0x47, 0x61, 0xEF, 0x4F, 0xF7, 0xD2,
0x85, 0x87, 0xCC, 0x62, 0xF4, 0xFB, 0xC8, 0xBF, 0x75, 0x12, 0x90, 0x35, 0xD1,
0x73, 0x68, 0x6A, 0xD3, 0x94, 0xA5, 0xDC
};
static const unsigned int test_data_4_len = 46;
static const unsigned char result_4_retailmac[]  = {
0xBF, 0x05, 0x57, 0xB7, 0x87, 0xC0, 0x1A, 0x58, 0x9B, 0xBD, 0x6E, 0xBB, 0x83,
0xF3, 0xA3, 0x30};
static const unsigned int result_4_len_retailmac = 16;

static const unsigned char key5[] = {
  0xA9, 0x0B, 0x14, 0x5D, 0xD7, 0x2A, 0x2F, 0xD1, 0x07, 0x96, 0xE3, 0x36, 0x8F,
  0xF9, 0xDC, 0x6D
};
static const unsigned int key5_len = 16;
static const unsigned char test_data_5[] = {
		0xE4, 0x7F, 0x16, 0x59, 0xA9, 0xF9, 0x93, 0x0C, 0x2E, 0x63, 0x69, 0x85, 0xCA,
		0x2E, 0xB0, 0x68, 0x6A, 0xB4, 0xCB, 0x16, 0xD1, 0xFA, 0xDD, 0x67, 0x12, 0x2F,
		0xF9, 0x16, 0xA6, 0xDE, 0x35, 0x8A, 0x5D, 0x4B, 0xE3, 0x06, 0x45, 0x76, 0x12,
		0x73, 0xD9, 0x7C, 0xF9, 0xA3, 0xAA
};
static const unsigned int test_data_5_len_retailmac = 45;
static const unsigned char result_5_retailmac[]  = {
		0x9F, 0xA9, 0x9D, 0x92, 0x57, 0x51, 0xC9, 0x61, 0x3D, 0x3A, 0x8D, 0x42, 0xE3,
		0xB6, 0x04, 0xB0};
static const unsigned int result_5_len_retailmac = 16;

int mbedtls_retailmac_self_test( int verbose )
{
	int ret, res1, res2, res3, res4, res5, res6, res7;

	/* Retail MAC Tests */
    mbedtls_is9797_retail_mac_context rmac_ctx1;
    mbedtls_is9797_retail_mac_context rmac_ctx2;
    mbedtls_is9797_retail_mac_context ramc_ctx5;


    mbedtls_retailmac_init( &rmac_ctx1 );
    mbedtls_retailmac_init( &rmac_ctx2 );
    mbedtls_retailmac_init( &ramc_ctx5 );

    if( mbedtls_retailmac_setkey( &rmac_ctx1, MBEDTLS_CIPHER_ID_DES, key_1, 64, MBEDTLS_CIPHER_ID_DES, &(key_1[8]) , 64) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  Retail Mac: setup failed\n" );

        return( 1 );
    }
    if( mbedtls_retailmac_setkey( &rmac_ctx2, MBEDTLS_CIPHER_ID_AES, key4, 128, MBEDTLS_CIPHER_ID_AES, key4 , 128) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  Retail Mac: setup failed\n" );

        return( 1 );
    }
    if( mbedtls_retailmac_setkey( &ramc_ctx5, MBEDTLS_CIPHER_ID_AES, key5, 128, MBEDTLS_CIPHER_ID_AES, key5 , 128) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  Retail Mac: setup failed\n" );

        return( 1 );
    }

    unsigned char tag[8] = {0x00 };
    unsigned char tag2[16] = {0x00};


    mbedtls_printf("\n\033[1mRetail MacTest 1\033[0m\n");
    ret = mbedtls_retail_mac_generate(&rmac_ctx1, test_data_1, test_data_1_len,tag,8);
    res1 = memcmp(result_1_retailmac, tag, 8);
    res1 += mbedtls_retailmac_verify(&rmac_ctx1, test_data_1, test_data_1_len,result_1_retailmac,8);
    if(ret + res1== 0) mbedtls_printf("test 1 passed\n"); else mbedtls_printf("test 1 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_printf("\n\033[1mRetail MacTest 2\033[0m\n");
    ret = mbedtls_retail_mac_generate(&rmac_ctx1, test_data_2, test_data_2_len,tag,8);
    res2 = memcmp(result_2_retailmac, tag, 8);
    res2 += mbedtls_retailmac_verify(&rmac_ctx1, test_data_2, test_data_2_len,result_2_retailmac,8);
    if(ret + res2 == 0) mbedtls_printf("test 2 passed\n"); else mbedtls_printf("test 2 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_printf("\n\033[1mRetail MacTest 3\033[0m\n");
    ret = mbedtls_retail_mac_generate(&rmac_ctx1, test_data_3, test_data_3_len,tag,8);
    res3 = memcmp(result_3_retailmac, tag, 8);
    res3 += mbedtls_retailmac_verify(&rmac_ctx1, test_data_3, test_data_3_len,result_3_retailmac,8);
    if(ret +res3 == 0) mbedtls_printf("test 3 passed\n"); else mbedtls_printf("test 3 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_printf("\n\033[1mRetail MacTest 4\033[0m\n");
    ret = mbedtls_retail_mac_generate(&rmac_ctx2, test_data_4, test_data_4_len,tag2,16);
    res4 = memcmp(result_4_retailmac, tag2, 16);
    res4 += mbedtls_retailmac_verify(&rmac_ctx2, test_data_4, test_data_4_len,result_4_retailmac,16);
    if(ret +res4 == 0) mbedtls_printf("test 4 passed\n"); else mbedtls_printf("test 4 FAILED\n");
    print_hex("tag", tag2, 8);

    mbedtls_printf("\n\033[1mRetail MacTest 5\033[0m\n");
    ret = mbedtls_retail_mac_generate(&ramc_ctx5, test_data_5, test_data_5_len_retailmac,tag2,16);
    res5 = memcmp(result_5_retailmac, tag2, 16);
    res5 += mbedtls_retailmac_verify(&ramc_ctx5, test_data_5, test_data_4_len,result_5_retailmac,16);
    if(ret + res5 == 0) mbedtls_printf("test 5 passed\n"); else mbedtls_printf("test 5 FAILED\n");
    print_hex("tag", tag2, 8);

    mbedtls_retailmac_free(&rmac_ctx1);
    mbedtls_retailmac_free(&rmac_ctx2);
    mbedtls_retailmac_free(&ramc_ctx5);

    /* CBC MAC Tests */

    memset(tag,0,8);
    mbedtls_is9797_cbc_mac_context cbcmac_ctx1;
    mbedtls_cbcmac_init(&cbcmac_ctx1);
    if( mbedtls_cbcmac_setkey( &cbcmac_ctx1, MBEDTLS_CIPHER_ID_DES, key_1, 64) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  Retail Mac: setup failed\n" );

        return( 1 );
    }

    mbedtls_printf("\n\033[1mCBC MacTest 1\033[0m\n");
    ret = mbedtls_cbcmac_generate(&cbcmac_ctx1, test_data_1, test_data_1_len,tag,8);
    res6 = memcmp(result_1_cbcmac, tag, 8);
    res6 += mbedtls_cbcmac_verify(&cbcmac_ctx1, test_data_1, test_data_1_len,tag,8);
    if(ret + res6 == 0) mbedtls_printf("test 1 passed\n"); else mbedtls_printf("test 1 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_printf("\n\033[1mCBC MacTest 2\033[0m\n");
    ret = mbedtls_cbcmac_generate(&cbcmac_ctx1, test_data_2, test_data_2_len,tag,8);
    res7 = memcmp(result_2_cbcmac, tag, 8);
    if(ret + res7 == 0) mbedtls_printf("test 2 passed\n"); else mbedtls_printf("test 2 FAILED\n");
    print_hex("tag", tag, 4);

    mbedtls_retailmac_free(&cbcmac_ctx1);
    return ret + res1 + res2 + res3 +res4 + res5 +res6 + res7;
}

#endif /*defined(MBEDTLS_SELF_TEST) && (defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C))  */


#endif /* defined(MBEDTLS_RETAILMAC_C) */
