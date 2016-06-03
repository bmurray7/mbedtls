/*
 *                **** WARNING ****
 *   This file has NOT submitted to mbedTLS upstream
 */


/**
 * \file iso9797mac.h
 *
 * \brief The CBC-MAC Mode and Retail Mac Modes for Authentication
 *
 *  Copyright (C) 2016, Clover
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
 *  This file is NOT part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_ISO9797MAC_H
#define MBEDTLS_ISO9797MAC_H

#include "cipher.h"
#include "des.h"


#ifdef __cplusplus
extern "C" {
#endif


#define MBEDTLS_ERR_ISO9797MAC_BAD_INPUT      -0x0015 /**< Bad input parameters to function. */
#define MBEDTLS_ERR_ISO9797MAC_VERIFY_FAILED  -0x0017 /**< Verification failed. */
#define MBEDTLS_ERR_ISO9797MAC_ALLOC_FAILED  -0x0019 /**< Verification failed. */


/**
 *  \brief  ISO 9791 Algorithm 1  MAC context structure
 *  AKA Retail MAC
 */
typedef struct {

	mbedtls_cipher_context_t cipher1_ctx;
	size_t cipher_block_size;
}
mbedtls_is9797_cbc_mac_context;



/**
 *  \brief  ISO 9791 Algorithm 3  MAC context structure
 *  AKA Retail MAC
 */
typedef struct {

	mbedtls_cipher_context_t cipher1_ctx;
	mbedtls_cipher_context_t cipher2_ctx;
	size_t cipher_block_size;
}
mbedtls_is9797_retail_mac_context;


/**
 * \brief           Initialize  CBC-MAC context (just makes references valid)
 *
 * \param ctx       CBC Mac context to initialize
 */
void mbedtls_retailmac_init(mbedtls_is9797_retail_mac_context *ctx );


/**
 * \brief           Initialize CBC-MAC context (just makes references valid)
 *
 * \param ctx       CNC Mac context to initialize
 */
void mbedtls_cbcmac_init(mbedtls_is9797_cbc_mac_context *ctx );

/**
 * \brief           Initialize CBC-MAC context
 *
 * \param ctx       CBC-MAC context to initialize
 */
void mbedtls_retailmac_init(mbedtls_is9797_retail_mac_context *ctx );


/**
 * \brief           Free a Retail Mac context and underlying cipher sub-context
 *
 * \param ctx       CBC-MAC context to free
 */
void mbedtls_retailmac_free( mbedtls_is9797_retail_mac_context *ctx );

/**
 * \brief           Free a CBC Mac context and underlying cipher sub-context
 *
 * \param ctx       CBC-MAC context to free
 */
void mbedtls_cbcmac_free( mbedtls_is9797_cbc_mac_context *ctx );


int mbedtls_retailmac_setkey( mbedtls_is9797_retail_mac_context *ctx,
		                 mbedtls_cipher_id_t cipher1_id,
                         const unsigned char *key1,
						 unsigned int key1_bits,
						 mbedtls_cipher_id_t cipher2_id,
						 const unsigned char *key2,
						 unsigned int key2_bits
						 );

int mbedtls_cbcmac_setkey( mbedtls_is9797_cbc_mac_context *ctx,
		                 mbedtls_cipher_id_t cipher_id,
                         const unsigned char *key,
						 unsigned int key_bits
						 );


int mbedtls_retailmac_generate( mbedtls_is9797_retail_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len);

int mbedtls_cbc_mac_generate( mbedtls_is9797_cbc_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len);

int mbedtls_retailmac_verify( mbedtls_is9797_retail_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len);


int mbedtls_cbcmac_verify( mbedtls_is9797_cbc_mac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_DES_C)
int mbedtls_retailmac_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_DES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_RETAILMAC_H */

