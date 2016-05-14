/**
 * \file cbcmac.h
 *
 * \brief The CBC-MAC Mode for Authentication
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
#ifndef MBEDTLS_RETAILMAC_H
#define MBEDTLS_RETAILMAC_H

#include "cipher.h"
#include "des.h"


#ifdef __cplusplus
extern "C" {
#endif


#define MBEDTLS_ERR_RETAILMAC_BAD_INPUT      -0x0015 /**< Bad input parameters to function. */
#define MBEDTLS_ERR_RETAILMAC_VERIFY_FAILED  -0x0017 /**< Verification failed. */


/**
 * \brief          Retail MAC context structure
 */
typedef struct {

	mbedtls_des_context key_1_ctx;
	mbedtls_des_context key_2_ctx;

}
mbedtls_retailmac_context;

/**
 * \brief           Initialize CBC-MAC context (just makes references valid)
 *                  Makes the context ready for mbedtls_ccm_setkey() or
 *                  mbedtls_ccm_free().
 *
 * \param ctx       CBC-MAC context to initialize
 */
void mbedtls_retailmac_init(mbedtls_retailmac_context *ctx );

/**
 * \brief           Free a CBC-MAC context and underlying cipher sub-context
 *
 * \param ctx       CBC-MAC context to free
 */
void mbedtls_retailmac_free( mbedtls_retailmac_context *ctx );

void mbedtls_retailmac_init( mbedtls_retailmac_context *ctx );

int mbedtls_retailmac_setkey( mbedtls_retailmac_context *ctx,
                         const unsigned char key_1[8],
						 const unsigned char key_2[8]);

int mbedtls_cbcmac_alg3_generate( mbedtls_retailmac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char* tag,  size_t tag_len);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_DES_C)
int mbedtls_retailmac_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_DES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_RETAILMAC_H */

