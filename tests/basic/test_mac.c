//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements basic PSA Crypto API tests.

#include <stdint.h>
#include "psa/crypto.h"

// example image
static const uint8_t image[1001] = 
    "the brown fox jumps over the dog" 
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown fox jumps over the dog"
    "the brown";

static const uint8_t key_data[32] = {
     1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};


int main(void)
{
    psa_status_t status;
    uint8_t data[1024];
    size_t length;
    psa_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    status = psa_crypto_init();
    if (status) return status;

#if defined(PSA_WANT_ALG_HMAC) && defined(PSA_WANT_ALG_SHA_256)
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    status = psa_import_key(&attr, key_data, 32, &key);
    if (status) return status;
    status = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256), image, sizeof image, data, sizeof data, &length);
    if (status) return status;
    psa_destroy_key(key);
#endif

    return status;
}
