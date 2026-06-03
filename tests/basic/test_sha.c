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


int main(void)
{
    psa_status_t status;
    size_t length;

    status = psa_crypto_init();
    if (status) return status;

#if defined(PSA_WANT_ALG_SHA_256)
    psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
    uint8_t hash[32];
    status = psa_hash_setup(&hash_operation, PSA_ALG_SHA_256);
    const size_t chunk_size = 32;
    size_t i = 0; 
    while(i < sizeof image) {
        size_t remaining = sizeof image - i;
        size_t length = (remaining < chunk_size ? remaining : chunk_size);
        status = psa_hash_update(&hash_operation, &image[i], length);
        i+= chunk_size;
    }
    status = psa_hash_finish(&hash_operation, hash, sizeof hash, &length);
#endif

    return status;
}
