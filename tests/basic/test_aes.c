//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements basic PSA Crypto API tests.

#include <stdint.h>
#include <stdio.h>

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

static const uint8_t key_data[32] = { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16 };

int main(void)
{
    psa_status_t status;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
    psa_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t data[1024];
    size_t length;

    status = psa_crypto_init();
    if (status) return status;
    printf("0");
   
#if defined(PSA_WANT_ALG_CTR)
    // encrypt
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_algorithm(&attr, PSA_ALG_CTR);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    status = psa_import_key(&attr, key_data, 16, &key);
    if (status) return status;
    printf("1");
    status = psa_cipher_encrypt_setup(&cipher_op, key, PSA_ALG_CTR);
    if (status) return status;
    printf("2");
    status = psa_cipher_set_iv(&cipher_op, key_data, 16);
    if (status) return status;
    printf("3");
    status = psa_cipher_update(&cipher_op, image, sizeof image, data, sizeof data, &length);
    if (status) return status;
    printf("4");
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) return status;
    printf("5");
    psa_destroy_key(key);

    // decrypt
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    status = psa_import_key(&attr, key_data, 16, &key);
    if (status) return status;
    status = psa_cipher_decrypt_setup(&cipher_op, key, PSA_ALG_CTR);
    if (status) return status;
    status = psa_cipher_set_iv(&cipher_op, key_data, 16);
    if (status) return status;
    status = psa_cipher_update(&cipher_op, data, sizeof data, data, sizeof data, &length);
    if (status) return status;
    status = psa_cipher_finish(&cipher_op, NULL, 0, &length);
    if (status) return status;
    psa_destroy_key(key);
#endif

    return status;
}
