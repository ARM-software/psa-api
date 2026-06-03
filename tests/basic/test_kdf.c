//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements basic PSA Crypto API tests.

#include <stdint.h>
#include "psa/crypto.h"


static const uint8_t key_data[32] = {
     1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

int main(void)
{
    psa_status_t status;
    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t data[1024];

    status = psa_crypto_init();
    if (status) return status;
   
#if defined(PSA_WANT_ALG_HKDF)
    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status) return status;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SALT, (uint8_t*)"Salt", 4);
    if (status) return status;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_INFO, (uint8_t*)"Info", 4);
    if (status) return status;
    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET, key_data, 32);
    if (status) return status;
    status = psa_key_derivation_output_bytes(&kdf_op, data, 32);
    if (status) return status;
    status = psa_key_derivation_abort(&kdf_op);
    if (status) return status;
#endif

    return status;
}
