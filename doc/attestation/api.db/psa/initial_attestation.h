// SPDX-FileCopyrightText: Copyright 2018-2020, 2022-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

#define PSA_INITIAL_ATTEST_API_VERSION_MAJOR 2
#define PSA_INITIAL_ATTEST_API_VERSION_MINOR 0
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32 (32u)
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48 (48u)
#define PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 (64u)
#define PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE /* implementation-specific value */
psa_status_t psa_initial_attest_get_token(const uint8_t *auth_challenge,
                                          size_t challenge_size,
                                          uint8_t *token_buf,
                                          size_t token_buf_size,
                                          size_t *token_size);
psa_status_t psa_initial_attest_get_token_size(size_t challenge_size,
                                               size_t *token_size);
