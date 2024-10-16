// SPDX-FileCopyrightText: Copyright 2018-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

typedef uint8_t psa_slh_dsa_family_t;
#define PSA_ALG_DETERMINISTIC_HASH_SLH_DSA(hash_alg) \
    /* specification-defined value */
#define PSA_ALG_DETERMINISTIC_SLH_DSA ((psa_algorithm_t) 0x06004100)
#define PSA_ALG_HASH_SLH_DSA(hash_alg) /* specification-defined value */
#define PSA_ALG_IS_DETERMINISTIC_HASH_SLH_DSA(alg) \
    /* specification-defined value */
#define PSA_ALG_IS_HASH_SLH_DSA(alg) /* specification-defined value */
#define PSA_ALG_IS_HEDGED_HASH_SLH_DSA(alg) /* specification-defined value */
#define PSA_ALG_IS_SLH_DSA(alg) /* specification-defined value */
#define PSA_ALG_SHAKE128_256 ((psa_algorithm_t)0x02000016)
#define PSA_ALG_SLH_DSA ((psa_algorithm_t) 0x06004000)
#define PSA_KEY_TYPE_IS_SLH_DSA(type) /* specification-defined value */
#define PSA_KEY_TYPE_IS_SLH_DSA_KEY_PAIR(type) \
    /* specification-defined value */
#define PSA_KEY_TYPE_IS_SLH_DSA_PUBLIC_KEY(type) \
    /* specification-defined value */
#define PSA_KEY_TYPE_SLH_DSA_GET_FAMILY(type) /* specification-defined value */
#define PSA_KEY_TYPE_SLH_DSA_KEY_PAIR(set) /* specification-defined value */
#define PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY(set) /* specification-defined value */
#define PSA_SLH_DSA_FAMILY_SHA2_F ((psa_slh_dsa_family_t) 0x04)
#define PSA_SLH_DSA_FAMILY_SHA2_S ((psa_slh_dsa_family_t) 0x02)
#define PSA_SLH_DSA_FAMILY_SHAKE_F ((psa_slh_dsa_family_t) 0x0d)
#define PSA_SLH_DSA_FAMILY_SHAKE_S ((psa_slh_dsa_family_t) 0x0b)
