.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _specification-defined-value:

Example macro implementations
-----------------------------

This section provides example implementations of the function-like macros that have specification-defined values.

.. note::
    In a future version of this specification, these example implementations will be replaced with a pseudo-code representation of the macro's computation in the macro description.

The examples here provide correct results for the valid inputs defined by each API, for an implementation that supports all of the defined algorithms and key types. An implementation can provide alternative definitions of these macros:

Algorithm macros
~~~~~~~~~~~~~~~~

Updated macros
^^^^^^^^^^^^^^

.. code-block:: xref

    #define PSA_ALG_IS_HASH_AND_SIGN(alg) \
        (PSA_ALG_IS_RSA_PSS(alg) || PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) || \
         PSA_ALG_IS_ECDSA(alg) || PSA_ALG_IS_HASH_EDDSA(alg) || \
         PSA_ALG_IS_HASH_ML_DSA(alg) || PSA_ALG_IS_HASH_SLH_DSA(alg))

    #define PSA_ALG_IS_SIGN_HASH(alg) \
        (PSA_ALG_IS_HASH_AND_SIGN(alg) ||
        (alg) == PSA_ALG_RSA_PKCS1V15_SIGN_RAW ||
        (alg) == PSA_ALG_ECDSA_ANY
        )

New macros
^^^^^^^^^^

.. code-block:: xref

    #define PSA_ALG_DETERMINISTIC_HASH_ML_DSA(hash_alg) \
        ((psa_algorithm_t) (0x06004700 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_DETERMINISTIC_HASH_SLH_DSA(hash_alg) \
        ((psa_algorithm_t) (0x06004300 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_HASH_ML_DSA(hash_alg) \
        ((psa_algorithm_t) (0x06004600 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_HASH_SLH_DSA(hash_alg) \
        ((psa_algorithm_t) (0x06004200 | ((hash_alg) & 0x000000ff)))

    #define PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg) \
        (((alg) & ~0x000000ff) == 0x06004700)

    #define PSA_ALG_IS_DETERMINISTIC_HASH_SLH_DSA(alg) \
        (((alg) & ~0x000000ff) == 0x06004300)

    #define PSA_ALG_IS_HASH_ML_DSA(alg) \
        (((alg) & ~0x000001ff) == 0x06004600)

    #define PSA_ALG_IS_HASH_SLH_DSA(alg) \
        (((alg) & ~0x000001ff) == 0x06004200)

    #define PSA_ALG_IS_HEDGED_HASH_ML_DSA(alg) \
        (((alg) & ~0x000000ff) == 0x06004600)

    #define PSA_ALG_IS_HEDGED_HASH_SLH_DSA(alg) \
        (((alg) & ~0x000000ff) == 0x06004200)

    #define PSA_ALG_IS_ML_DSA(alg) \
        (((alg) & ~0x00000100) == 0x06004400)

    #define PSA_ALG_IS_SLH_DSA(alg) \
        (((alg) & ~0x00000100) == 0x06004000)

Key type macros
~~~~~~~~~~~~~~~

.. code-block:: xref

    #define PSA_KEY_TYPE_IS_ML_DSA(type) \
        (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) == 0x4002)

    #define PSA_KEY_TYPE_IS_ML_KEM(type) \
        (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) == 0x4004)

    #define PSA_KEY_TYPE_IS_SLH_DSA(type) \
        ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) & 0xff80) == 0x4180)

    #define PSA_KEY_TYPE_IS_SLH_DSA_KEY_PAIR(type) \
        (((type) & 0xff80) == 0x7180)

    #define PSA_KEY_TYPE_IS_SLH_DSA_PUBLIC_KEY(type) \
        (((type) & 0xff80) == 0x4180)

    #define PSA_KEY_TYPE_SLH_DSA_GET_FAMILY(type) \
        ((psa_slh_dsa_family_t) ((type) & 0x007f))

    #define PSA_KEY_TYPE_SLH_DSA_KEY_PAIR(set) \
        ((psa_key_type_t) (0x7180 | ((set) & 0x007f)))

    #define PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY(set) \
        ((psa_key_type_t) (0x4180 | ((set) & 0x007f)))
