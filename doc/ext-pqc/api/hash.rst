.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 1

.. _hashes:

Additional Hash algorithms
==========================

SHAKE-based hash algorithms
---------------------------

.. macro:: PSA_ALG_SHAKE128_256
    :definition: ((psa_algorithm_t)0x02000016)

    .. summary::
        The first 256 bits (32 bytes) of the SHAKE128 output.

        .. versionadded:: 1.3

    This can be used as pre-hashing for SLH-DSA (see `PSA_ALG_HASH_SLH_DSA()`).

    SHAKE128 is defined in :cite:`FIPS202`.

    .. note::
        For other scenarios where a hash function based on SHA3 or SHAKE is required, SHA3-256 is recommended. SHA3-256 has the same output size, and a theoretically higher security strength.

.. comment
    Update the description of PSA_ALG_SHAKE256_512 to state:

    This is the pre-hashing for Ed448ph (see `PSA_ALG_ED448PH`), and can be used as pre-hashing for SLH-DSA (see `PSA_ALG_HASH_SLH_DSA()`).
