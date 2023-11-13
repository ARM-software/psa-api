.. SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _specification-defined-value:

Example macro implementations
-----------------------------

This section provides example implementations of the function-like macros that have specification-defined values.

.. note::
    In a future version of this specification, these example implementations will be replaced with a pseudo-code representation of the macro's computation in the macro description.

The examples here provide correct results for the valid inputs defined by each API, for an implementation that supports all of the defined algorithms and key types. An implementation can provide alternative definitions of these macros:

.. code-block:: xref

    #define PSA_ALG_IS_JPAKE(alg) \
        (((alg) & ~0x000000ff) == 0x0a000100)

    #define PSA_ALG_IS_PAKE(alg) \
        (((alg) & 0x7f000000) == 0x0a000000)

    #define PSA_ALG_JPAKE(hash_alg) \
        ((psa_algorithm_t) (0x0a000100 | ((hash_alg) & 0x000000ff)))

    #define PSA_PAKE_PRIMITIVE(pake_type, pake_family, pake_bits) \
        ((pake_bits & 0xFFFF) != pake_bits) ? 0 :                 \
        ((psa_pake_primitive_t) (((pake_type) << 24 |             \
                (pake_family) << 16) | (pake_bits)))
