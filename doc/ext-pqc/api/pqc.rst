.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

..  _pqc-api:

~~~~~~~~~~~~~
API Reference
~~~~~~~~~~~~~

.. note::

    The API defined in this specification will be integrated into a future version of :cite:`PSA-CRYPT`.

.. header:: psa/crypto-pqc
    :copyright: Copyright 2018-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
    :license: Apache-2.0

    /* This file contains reference definitions for implementation of the
     * PSA Certified Crypto API v1.4 PQC Extension
     *
     * These definitions must be embedded in, or included by, psa/crypto.h
     */

This chapter is divided into sections for each of the PQC algorithms in the |API|:

.. toctree::

    hash
    mlkem
    mldsa
    slhdsa
    lms
    xmss

See :secref:`pqc-encodings` for the encoding of the key types and algorithm identifiers added by this extension.
