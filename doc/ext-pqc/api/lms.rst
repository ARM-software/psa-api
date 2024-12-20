.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 5

.. _lms:

Leighton-Micali Signatures
==========================

The |API| supports Leighton-Micali Signatures (LMS) within the Hierarchical Signature Scheme (HSS). Together this is referenced as HSS/LMS, and defined in :rfc-title:`8554`.

For the |API| to support signature verification, it is only necessary to define a public key for this scheme, and the default public key format for import and export.

.. rationale::

    At present, it is not expected that the |API| will be used to generate HSS/LMS private keys, or to carry out signing operations.
    However, there is value in supporting verification of HSS/LMS signatures.
    Therefore, the |API| does not support HSS/LMS key pairs, or HSS/LMS signing.

HSS allows a single level, in which case the HSS/LMS public key and signature formats are essentially the LMS public key and signature formats, prepended by a fixed field.
As :rfc:`8554#6` requires that all implementations support HSS, the |API| only define key types and algorithm identifiers for the combined HSS/LMS scheme.
This matches the approach taken in :cite-title:`LAMPS-SHBS`, which defines the X.509 identifiers for stateful hash-based signature schemes.

.. note::
    A full set of NIST-approved parameter sets for HSS/LMS is defined in :cite-title:`SP800-208` §4, with the additional IANA identifiers defined in :cite-title:`CFRG-LMS`.

.. _lms-keys:

Leighton-Micali Signature keys
------------------------------

.. macro:: PSA_KEY_TYPE_HSS_LMS_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4007)

    .. summary::
        Hierarchical Signature Scheme with Leighton-Micali Signatures (HSS/LMS) public key.

        .. versionadded:: 1.3

    The parameterization of an HSS/LMS key is fully encoded in the key data.

    The key attribute size of an HSS/LMS public key is :issue:`not used?`

    .. todo:: Decide if we want to use the ``key_bits`` attribute for HSS/LMS keys at all.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_HSS_LMS`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for HSS/LMS public keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-SHBS`.

            The current proposed format is based on the expected outcome of that process.

        The data format for import or export of the public key is the encoded ``hss_public_key`` structure, defined in :rfc:`8554#3`.


.. _lms-algorithms:

Leighton-Micali Signature algorithms
------------------------------------

.. macro:: PSA_ALG_HSS_LMS
    :definition: ((psa_algorithm_t) 0x06004900)

    .. summary::
        Hierarchical Signature Scheme with Leighton-Micali Signatures (HSS/LMS) signature algorithm.

        .. versionadded:: 1.3

    This message-signature algorithm can only be used with the :code:`psa_verify_message()` function.

    This is the HSS/LMS stateful hash-based signature algorithm, defined by :rfc-title:`8554`.
    HSS/LMS requires an HSS/LMS key.
    The key and the signature must both encode the same HSS/LMS parameter set, which is used for the verification procedure.

    .. note::
        HSS/LMS signature calculation is not supported.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_HSS_LMS_PUBLIC_KEY` (signature verification only)
