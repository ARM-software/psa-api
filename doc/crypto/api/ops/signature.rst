.. SPDX-FileCopyrightText: Copyright 2018-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 26

.. _sign:

Asymmetric signature
====================

An asymmetric signature algorithm provides two functions:

*   **Sign**: Calculate a message signature using a private, or secret, key.
*   **Verify**: Check that a signature matches a message using a public key.

Successful verification indicates that the message signature was calculated using the private key that is associated with the public key.

In the |API|, an asymmetric-sign function requires an asymmetric key pair; and an asymmetric-verify function requires an asymmetric public key or key pair.

.. rubric:: Signature schemes

The |API| supports the following signature schemes:

*   :secref:`rsa-sign-algorithms`
*   :secref:`ecdsa-sign-algorithms`
*   :secref:`eddsa-sign-algorithms`

.. rubric:: Types of signature algorithm

There are three categories of asymmetric signature algorithm in the |API|:

*   Hash-and-sign algorithms, that have two distinct phases:

    -   Calculate a hash of the message
    -   Calculate a signature over the hash

    For these algorithms, the asymmetric signature API allows applications to either calculate the full message signature, or calculate the signature of a pre-computed hash. For example, this enables the application to use a multi-part hash operation to calculate the hash of a large message, prior to calculating or verifying a signature on the calculated hash.

    The following algorithms are in this category:

    | `PSA_ALG_RSA_PKCS1V15_SIGN`
    | `PSA_ALG_RSA_PSS`
    | `PSA_ALG_RSA_PSS_ANY_SALT`
    | `PSA_ALG_ECDSA`
    | `PSA_ALG_DETERMINISTIC_ECDSA`
    | `PSA_ALG_ED25519PH`
    | `PSA_ALG_ED448PH`

*   Message signature algorithms that do not separate the message processing from the signature calculations. This approach can provide better security against certain types of attack.

    For these algorithms, it is not possible to inject a pre-computed hash into the middle of the algorithm. An application can choose to calculate a message hash, and sign that instead of the message --- but this is not functionally equivalent to signing the message, and eliminates the security benefits of signing the message directly.

    Some of these algorithms still permit the signature of a large message to be calculated, or verified, by providing the message data in fragments. This is possible when the algorithm only processes the message data once. See the individual algorithm descriptions for details.

    The following algorithms are in this category:

    | `PSA_ALG_PURE_EDDSA`

*   Specialized signature algorithms, that use part of a standard signature algorithm within a specific protocol. It is recommended that these algorithms are only used for that purpose, with inputs as specified by the higher-level protocol. See the individual algorithm descriptions for details on their usage.

    The following algorithms are in this category:

    | `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`
    | `PSA_ALG_ECDSA_ANY`

.. rubric:: Signature functions

The |API| provides several functions for calculating and verifying signatures:

*   The single-part signature and verification functions, `psa_sign_message()` and `psa_verify_message()`, take a message as one of their inputs, and perform the sign or verify algorithm.

    These functions can be used on any hash-and-sign, or message signature, algorithms. See also `PSA_ALG_IS_SIGN_MESSAGE()`.

*   The single-part functions, `psa_sign_hash()` and `psa_verify_hash()`, typically take a message hash as one of their inputs, and perform the sign or verify algorithm.

    These functions can be used on any hash-and-sign signature algorithm. It is recommended that the input to these functions is a hash, computed using the corresponding hash algorithm. To determine which hash algorithm to use, the macro `PSA_ALG_GET_HASH()` can be called on the signature algorithm identifier.

    These functions can also be used on the specialized signature algorithms, with a hash or encoded-hash as input. See also `PSA_ALG_IS_SIGN_HASH()`.

*   The pair of `interruptible operations <interruptible-operations>`, `psa_sign_iop_t` and `psa_verify_iop_t`, enable the signature of a message, or pre-computed hash, to be calculated and verified in an interruptible manner. See :secref:`interruptible-sign` and :secref:`interruptible-verify` for details on how to use these operations.

.. _rsa-sign-algorithms:

RSA signature algorithms
------------------------

.. macro:: PSA_ALG_RSA_PKCS1V15_SIGN
    :definition: /* specification-defined value */

    .. summary::
        The RSA PKCS#1 v1.5 message signature scheme, with hashing.

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding RSA PKCS#1 v1.5 signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    This signature scheme is defined by :RFC-title:`8017#8.2` under the name RSASSA-PKCS1-v1_5.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is used as :math:`H` from step 2 onwards in the message encoding algorithm ``EMSA-PKCS1-V1_5-ENCODE()`` in :RFC:`8017#9.2`. :math:`H` is the message digest, computed using the ``hash_alg`` hash algorithm.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_RSA_KEY_PAIR`
        | `PSA_KEY_TYPE_RSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_RSA_PKCS1V15_SIGN_RAW
    :definition: ((psa_algorithm_t) 0x06000200)

    .. summary::
        The raw RSA PKCS#1 v1.5 signature algorithm, without hashing.

    This specialized signature algorithm can be only used with the `psa_sign_hash()` and `psa_verify_hash()` functions, or with the interruptible asymmetric signature and verification operations.

    This signature scheme is defined by :RFC-title:`8017#8.2` under the name RSASSA-PKCS1-v1_5.

    The ``hash`` parameter to `psa_sign_hash()` or `psa_verify_hash()` is used as :math:`T` from step 3 onwards in the message encoding algorithm ``EMSA-PKCS1-V1_5-ENCODE()`` in :RFC:`8017#9.2`. :math:`T` is normally the DER encoding of the *DigestInfo* structure produced by step 2 in the message encoding algorithm, but it can be any byte string within the available length.

    The wildcard key policy :code:`PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH)` also permits a key to be used with the `PSA_ALG_RSA_PKCS1V15_SIGN_RAW` signature algorithm.

    .. rationale::

        RSA keys that are used for TLS session establishment can be used in different versions of the TLS protocol.

        *   Versions 1.0 and 1.1 of the TLS protocol uses the `PSA_ALG_RSA_PKCS1V15_SIGN_RAW` algorithm, which signs an encoded SHA-1 + MD5 hash.
        *   Version 1.2 of the TLS protocol uses the :code:`PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256))` algorithm, which signs the [unencoded] SHA-256 hash.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_RSA_KEY_PAIR`
        | `PSA_KEY_TYPE_RSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_RSA_PSS
    :definition: /* specification-defined value */

    .. summary::
        The RSA PSS message signature scheme, with hashing.

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding RSA PSS signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    This algorithm is randomized: each invocation returns a different, equally valid signature.

    This is the signature scheme defined by :RFC:`8017#8.1` under the name RSASSA-PSS, with the following options:

    *   The mask generation function is *MGF1* defined by :RFC:`8017#B`.
    *   When creating a signature, the salt length is equal to the length of the hash, or the largest possible salt length for the algorithm and key size if that is smaller than the hash length.
    *   When verifying a signature, the salt length must be equal to the length of the hash, or the largest possible salt length for the algorithm and key size if that is smaller than the hash length.
    *   The specified hash algorithm, ``hash_alg``,  is used to hash the input message, to create the salted hash, and for the mask generation.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is the message digest, computed using the ``hash_alg`` hash algorithm.

    .. note::

        The `PSA_ALG_RSA_PSS_ANY_SALT()` algorithm is equivalent to `PSA_ALG_RSA_PSS()` when creating a signature, but permits any salt length when verifying a signature.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_RSA_KEY_PAIR`
        | `PSA_KEY_TYPE_RSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_RSA_PSS_ANY_SALT
    :definition: /* specification-defined value */

    .. summary::
        The RSA PSS message signature scheme, with hashing.
        This variant permits any salt length for signature verification.

        .. versionadded:: 1.1

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding RSA PSS signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    This algorithm is randomized: each invocation returns a different, equally valid signature.

    This is the signature scheme defined by :RFC:`8017#8.1` under the name RSASSA-PSS, with the following options:

    *   The mask generation function is *MGF1* defined by :RFC:`8017#B`.
    *   When creating a signature, the salt length is equal to the length of the hash, or the largest possible salt length for the algorithm and key size if that is smaller than the hash length.
    *   When verifying a signature, any salt length permitted by the RSASSA-PSS signature algorithm is accepted.
    *   The specified hash algorithm, ``hash_alg``,  is used to hash the input message, to create the salted hash, and for the mask generation.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is the message digest, computed using the ``hash_alg`` hash algorithm.

    .. note::

        The `PSA_ALG_RSA_PSS()` algorithm is equivalent to `PSA_ALG_RSA_PSS_ANY_SALT()` when creating a signature, but is strict about the permitted salt length when verifying a signature.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_RSA_KEY_PAIR`
        | `PSA_KEY_TYPE_RSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_IS_RSA_PKCS1V15_SIGN
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an RSA PKCS#1 v1.5 signature algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an RSA PKCS#1 v1.5 signature algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_RSA_PSS
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an RSA PSS signature algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an RSA PSS signature algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    This macro returns ``1`` for algorithms constructed using either `PSA_ALG_RSA_PSS()` or `PSA_ALG_RSA_PSS_ANY_SALT()`.

.. macro:: PSA_ALG_IS_RSA_PSS_ANY_SALT
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an RSA PSS signature algorithm that permits any salt length.

        .. versionadded:: 1.1

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an RSA PSS signature algorithm that permits any salt length, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    An RSA PSS signature algorithm that permits any salt length is constructed using `PSA_ALG_RSA_PSS_ANY_SALT()`.

    See also `PSA_ALG_IS_RSA_PSS()` and `PSA_ALG_IS_RSA_PSS_STANDARD_SALT()`.

.. macro:: PSA_ALG_IS_RSA_PSS_STANDARD_SALT
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an RSA PSS signature algorithm that requires the standard salt length.

        .. versionadded:: 1.1

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an RSA PSS signature algorithm that requires the standard salt length, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    An RSA PSS signature algorithm that requires the standard salt length is constructed using `PSA_ALG_RSA_PSS()`.

    See also `PSA_ALG_IS_RSA_PSS()` and `PSA_ALG_IS_RSA_PSS_ANY_SALT()`.

.. _ecdsa-sign-algorithms:

ECDSA signature algorithms
--------------------------

.. macro:: PSA_ALG_ECDSA
    :definition: /* specification-defined value */

    .. summary::
        The randomized ECDSA signature scheme, with hashing.

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding randomized ECDSA signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is the message digest, computed using the ``hash_alg`` hash algorithm.

    This algorithm is randomized: each invocation returns a different, equally valid signature.

    .. note::

        When based on the same hash algorithm, the verification operations for `PSA_ALG_ECDSA` and `PSA_ALG_DETERMINISTIC_ECDSA` are identical. A signature created using `PSA_ALG_ECDSA` can be verified with the same key using either `PSA_ALG_ECDSA` or `PSA_ALG_DETERMINISTIC_ECDSA`. Similarly, a signature created using `PSA_ALG_DETERMINISTIC_ECDSA` can be verified with the same key using either `PSA_ALG_ECDSA` or `PSA_ALG_DETERMINISTIC_ECDSA`.

        In particular, it is impossible to determine whether a signature was produced with deterministic ECDSA or with randomized ECDSA: it is only possible to verify that a signature was made with ECDSA with the private key corresponding to the public key used for the verification.

    This signature scheme is defined by :cite-title:`SEC1`, and also by :cite-title:`X9-62`, with a random per-message secret number :math:`k`.

    The representation of the signature as a byte string consists of the concatenation of the signature values :math:`r` and :math:`s`. Each of :math:`r` and :math:`s` is encoded as an :math:`N`-octet string, where :math:`N` is the length of the base point of the curve in octets. Each value is represented in big-endian order, with the most significant octet first.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(family)` (signature verification only)

        where ``family`` is a Weierstrass Elliptic curve family. That is, one of the following values:

        *   ``PSA_ECC_FAMILY_SECT_XX``
        *   ``PSA_ECC_FAMILY_SECP_XX``
        *   `PSA_ECC_FAMILY_FRP`
        *   `PSA_ECC_FAMILY_BRAINPOOL_P_R1`

.. macro:: PSA_ALG_ECDSA_ANY
    :definition: ((psa_algorithm_t) 0x06000600)

    .. summary::
        The randomized ECDSA signature scheme, without hashing.

    This specialized signature algorithm can be only used with the `psa_sign_hash()` and `psa_verify_hash()` functions, or with the interruptible asymmetric signature and verification operations.

    This algorithm is randomized: each invocation returns a different, equally valid signature.

    This is the same signature scheme as `PSA_ALG_ECDSA()`, but without specifying a hash algorithm, and skipping the message hashing operation.

    .. warning::

        This algorithm is only recommended to sign or verify a sequence of bytes that are a pre-computed hash. Note that the input is padded with zeros on the left or truncated on the right as required to fit the curve size.

    This algorithm cannot be used with the wildcard key policy :code:`PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)`. It is only permitted when `PSA_ALG_ECDSA_ANY` is the key's permitted-algorithm policy.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(family)` (signature verification only)

        where ``family`` is a Weierstrass Elliptic curve family. That is, one of the following values:

        *   ``PSA_ECC_FAMILY_SECT_XX``
        *   ``PSA_ECC_FAMILY_SECP_XX``
        *   `PSA_ECC_FAMILY_FRP`
        *   `PSA_ECC_FAMILY_BRAINPOOL_P_R1`

.. macro:: PSA_ALG_DETERMINISTIC_ECDSA
    :definition: /* specification-defined value */

    .. summary::
        Deterministic ECDSA signature scheme, with hashing.

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding deterministic ECDSA signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is the message digest, computed using the ``hash_alg`` hash algorithm.

    This is the deterministic ECDSA signature scheme defined by :RFC-title:`6979`.

    The representation of a signature is the same as with `PSA_ALG_ECDSA()`.

    .. note::

        When based on the same hash algorithm, the verification operations for `PSA_ALG_ECDSA` and `PSA_ALG_DETERMINISTIC_ECDSA` are identical. A signature created using `PSA_ALG_ECDSA` can be verified with the same key using either `PSA_ALG_ECDSA` or `PSA_ALG_DETERMINISTIC_ECDSA`. Similarly, a signature created using `PSA_ALG_DETERMINISTIC_ECDSA` can be verified with the same key using either `PSA_ALG_ECDSA` or `PSA_ALG_DETERMINISTIC_ECDSA`.

        In particular, it is impossible to determine whether a signature was produced with deterministic ECDSA or with randomized ECDSA: it is only possible to verify that a signature was made with ECDSA with the private key corresponding to the public key used for the verification.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(family)` (signature verification only)

        where ``family`` is a Weierstrass Elliptic curve family. That is, one of the following values:

        *   ``PSA_ECC_FAMILY_SECT_XX``
        *   ``PSA_ECC_FAMILY_SECP_XX``
        *   `PSA_ECC_FAMILY_FRP`
        *   `PSA_ECC_FAMILY_BRAINPOOL_P_R1`

.. macro:: PSA_ALG_IS_ECDSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is ECDSA.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an ECDSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_DETERMINISTIC_ECDSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is deterministic ECDSA.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a deterministic ECDSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See also `PSA_ALG_IS_ECDSA()` and `PSA_ALG_IS_RANDOMIZED_ECDSA()`.

.. macro:: PSA_ALG_IS_RANDOMIZED_ECDSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is randomized ECDSA.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a randomized ECDSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See also `PSA_ALG_IS_ECDSA()` and `PSA_ALG_IS_DETERMINISTIC_ECDSA()`.

.. _eddsa-sign-algorithms:

EdDSA signature algorithms
--------------------------

.. macro:: PSA_ALG_PURE_EDDSA
    :definition: ((psa_algorithm_t) 0x06000800)

    .. summary::
        Edwards-curve digital signature algorithm without pre-hashing (PureEdDSA), using standard parameters.

        .. versionadded:: 1.1

    This message signature algorithm can be only used with the `psa_sign_message()` and `psa_verify_message()` functions, or with the interruptible asymmetric signature and verification operations.

    This is the PureEdDSA digital signature algorithm defined by :RFC-title:`8032`, using standard parameters.

    PureEdDSA requires an elliptic curve key on a twisted Edwards curve. The following curves are supported:

    *   Edwards25519: the Ed25519 algorithm is computed. The output signature is a 64-byte string: the concatenation of :math:`R` and :math:`S` as defined by :RFC:`8032#5.1.6`.

    *   Edwards448: the Ed448 algorithm is computed with an empty string as the context. The output signature is a 114-byte string: the concatenation of :math:`R` and :math:`S` as defined by :RFC:`8032#5.2.6`.

    .. note::
        When using an interruptible asymmetric signature operation with this algorithm, it is not possible to fragment the message data when calculating the signature. The message must be passed in a single call to `psa_sign_iop_update()`.

        However, it is possible to fragment the message data when verifying a signature using an interruptible asymmetric verification operation.

    .. note::
        To sign or verify the pre-computed hash of a message using EdDSA, the HashEdDSA algorithms (`PSA_ALG_ED25519PH` and `PSA_ALG_ED448PH`) can be used.

        The signature produced by HashEdDSA is distinct from that produced by PureEdDSA.

    .. note::
        Contexts are not supported in the current version of this specification because there is no suitable signature interface that can take the context as a parameter. A future version of this specification may add suitable functions and extend this algorithm to support contexts.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)` (signature verification only)

.. macro:: PSA_ALG_ED25519PH
    :definition: ((psa_algorithm_t) 0x0600090B)

    .. summary::
        Edwards-curve digital signature algorithm with pre-hashing (HashEdDSA), using the Edwards25519 curve.

        .. versionadded:: 1.1

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    This calculates the Ed25519ph algorithm as specified in :RFC-title:`8032#5.1`, and requires an Edwards25519 curve key. An empty string is used as the context. The pre-hash function is SHA-512, see `PSA_ALG_SHA_512`.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is the SHA-512 message digest.

    .. subsection:: Usage

        This is a hash-and-sign algorithm. To calculate a signature, use one of the following approaches:

        *   Call `psa_sign_message()` with the message.

        *   Calculate the SHA-512 hash of the message with `psa_hash_compute()`, or with a multi-part hash operation, using the hash algorithm `PSA_ALG_SHA_512`. Then sign the calculated hash with `psa_sign_hash()`.

        Verifying a signature is similar, using `psa_verify_message()` or `psa_verify_hash()` instead of the signature function.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)` (signature verification only)

    .. admonition:: Implementation note

        When used with `psa_sign_hash()` or `psa_verify_hash()`, the ``hash`` parameter to the call should be used as :math:`\text{PH}(M)` in the algorithms defined in :RFC:`8032#5.1`.

.. macro:: PSA_ALG_ED448PH
    :definition: ((psa_algorithm_t) 0x06000915)

    .. summary::
        Edwards-curve digital signature algorithm with pre-hashing (HashEdDSA), using the Edwards448 curve.

        .. versionadded:: 1.1

    This hash-and-sign signature algorithm can be used with both the message and hash signature functions.

    This calculates the Ed448ph algorithm as specified in :RFC-title:`8032#5.2`, and requires an Edwards448 curve key. An empty string is used as the context. The pre-hash function is the first 64 bytes of the output from SHAKE256, see `PSA_ALG_SHAKE256_512`.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is the truncated SHAKE256 message digest.

    .. subsection:: Usage

        This is a hash-and-sign algorithm. To calculate a signature, use one of the following approaches:

        *   Call `psa_sign_message()` with the message.

        *   Calculate the first 64 bytes of the SHAKE256 output of the message with `psa_hash_compute()`, or with a multi-part hash operation, using the hash algorithm `PSA_ALG_SHAKE256_512`. Then sign the calculated hash with `psa_sign_hash()`.

        Verifying a signature is similar, using `psa_verify_message()` or `psa_verify_hash()` instead of the signature function.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)` (signature verification only)

    .. admonition:: Implementation note

        When used with `psa_sign_hash()` or `psa_verify_hash()`, the ``hash`` parameter to the call should be used as :math:`\text{PH}(M)` in the algorithms defined in :RFC:`8032#5.2`.

.. macro:: PSA_ALG_IS_HASH_EDDSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is HashEdDSA.

        .. versionadded:: 1.1

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a HashEdDSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.


.. _single-part-signature:

Single-part asymmetric signature functions
------------------------------------------

.. function:: psa_sign_message

    .. summary::
        Sign a message with a private key. For hash-and-sign algorithms, this includes the hashing step.

    .. param:: psa_key_id_t key
        Identifier of the key to use for the operation. It must be an asymmetric key pair. The key must permit the usage `PSA_KEY_USAGE_SIGN_MESSAGE`.
    .. param:: psa_algorithm_t alg
        An asymmetric signature algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_SIGN_MESSAGE(alg)` is true.
    .. param:: const uint8_t * input
        The input message to sign.
    .. param:: size_t input_length
        Size of the ``input`` buffer in bytes.
    .. param:: uint8_t * signature
        Buffer where the signature is to be written.
    .. param:: size_t signature_size
        Size of the ``signature`` buffer in bytes.
        This must be appropriate for the selected algorithm and key:

        *   The required signature size is :code:`PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)` where ``key_type`` and ``key_bits`` are the type and bit-size respectively of ``key``.
        *   `PSA_SIGNATURE_MAX_SIZE` evaluates to the maximum signature size of any supported signature algorithm.

    .. param:: size_t * signature_length
        On success, the number of bytes that make up the returned signature value.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The first ``(*signature_length)`` bytes of ``signature`` contain the signature value.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_SIGN_MESSAGE` flag, or it does not permit the requested algorithm.
    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``signature`` buffer is too small.
        `PSA_SIGN_OUTPUT_SIZE()` or `PSA_SIGNATURE_MAX_SIZE` can be used to determine a sufficient buffer size.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported, or is not an asymmetric signature algorithm that permits signing a message.
        *   ``key`` is not supported for use with ``alg``.
        *   ``input_length`` is too large for the implementation.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm that permits signing a message.
        *   ``key`` is not an asymmetric key pair, that is compatible with ``alg``.
        *   ``input_length`` is too large for the algorithm and key type.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    ..  note::
        To perform a multi-part hash-and-sign signature algorithm, first use a :ref:`multi-part hash operation <hash-mp>` and then pass the resulting hash to `psa_sign_hash()`. :code:`PSA_ALG_GET_HASH(alg)` can be used to determine the hash algorithm to use.

.. function:: psa_verify_message

    .. summary::
        Verify the signature of a message with a public key. For hash-and-sign algorithms, this includes the hashing step.

    .. param:: psa_key_id_t key
        Identifier of the key to use for the operation. It must be a public key or an asymmetric key pair. The key must permit the usage `PSA_KEY_USAGE_VERIFY_MESSAGE`.
    .. param:: psa_algorithm_t alg
        An asymmetric signature algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_SIGN_MESSAGE(alg)` is true.
    .. param:: const uint8_t * input
        The message whose signature is to be verified.
    .. param:: size_t input_length
        Size of the ``input`` buffer in bytes.
    .. param:: const uint8_t * signature
        Buffer containing the signature to verify.
    .. param:: size_t signature_length
        Size of the ``signature`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The signature is valid.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_VERIFY_MESSAGE` flag, or it does not permit the requested algorithm.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        ``signature`` is not the result of signing the ``input`` message with algorithm ``alg`` using the private key corresponding to ``key``.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported, or is not an asymmetric signature algorithm that permits verifying a message.
        *   ``key`` is not supported for use with ``alg``.
        *   ``input_length`` is too large for the implementation.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm that permits verifying a message.
        *   ``key`` is not a public key or an asymmetric key pair, that is compatible with ``alg``.
        *   ``input_length`` is too large for the algorithm and key type.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    ..  note::
        To perform a multi-part hash-and-sign signature verification algorithm, first use a :ref:`multi-part hash operation <hash-mp>` to hash the message and then pass the resulting hash to `psa_verify_hash()`. :code:`PSA_ALG_GET_HASH(alg)` can be used to determine the hash algorithm to use.

.. function:: psa_sign_hash

    .. summary::
        Sign a pre-computed hash with a private key.

    .. param:: psa_key_id_t key
        Identifier of the key to use for the operation. It must be an asymmetric key pair. The key must permit the usage `PSA_KEY_USAGE_SIGN_HASH`.
    .. param:: psa_algorithm_t alg
        An asymmetric signature algorithm that separates the hash and sign operations: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_SIGN_HASH(alg)` is true.
    .. param:: const uint8_t * hash
        The input to sign. This is usually the hash of a message.

        See the description of this function, or the description of individual signature algorithms, for details of the acceptable inputs.
    .. param:: size_t hash_length
        Size of the ``hash`` buffer in bytes.
    .. param:: uint8_t * signature
        Buffer where the signature is to be written.
    .. param:: size_t signature_size
        Size of the ``signature`` buffer in bytes.
        This must be appropriate for the selected algorithm and key:

        *   The required signature size is :code:`PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)` where ``key_type`` and ``key_bits`` are the type and bit-size respectively of ``key``.
        *   `PSA_SIGNATURE_MAX_SIZE` evaluates to the maximum signature size of any supported signature algorithm.

    .. param:: size_t * signature_length
        On success, the number of bytes that make up the returned signature value.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The first ``(*signature_length)`` bytes of ``signature`` contain the signature value.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_SIGN_HASH` flag, or it does not permit the requested algorithm.
    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``signature`` buffer is too small.
        `PSA_SIGN_OUTPUT_SIZE()` or `PSA_SIGNATURE_MAX_SIZE` can be used to determine a sufficient buffer size.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported, or is not an asymmetric signature algorithm that permits signing a pre-computed hash.
        *   ``key`` is not supported for use with ``alg``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm that permits signing a pre-computed hash.
        *   ``key`` is not an asymmetric key pair, that is compatible with ``alg``.
        *   ``hash_length`` is not valid for the algorithm and key type.
        *   ``hash`` is not a valid input value for the algorithm and key type.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    For hash-and-sign signature algorithms, the ``hash`` input to this function is the hash of the message to sign. The algorithm used to calculate this hash is encoded in the signature algorithm. For such algorithms, ``hash_length`` must equal the length of the hash output: :code:`hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))`.

    Specialized signature algorithms can apply a padding or encoding to the hash. In such cases, the encoded hash must be passed to this function. For example, see `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.

.. function:: psa_verify_hash

    .. summary::
        Verify the signature of a hash or short message using a public key.

    .. param:: psa_key_id_t key
        Identifier of the key to use for the operation. It must be a public key or an asymmetric key pair. The key must permit the usage `PSA_KEY_USAGE_VERIFY_HASH`.
    .. param:: psa_algorithm_t alg
        An asymmetric signature algorithm that separates the hash and sign operations: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_SIGN_HASH(alg)` is true.
    .. param:: const uint8_t * hash
        The input whose signature is to be verified. This is usually the hash of a message.

        See the description of this function, or the description of individual signature algorithms, for details of the acceptable inputs.
    .. param:: size_t hash_length
        Size of the ``hash`` buffer in bytes.
    .. param:: const uint8_t * signature
        Buffer containing the signature to verify.
    .. param:: size_t signature_length
        Size of the ``signature`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The signature is valid.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_VERIFY_HASH` flag, or it does not permit the requested algorithm.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        ``signature`` is not the result of signing ``hash`` with algorithm ``alg`` using the private key corresponding to ``key``.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported, or is not an asymmetric signature algorithm that permits verifying a pre-computed hash.
        *   ``key`` is not supported for use with ``alg``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm that permits verifying a pre-computed hash.
        *   ``key`` is not a public key or an asymmetric key pair, that is compatible with ``alg``.
        *   ``hash_length`` is not valid for the algorithm and key type.
        *   ``hash`` is not a valid input value for the algorithm and key type.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    For hash-and-sign signature algorithms, the ``hash`` input to this function is the hash of the message to verify. The algorithm used to calculate this hash is encoded in the signature algorithm. For such algorithms, ``hash_length`` must equal the length of the hash output: :code:`hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))`.

    Specialized signature algorithms can apply a padding or encoding to the hash. In such cases, the encoded hash must be passed to this function. For example, see `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.


.. _interruptible-sign:

Interruptible asymmetric signature operations
---------------------------------------------

The interruptible asymmetric signature operation calculates the signature of a message, or pre-computed hash, in an interruptible manner. For example, this can enable an application to remain responsive in an execution environment that does not provide multi-tasking.

An interruptible asymmetric signature operation is used as follows:

1.  Allocate an interruptible asymmetric signature operation object, of type `psa_sign_iop_t`, which will be passed to all the functions listed here.
#.  Initialize the operation object with one of the methods described in the documentation for `psa_sign_iop_t`, for example, `PSA_SIGN_IOP_INIT`.
#.  Call `psa_sign_iop_setup()` to specify the algorithm and key.
#.  Call `psa_sign_iop_setup_complete()` to complete the setup, until this function does not return :code:`PSA_OPERATION_INCOMPLETE`.
#.  Either:

    1.  Call `psa_sign_iop_hash()` with a pre-computed hash of the message to sign; or
    2.  Call `psa_sign_iop_update()` one or more times, passing a fragment of the message each time. The signature that is calculated will that be of the concatenation of these fragments, in order.
#.  Call `psa_sign_iop_complete()` to finish calculating the signature value, until this function does not return :code:`PSA_OPERATION_INCOMPLETE`.
#.  If an error occurs at any stage, or to terminate the operation early, call `psa_sign_iop_abort()`.


.. typedef:: /* implementation-defined type */ psa_sign_iop_t

    .. summary::
        The type of the state data structure for an interruptible asymmetric signature operation.

        .. versionadded:: 1.x

    Before calling any function on an interruptible asymmetric signature operation object, the application must initialize it by any of the following means:

    *   Set the object to all-bits-zero, for example:

        .. code-block:: xref

            psa_sign_iop_t operation;
            memset(&operation, 0, sizeof(operation));

    *   Initialize the object to logical zero values by declaring the object as static or global without an explicit initializer, for example:

        .. code-block:: xref

            static psa_sign_iop_t operation;

    *   Initialize the object to the initializer `PSA_SIGN_IOP_INIT`, for example:

        .. code-block:: xref

            psa_sign_iop_t operation = PSA_SIGN_IOP_INIT;

    *   Assign the result of the function `psa_sign_iop_init()` to the object, for example:

        .. code-block:: xref

            psa_sign_iop_t operation;
            operation = psa_sign_iop_init();

    This is an implementation-defined type. Applications that make assumptions about the content of this object will result in implementation-specific behavior, and are non-portable.

.. macro:: PSA_SIGN_IOP_INIT
    :definition: /* implementation-defined value */

    .. summary::
        This macro evaluates to an initializer for an interruptible asymmetric signature operation object of type `psa_sign_iop_t`.

        .. versionadded:: 1.x

.. function:: psa_sign_iop_init

    .. summary::
        Return an initial value for an interruptible asymmetric signature operation object.

        .. versionadded:: 1.x

    .. return:: psa_sign_iop_t

.. function:: psa_sign_iop_get_num_ops

    .. summary::
        Get the number of *ops* that an interruptible asymmetric signature operation has taken so far.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible asymmetric signature operation to inspect.

    .. return:: uint32_t
        Number of *ops* that the operation has taken so far.

    After the interruptible operation has completed, the returned value is the number of *ops* required for the entire operation. The value is reset to zero by a call to either `psa_sign_iop_setup()` or `psa_sign_iop_abort()`.

    This function can be used to tune the value passed to `psa_iop_set_max_ops()`.

    The value is undefined if the operation object has not been initialized.

.. function:: psa_sign_iop_setup

    .. summary::
        Begin the setup of an interruptible asymmetric signature operation.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible asymmetric signature operation to set up. It must have been initialized as per the documentation for `psa_sign_iop_t` and not yet in use.
    .. param:: psa_key_id_t key
        Identifier of the key to use for the operation. It must be an asymmetric key pair. The key must either permit the usage `PSA_KEY_USAGE_SIGN_HASH` or `PSA_KEY_USAGE_SIGN_MESSAGE`.
    .. param:: psa_algorithm_t alg
        An asymmetric signature algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_SIGN(alg)` is true.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation setup must now be completed by calling `psa_sign_iop_setup_complete()`.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The following conditions can result in this error:

        *   The key has neither the `PSA_KEY_USAGE_SIGN_HASH` nor the `PSA_KEY_USAGE_SIGN_MESSAGE` usage flag.
        *   The key does not permit the requested algorithm.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not an asymmetric signature algorithm.
        *   ``key`` is not supported for use with ``alg``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm.
        *   ``key`` is not an asymmetric key pair, that is compatible with ``alg``.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be inactive.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY

    This function sets up the calculation of an asymmetric signature of a message or pre-computed hash. To verify an asymmetric signature against an expected value, use an interruptible asymmetric verification operation, see :secref:`interruptible-verify`.

    After a successful call to `psa_sign_iop_setup()`, the operation is in setup state. Setup can be completed by calling `psa_sign_iop_setup_complete()` repeatedly, until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`. Once setup has begun, the application must eventually terminate the operation. The following events terminate an operation:

    *   A successful call to `psa_sign_iop_complete()`.
    *   A call to `psa_sign_iop_abort()`.

    If `psa_sign_iop_setup()` returns an error, the operation object is unchanged.

.. function:: psa_sign_iop_setup_complete

    .. summary::
        Finish setting up an interruptible asymmetric signature operation.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible asymmetric signature operation to use. The operation must be in the process of being set up.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation is now ready for input of data to sign.
    .. retval:: PSA_OPERATION_INCOMPLETE
        The function was interrupted after exhausting the maximum *ops*. The computation is incomplete, and this function must be called again with the same operation object to continue.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation setup must have started, but not yet finished.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY

    .. note::
        This is an interruptible function, and must be called repeatedly, until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    When this function returns successfully, the operation is ready for data input using a call to `psa_sign_iop_hash()` or `psa_sign_iop_update()`.
    If this function returns :code:`PSA_OPERATION_INCOMPLETE`, setup is not complete, and this function must be called again to continue the operation.
    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_sign_iop_abort()`.

    The amount of calculation performed in a single call to this function is determined by the maximum *ops* setting. See `psa_iop_set_max_ops()`.

.. function:: psa_sign_iop_hash

    .. summary::
        Input a pre-computed hash to an interruptible asymmetric signature operation.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible asymmetric signature operation to use. The operation must have been set up, with no data input.
    .. param:: const uint8_t * hash
        The input to sign. This is usually the hash of a message.

        See the description of this function, or the description of individual signature algorithms, for details of the acceptable inputs.
    .. param:: size_t hash_length
        Size of the ``hash`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation is now ready for completion.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation must be set up, with no data input.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_SIGN_HASH` flag.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   The algorithm does not allow signing of a pre-computed hash.
        *   ``hash_length`` is not valid for the algorithm and key type.
        *   ``hash`` is not a valid input value for the algorithm and key type.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The implementation does not support signing of a pre-computed hash.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY

    The application must complete the setup of the operation before calling this function.

    For hash-and-sign signature algorithms, the ``hash`` input to this function is the hash of the message to sign. The algorithm used to calculate this hash is encoded in the signature algorithm. For such algorithms, ``hash_length`` must equal the length of the hash output: :code:`hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))`.

    Specialized signature algorithms can apply a padding or encoding to the hash. In such cases, the encoded hash must be passed to this function. For example, see `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.

    After input of the hash, the signature operation can be completed by calling `psa_sign_iop_complete()` until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_sign_iop_abort()`.

.. function:: psa_sign_iop_update

    .. summary::
        Add a message fragment to an interruptible asymmetric signature operation.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible asymmetric signature operation to use. The operation must have been set up, with no hash value input.
    .. param:: const uint8_t * input
        Buffer containing the message fragment to add to the signature calculation.
    .. param:: size_t input_length
        Size of the ``input`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation must be set up, with no pre-computed hash value input.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_SIGN_MESSAGE` flag.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   The algorithm does not allow signing of a message.
        *   The total input for the operation is too large for the signature algorithm.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   The implementation does not support signing of a message.
        *   The total input for the operation is too large for the implementation.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY

    The application must complete the setup of the operation before calling this function.

    For message-signature algorithms that process the message data multiple times when computing a signature, `psa_sign_iop_update()` must be called exactly once with the entire message content. For signature algorithms that only process the message data once, the message content can be passed in a series of calls to `psa_sign_iop_update()`.

    After input of the message, the signature operation can be completed by calling `psa_sign_iop_complete()` until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_sign_iop_abort()`.

    .. note::

        To sign the zero-length message using an interruptible operation, call `psa_sign_iop_update()` once with a zero-length message fragment before calling `psa_sign_iop_complete()`.

.. function:: psa_sign_iop_complete

    .. summary::
        Attempt to finish the interruptible calculation of an asymmetric signature.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible asymmetric signature operation to use. The operation must have hash or message data input, or be in the process of finishing.
    .. param:: uint8_t * signature
        Buffer where the signature is to be written.
    .. param:: size_t signature_size
        Size of the ``signature`` buffer in bytes. This must be appropriate for the selected algorithm and key:

        *   The required signature size is :code:`PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)` where ``key_type`` and ``key_bits`` are attributes of the key, and ``alg`` is the algorithm used to calculate the signature.
        *   `PSA_SIGNATURE_MAX_SIZE` evaluates to the maximum signature size of any supported signature algorithm.
    .. param:: size_t * signature_length
        On success, the number of bytes that make up the returned signature value.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The first ``(*signature_length)`` bytes of ``signature`` contain the signature value.
    .. retval:: PSA_OPERATION_INCOMPLETE
        The function was interrupted after exhausting the maximum *ops*. The computation is incomplete, and this function must be called again with the same operation object to continue.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation setup must be complete, or a previous call to `psa_sign_iop_complete()` returned :code:`PSA_OPERATION_INCOMPLETE`.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``signature`` buffer is too small.
        `PSA_SIGN_OUTPUT_SIZE()` or `PSA_SIGNATURE_MAX_SIZE` can be used to determine a sufficient buffer size.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY

    .. note::
        This is an interruptible function, and must be called repeatedly, until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    When this function returns successfully, the signature is returned in ``signature``, and the operation becomes inactive.
    If this function returns :code:`PSA_OPERATION_INCOMPLETE`, no signature is returned, and this function must be called again to continue the operation.
    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_sign_iop_abort()`.

    The amount of calculation performed in a single call to this function is determined by the maximum *ops* setting. See `psa_iop_set_max_ops()`.

.. function:: psa_sign_iop_abort

    .. summary::
        Abort an interruptible asymmetric signature operation.

        .. versionadded:: 1.x

    .. param:: psa_sign_iop_t * operation
        The interruptible signature operation to abort.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation object can now be discarded or reused.
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    Aborting an operation frees all associated resources except for the ``operation`` structure itself. Once aborted, the operation object can be reused for another operation by calling `psa_sign_iop_setup()` again.

    This function can be called at any time after the operation object has been initialized as described in `psa_sign_iop_t`.

    In particular, it is valid to call `psa_sign_iop_abort()` twice, or to call `psa_sign_iop_abort()` on an operation that has not been set up.


.. _interruptible-verify:

Interruptible asymmetric verification operations
------------------------------------------------

The interruptible asymmetric verification operation verifies the signature of a message, or pre-computed hash, in an interruptible manner. For example, this can enable an application to remain responsive in an execution environment that does not provide multi-tasking.

An interruptible asymmetric verification operation is used as follows:

1.  Allocate an interruptible asymmetric verification operation object, of type `psa_verify_iop_t`, which will be passed to all the functions listed here.
#.  Initialize the operation object with one of the methods described in the documentation for `psa_verify_iop_t`, for example, `PSA_VERIFY_IOP_INIT`.
#.  Call `psa_verify_iop_setup()` to specify the algorithm, key, and the signature to verify.
#.  Call `psa_verify_iop_setup_complete()` to complete the setup, until this function does not return :code:`PSA_OPERATION_INCOMPLETE`.
#.  Either:

    1.  Call `psa_verify_iop_hash()` with a pre-computed hash of the message to verify; or
    2.  Call `psa_verify_iop_update()` one or more times, passing a fragment of the message each time. The signature is verified against the concatenation of these fragments, in order.
#.  Call `psa_verify_iop_complete()` to finish verifying the signature value, until this function does not return :code:`PSA_OPERATION_INCOMPLETE`.
#.  If an error occurs at any stage, or to terminate the operation early, call `psa_verify_iop_abort()`.


.. typedef:: /* implementation-defined type */ psa_verify_iop_t

    .. summary::
        The type of the state data structure for an interruptible asymmetric verification operation.

        .. versionadded:: 1.x

    Before calling any function on an interruptible asymmetric verification operation object, the application must initialize it by any of the following means:

    *   Set the object to all-bits-zero, for example:

        .. code-block:: xref

            psa_verify_iop_t operation;
            memset(&operation, 0, sizeof(operation));

    *   Initialize the object to logical zero values by declaring the object as static or global without an explicit initializer, for example:

        .. code-block:: xref

            static psa_verify_iop_t operation;

    *   Initialize the object to the initializer `PSA_VERIFY_IOP_INIT`, for example:

        .. code-block:: xref

            psa_verify_iop_t operation = PSA_VERIFY_IOP_INIT;

    *   Assign the result of the function `psa_verify_iop_init()` to the object, for example:

        .. code-block:: xref

            psa_verify_iop_t operation;
            operation = psa_verify_iop_init();

    This is an implementation-defined type. Applications that make assumptions about the content of this object will result in implementation-specific behavior, and are non-portable.

.. macro:: PSA_VERIFY_IOP_INIT
    :definition: /* implementation-defined value */

    .. summary::
        This macro evaluates to an initializer for an interruptible asymmetric verification operation object of type `psa_verify_iop_t`.

        .. versionadded:: 1.x

.. function:: psa_verify_iop_init

    .. summary::
        Return an initial value for an interruptible asymmetric verification operation object.

        .. versionadded:: 1.x

    .. return:: psa_verify_iop_t

.. function:: psa_verify_iop_get_num_ops

    .. summary::
        Get the number of *ops* that an interruptible asymmetric verification operation has taken so far.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible asymmetric verification operation to inspect.

    .. return:: uint32_t
        Number of *ops* that the operation has taken so far.

    After the interruptible operation has completed, the returned value is the number of *ops* required for the entire operation. The value is reset to zero by a call to either `psa_verify_iop_setup()` or `psa_verify_iop_abort()`.

    This function can be used to tune the value passed to `psa_iop_set_max_ops()`.

    The value is undefined if the operation object has not been initialized.

.. function:: psa_verify_iop_setup

    .. summary::
        Begin the setup of an interruptible asymmetric verification operation.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible verification operation to set up. It must have been initialized as per the documentation for `psa_verify_iop_t` and not yet in use.
    .. param:: psa_key_id_t key
        Identifier of the key to use for the operation. It must be an asymmetric key pair or asymmetric public key. The key must either permit the usage `PSA_KEY_USAGE_VERIFY_HASH` or `PSA_KEY_USAGE_VERIFY_MESSAGE`.
    .. param:: psa_algorithm_t alg
        An asymmetric signature algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_SIGN(alg)` is true.
    .. param:: const uint8_t * signature
        Buffer containing the signature to verify.
    .. param:: size_t signature_length
        Size of the ``signature`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation setup must now be completed by calling `psa_verify_iop_setup_complete()`.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The following conditions can result in this error:

        *   The key has neither the `PSA_KEY_USAGE_VERIFY_HASH` nor the `PSA_KEY_USAGE_VERIFY_MESSAGE` usage flag.
        *   The key does not permit the requested algorithm.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not an asymmetric signature algorithm.
        *   ``key`` is not supported for use with ``alg``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm.
        *   ``key`` is not an asymmetric key pair, or asymmetric public key, that is compatible with ``alg``.
        *   ``signature`` is not a valid signature for the algorithm and key.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be inactive.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        ``signature`` is not a valid signature for the algorithm and key.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    This function sets up the verification of an asymmetric signature of a message or pre-computed hash. To calculate an asymmetric signature, use an interruptible asymmetric signature operation, see :secref:`interruptible-sign`.

    After a successful call to `psa_verify_iop_setup()`, the operation is in setup state. Setup can be completed by calling `psa_verify_iop_setup_complete()` repeatedly, until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`. Once setup has begun, the application must eventually terminate the operation. The following events terminate an operation:

    *   A successful call to `psa_verify_iop_complete()`.
    *   A call to `psa_verify_iop_abort()`.

    If `psa_verify_iop_setup()` returns an error, the operation object is unchanged.

.. function:: psa_verify_iop_setup_complete

    .. summary::
        Finish setting up an interruptible asymmetric verification operation.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible verification operation to use. The operation must be in the process of being set up.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation is now ready for input of data to verify.
    .. retval:: PSA_OPERATION_INCOMPLETE
        The function was interrupted after exhausting the maximum *ops*. The computation is incomplete, and this function must be called again with the same operation object to continue.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation setup must have started, but not yet finished.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        The signature is not a valid signature for the algorithm and key.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    .. note::
        This is an interruptible function, and must be called repeatedly, until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    When this function returns successfully, the operation is ready for data input using a call to `psa_verify_iop_hash()` or `psa_verify_iop_update()`.
    If this function returns :code:`PSA_OPERATION_INCOMPLETE`, setup is not complete, and this function must be called again to continue the operation.
    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_verify_iop_abort()`.

    The amount of calculation performed in a single call to this function is determined by the maximum *ops* setting. See `psa_iop_set_max_ops()`.

.. function:: psa_verify_iop_hash

    .. summary::
        Input a pre-computed hash to an interruptible asymmetric verification operation.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible verification operation to use. The operation must have been set up, with no data input.
    .. param:: const uint8_t * hash
        The input whose signature is to be verified. This is usually the hash of a message.

        See the description of this function, or the description of individual signature algorithms, for details of the acceptable inputs.
    .. param:: size_t hash_length
        Size of the ``hash`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation is now ready for completion.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation must be set up, with no data input.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_VERIFY_HASH` flag.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   The algorithm does not allow verification of a pre-computed hash.
        *   ``hash_length`` is not valid for the algorithm and key type.
        *   ``hash`` is not a valid input value for the algorithm and key type.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The implementation does not support verification of a pre-computed hash.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    The application must complete the setup of the operation before calling this function.

    For hash-and-sign signature algorithms, the ``hash`` input to this function is the hash of the message to verify. The algorithm used to calculate this hash is encoded in the signature algorithm. For such algorithms, ``hash_length`` must equal the length of the hash output: :code:`hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))`.

    Specialized signature algorithms can apply a padding or encoding to the hash. In such cases, the encoded hash must be passed to this function. For example, see `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.

    After input of the hash, the verification operation can be completed by calling `psa_verify_iop_complete()` until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_verify_iop_abort()`.


.. function:: psa_verify_iop_update

    .. summary::
        Add a message fragment to an interruptible asymmetric verification operation.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible verification operation to use. The operation must have been set up, with no hash value input.
    .. param:: const uint8_t * input
        Buffer containing the message fragment to add to the verification.
    .. param:: size_t input_length
        Size of the ``input`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation must be set up, with no pre-computed hash value input.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The key does not have the `PSA_KEY_USAGE_VERIFY_MESSAGE` flag.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   The algorithm does not allow verification of a message.
        *   The total input for the operation is too large for the signature algorithm.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   The implementation does not support signing of a message.
        *   The total input for the operation is too large for the implementation.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    The application must complete the setup of the operation before calling this function.

    For message-signature algorithms that process the message data multiple times when verifying a signature, `psa_verify_iop_update()` must be called exactly once with the entire message content. For signature algorithms that only process the message data once, the message content can be passed in a series of calls to `psa_verify_iop_update()`.

    After input of the message, the verification operation can be completed by calling `psa_verify_iop_complete()` until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_verify_iop_abort()`.

    .. note::

        To verify the signature of the zero-length message using an interruptible operation, call `psa_verify_iop_update()` once with a zero-length message fragment before calling `psa_verify_iop_complete()`

.. function:: psa_verify_iop_complete

    .. summary::
        Attempt to finish the interruptible verification of an asymmetric signature.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible verification operation to use. The operation must have hash or message data input, or be in the process of finishing.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The signature is valid.
    .. retval:: PSA_OPERATION_INCOMPLETE
        The function was interrupted after exhausting the maximum *ops*. The computation is incomplete, and this function must be called again with the same operation object to continue.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: the operation setup must be complete, or a previous call to `psa_verify_iop_complete()` returned :code:`PSA_OPERATION_INCOMPLETE`.
        *   The library requires initializing by a call to `psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        The signature is not the result of signing the input message, or hash value, with the requested algorithm, using the private key corresponding to the key provided to the operation.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    .. note::
        This is an interruptible function, and must be called repeatedly, until it returns a status code that is not :code:`PSA_OPERATION_INCOMPLETE`.

    When this function returns successfully, the operation becomes inactive.
    If this function returns :code:`PSA_OPERATION_INCOMPLETE`, this function must be called again to continue the operation.
    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_verify_iop_abort()`.

    The amount of calculation performed in a single call to this function is determined by the maximum *ops* setting. See `psa_iop_set_max_ops()`.

.. function:: psa_verify_iop_abort

    .. summary::
        Abort an interruptible asymmetric verification operation.

        .. versionadded:: 1.x

    .. param:: psa_verify_iop_t * operation
        The interruptible verification operation to abort.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation object can now be discarded or reused.
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    Aborting an operation frees all associated resources except for the ``operation`` structure itself. Once aborted, the operation object can be reused for another operation by calling `psa_verify_iop_setup()` again.

    This function can be called at any time after the operation object has been initialized as described in `psa_verify_iop_t`.

    In particular, it is valid to call `psa_verify_iop_abort()` twice, or to call `psa_verify_iop_abort()` on an operation that has not been set up.

Support macros
--------------

.. macro:: PSA_ALG_IS_SIGN_MESSAGE
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a signature algorithm that can be used with `psa_sign_message()` and `psa_verify_message()`.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a signature algorithm that can be used to sign a message. ``0`` if ``alg`` is a signature algorithm that can only be used to sign a pre-computed hash. ``0`` if ``alg`` is not a signature algorithm. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    This macro evaluates to ``1`` for hash-and-sign and message-signature algorithms.

.. macro:: PSA_ALG_IS_SIGN_HASH
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a signature algorithm that can be used with `psa_sign_hash()` and `psa_verify_hash()`.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a signature algorithm that can be used to sign a hash. ``0`` if ``alg`` is a signature algorithm that can only be used to sign a message. ``0`` if ``alg`` is not a signature algorithm. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    This macro evaluates to ``1`` for hash-and-sign and specialized signature algorithms.

.. macro:: PSA_ALG_IS_HASH_AND_SIGN
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a hash-and-sign algorithm that signs exactly the hash value.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a hash-and-sign algorithm that signs exactly the hash value, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

        A wildcard signature algorithm policy, using `PSA_ALG_ANY_HASH`, returns the same value as the signature algorithm parameterized with a valid hash algorithm.

    This macro identifies algorithms that can be used with `psa_sign_hash()` that use the exact message hash value as an input the signature operation. For example, if :code:`PSA_ALG_IS_HASH_AND_SIGN(alg)` is true, the following call sequence is equivalent to :code:`psa_sign_message(key, alg, msg, msg_len, ...)`:

    .. code-block:: xref

        uint8_t hash[PSA_HASH_MAX_SIZE];
        size_t hash_len;
        psa_hash_compute(PSA_ALG_GET_HASH(alg), msg, msg_len,
                         hash, sizeof(hash), &hash_len);
        psa_sign_hash(key, alg, hash, hash_len, ...);

.. macro:: PSA_ALG_ANY_HASH
    :definition: ((psa_algorithm_t)0x020000ff)

    .. summary::
        When setting a hash-and-sign algorithm in a key policy, permit any hash algorithm.

    This value can be used to form the permitted-algorithm attribute of a key policy for a signature algorithm that is parametrized by a hash. A key with this policy can then be used to perform operations using the same signature algorithm parametrized with any supported hash.
    A signature algorithm created using this macro is a wildcard algorithm, and `PSA_ALG_IS_WILDCARD()` will return true.

    This value must not be used to build other algorithms that are parametrized over a hash. For any valid use of this macro to build an algorithm ``alg``, :code:`PSA_ALG_IS_HASH_AND_SIGN(alg)` is true.

    This value cannot be used to build an algorithm specification to perform an operation. If used in this way, the operation will fail with an error.

    .. rubric:: Usage

    For example, suppose that ``PSA_xxx_SIGNATURE`` is one of the following macros:

    *   `PSA_ALG_RSA_PKCS1V15_SIGN`
    *   `PSA_ALG_RSA_PSS`
    *   `PSA_ALG_RSA_PSS_ANY_SALT`
    *   `PSA_ALG_ECDSA`
    *   `PSA_ALG_DETERMINISTIC_ECDSA`

    The following sequence of operations shows how `PSA_ALG_ANY_HASH` can be used in a key policy:

    1.  Set the key usage flags using `PSA_ALG_ANY_HASH`, for example:

        .. code-block:: xref

            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE); // or VERIFY_MESSAGE
            psa_set_key_algorithm(&attributes, PSA_xxx_SIGNATURE(PSA_ALG_ANY_HASH));

    #.  Import or generate key material.
    #.  Call `psa_sign_message()` or `psa_verify_message()`, passing an algorithm built from ``PSA_xxx_SIGNATURE`` and a specific hash. Each call to sign or verify a message can use a different hash algorithm.

        .. code-block:: xref

            psa_sign_message(key, PSA_xxx_SIGNATURE(PSA_ALG_SHA_256), ...);
            psa_sign_message(key, PSA_xxx_SIGNATURE(PSA_ALG_SHA_512), ...);
            psa_sign_message(key, PSA_xxx_SIGNATURE(PSA_ALG_SHA3_256), ...);


.. macro:: PSA_SIGN_OUTPUT_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient signature buffer size for `psa_sign_message()` and `psa_sign_hash()`.

    .. param:: key_type
        An asymmetric key type. This can be a key-pair type or a public-key type.
    .. param:: key_bits
        The size of the key in bits.
    .. param:: alg
        The signature algorithm.

    .. return::
        A sufficient signature buffer size for the specified asymmetric signature algorithm and key parameters. An implementation can return either ``0`` or a correct size for an asymmetric signature algorithm and key parameters that it recognizes, but does not support. If the parameters are not valid, the return value is unspecified.

    If the size of the signature buffer is at least this large, it is guaranteed that `psa_sign_message()` and `psa_sign_hash()` will not fail due to an insufficient buffer size. The actual size of the output might be smaller in any given call.

    See also `PSA_SIGNATURE_MAX_SIZE`.

.. macro:: PSA_SIGNATURE_MAX_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        A sufficient signature buffer size for `psa_sign_message()` and `psa_sign_hash()`, for any of the supported key types and asymmetric signature algorithms.

    If the size of the signature buffer is at least this large, it is guaranteed that `psa_sign_message()` and `psa_sign_hash()` will not fail due to an insufficient buffer size.

    See also `PSA_SIGN_OUTPUT_SIZE()`.
