.. SPDX-FileCopyrightText: Copyright 2018-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 26

.. _sign:

Asymmetric signature
====================

There are two pairs of single-part functions for asymmetric signature:

*   The signature and verification functions `psa_sign_message()` and `psa_verify_message()` take a message as one of their inputs and perform a hash-and-sign algorithm.

*   The functions `psa_sign_hash()` and `psa_verify_hash()` take a message hash as one of their inputs. This is useful for signing pre-computed hashes, or for implementing hash-and-sign using a :ref:`multi-part hash operation <hash-mp>` before signing the resulting hash. To determine which hash algorithm to use, call the macro `PSA_ALG_GET_HASH()` on the corresponding signature algorithm.

    Some hash-and-sign algorithms add padding to the message hash before completing the signing operation. The format of the padding that is used depends on the algorithm used to construct the signature, see the description of the specific algorithm for details.

.. _sign-algorithms:

Asymmetric signature algorithms
-------------------------------

.. macro:: PSA_ALG_RSA_PKCS1V15_SIGN
    :definition: /* specification-defined value */

    .. summary::
        The RSA PKCS#1 v1.5 message signature scheme, with hashing.

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding RSA PKCS#1 v1.5 signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

    This signature scheme is defined by :RFC-title:`8017#8.2` under the name RSASSA-PKCS1-v1_5.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is used as :math:`H` from step 2 onwards in the message encoding algorithm ``EMSA-PKCS1-V1_5-ENCODE()`` in :RFC:`8017#9.2`. :math:`H` is the message digest, computed using the ``hash_alg`` hash algorithm.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_RSA_KEY_PAIR`
        | `PSA_KEY_TYPE_RSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_RSA_PKCS1V15_SIGN_RAW
    :definition: ((psa_algorithm_t) 0x06000200)

    .. summary::
        The raw RSA PKCS#1 v1.5 signature algorithm, without hashing.

    This algorithm can be only used with the `psa_sign_hash()` and `psa_verify_hash()` functions.

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

    This algorithm can be used with both the message and hash signature functions.

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

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding RSA PSS signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

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

.. macro:: PSA_ALG_ECDSA
    :definition: /* specification-defined value */

    .. summary::
        The randomized ECDSA signature scheme, with hashing.

    .. param:: hash_alg
        A hash algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding randomized ECDSA signature algorithm.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

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

    This algorithm can be only used with the `psa_sign_hash()` and `psa_verify_hash()` functions.

    This algorithm is randomized: each invocation returns a different, equally valid signature.

    This is the same signature scheme as `PSA_ALG_ECDSA()`, but without specifying a hash algorithm, and skipping the message hashing operation.

    This algorithm is only recommended to sign or verify a sequence of bytes that are an already-calculated hash. Note that the input is padded with zeros on the left or truncated on the right as required to fit the curve size.

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

    This algorithm can be used with both the message and hash signature functions.

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

.. macro:: PSA_ALG_PURE_EDDSA
    :definition: ((psa_algorithm_t) 0x06000800)

    .. summary::
        Edwards-curve digital signature algorithm without prehashing (PureEdDSA), using standard parameters.

    This algorithm can be only used with the `psa_sign_message()` and `psa_verify_message()` functions.

    This is the PureEdDSA digital signature algorithm defined by :RFC-title:`8032`, using standard parameters.

    PureEdDSA requires an elliptic curve key on a twisted Edwards curve. The following curves are supported:

    *   Edwards25519: the Ed25519 algorithm is computed. The output signature is a 64-byte string: the concatenation of :math:`R` and :math:`S` as defined by :RFC:`8032#5.1.6`.

    *   Edwards448: the Ed448 algorithm is computed with an empty string as the context. The output signature is a 114-byte string: the concatenation of :math:`R` and :math:`S` as defined by :RFC:`8032#5.2.6`.

    .. note::
        Contexts are not supported in the current version of this specification because there is no suitable signature interface that can take the context as a parameter. A future version of this specification may add suitable functions and extend this algorithm to support contexts.

    .. note::
        To sign or verify the pre-computed hash of a message using EdDSA, the HashEdDSA algorithms (`PSA_ALG_ED25519PH` and `PSA_ALG_ED448PH`) can be used with `psa_sign_hash()` and `psa_verify_hash()`.

        The signature produced by HashEdDSA is distinct from that produced by PureEdDSA.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)`
        | :code:`PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)` (signature verification only)

.. macro:: PSA_ALG_ED25519PH
    :definition: ((psa_algorithm_t) 0x0600090B)

    .. summary::
        Edwards-curve digital signature algorithm with prehashing (HashEdDSA), using the Edwards25519 curve.

    This algorithm can be used with both the message and hash signature functions.

    This computes the Ed25519ph algorithm as specified in :RFC-title:`8032#5.1`, and requires an Edwards25519 curve key. An empty string is used as the context. The prehash function is SHA-512.

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
        Edwards-curve digital signature algorithm with prehashing (HashEdDSA), using the Edwards448 curve.

    This algorithm can be used with both the message and hash signature functions.

    This computes the Ed448ph algorithm as specified in :RFC-title:`8032#5.2`, and requires an Edwards448 curve key. An empty string is used as the context. The prehash function is the first 64 bytes of the output from SHAKE256.

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

.. macro:: PSA_ALG_MLDSA_SIGN
    :definition: ((psa_algorithm_t) 0x06000916)

.. summary::
        The Module Lattice Signature scheme, with hashing.

.. param:: hash_alg
        A hash algorithm: A value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true. This includes `PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    This algorithm can be used with both the message and hash signature functions.

    This signature scheme is defined by :cite:`FIPS204` as ML-DSA or HashML-DSA.

    When used with `psa_sign_hash()` or `psa_verify_hash()`, the provided ``hash`` parameter is used to select the OID and length  prepended to the hash. 
    
    .. subsection:: Usage

        This is a hash-and-sign algorithm. To calculate a signature, use one of the following approaches:

        *   Call `psa_sign_message()` with the message.

        *   Calculate the hash of the message with `psa_hash_compute()`, or with a multi-part hash operation, using the specified hash algorithm. Then sign the calculated hash with `psa_sign_hash()` When using the `psa_sign_hash()` function the caller should provide the raw hash, the function prepends the OID and length based on the ``hash`` parameter.

        Verifying a signature is similar, using `psa_verify_message()` or `psa_verify_hash()` instead of the signature function.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_MLDSA_KEY_PAIR`
        | :code:`PSA_KEY_TYPE_MLDSA_PUBLIC_KEY` (signature verification only)

    .. admonition:: Implementation note

        The :cite:`FIPS204` standard specifies OIDs for SHA256, SHA512 and SHA128, but permits use of other hashes, provided they offer at least the same security strength as the signature function and have an agreed OID. 
        
Asymmetric signature functions
------------------------------

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

        *   ``alg`` is not supported or is not an asymmetric signature algorithm.
        *   ``key`` is not supported for use with ``alg``.
        *   ``input_length`` is too large for the implementation.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm.
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

        *   ``alg`` is not supported or is not an asymmetric signature algorithm.
        *   ``key`` is not supported for use with ``alg``.
        *   ``input_length`` is too large for the implementation.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm.
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
        Sign an already-calculated hash with a private key.

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

        *   ``alg`` is not supported or is not an asymmetric signature algorithm.
        *   ``key`` is not supported for use with ``alg``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm.
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

    With most signature algorithms that follow the hash-and-sign paradigm, the ``hash`` input to this function is the hash of the message to sign. The algorithm used to compute this hash is encoded in the signature algorithm. For such algorithms, ``hash_length`` must equal the length of the hash output, and the following condition is true:

    .. code-block:: xref

        hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))

    The current version of this specification defines the following signature algorithms with this property: `PSA_ALG_RSA_PKCS1V15_SIGN`, `PSA_ALG_RSA_PSS`, `PSA_ALG_ECDSA`, `PSA_ALG_DETERMINISTIC_ECDSA`, `PSA_ALG_ED25519PH`, and `PSA_ALG_ED448PH`.

    Some hash-and-sign mechanisms apply a padding or encoding to the hash. In such cases, the encoded hash must be passed to this function. The current version of this specification defines one such signature algorithm: `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.

    .. note::
        To perform a hash-and-sign signature algorithm, the hash must be calculated before passing it to this function. This can be done by calling `psa_hash_compute()` or with a multi-part hash operation. The correct hash algorithm to use can be determined using `PSA_ALG_GET_HASH()`.

        Alternatively, to hash and sign a message in a single call, use `psa_sign_message()`.

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

        *   ``alg`` is not supported or is not an asymmetric signature algorithm.
        *   ``key`` is not supported for use with ``alg``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not an asymmetric signature algorithm.
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

    With most signature algorithms that follow the hash-and-sign paradigm, the ``hash`` input to this function is the hash of the message to verify. The algorithm used to compute this hash is encoded in the signature algorithm. For such algorithms, ``hash_length`` must equal the length of the hash output, and the following condition is true:

    .. code-block:: xref

        hash_length == PSA_HASH_LENGTH(PSA_ALG_GET_HASH(alg))

    The current version of this specification defines the following signature algorithms with this property: `PSA_ALG_RSA_PKCS1V15_SIGN`, `PSA_ALG_RSA_PSS`, `PSA_ALG_ECDSA`, `PSA_ALG_DETERMINISTIC_ECDSA`, `PSA_ALG_ED25519PH`, and `PSA_ALG_ED448PH`.

    Some hash-and-sign mechanisms apply a padding or encoding to the hash. In such cases, the encoded hash must be passed to this function. The current version of this specification defines one such signature algorithm: `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`.

    .. note::
        To perform a hash-and-sign verification algorithm, the hash must be calculated before passing it to this function. This can be done by calling `psa_hash_compute()` or with a multi-part hash operation. The correct hash algorithm to use can be determined using `PSA_ALG_GET_HASH()`.

        Alternatively, to hash and verify a message in a single call, use `psa_verify_message()`.

Support macros
--------------

.. macro:: PSA_ALG_IS_SIGN_MESSAGE
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a signature algorithm that can be used with `psa_sign_message()` and `psa_verify_message()`.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a signature algorithm that can be used to sign a message. ``0`` if ``alg`` is a signature algorithm that can only be used to sign an already-calculated hash. ``0`` if ``alg`` is not a signature algorithm. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_SIGN_HASH
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a signature algorithm that can be used with `psa_sign_hash()` and `psa_verify_hash()`.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a signature algorithm that can be used to sign a hash. ``0`` if ``alg`` is a signature algorithm that can only be used to sign a message. ``0`` if ``alg`` is not a signature algorithm. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.


    This includes all algorithms such that `PSA_ALG_IS_HASH_AND_SIGN()` is true, as well as signature algorithms for which the input to `psa_sign_hash()` or `psa_verify_hash()` is not directly a hash, such as `PSA_ALG_IS_RSA_PKCS1V15_SIGN`.

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

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an RSA PSS signature algorithm that requires the standard salt length, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    An RSA PSS signature algorithm that requires the standard salt length is constructed using `PSA_ALG_RSA_PSS()`.

    See also `PSA_ALG_IS_RSA_PSS()` and `PSA_ALG_IS_RSA_PSS_ANY_SALT()`.

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

.. macro:: PSA_ALG_IS_HASH_EDDSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is HashEdDSA.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a HashEdDSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_HASH_AND_SIGN
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a hash-and-sign algorithm that signs exactly the hash value.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a hash-and-sign algorithm that signs exactly the hash value, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

        A wildcard signature algorithm policy, using `PSA_ALG_ANY_HASH`, returns the same value as the signature algorithm parameterised with a valid hash algorithm.

    This macro identifies algorithms that can be used with `psa_sign_hash()` that use the exact message hash value as an input the signature operation. For example, if :code:`PSA_ALG_IS_HASH_AND_SIGN(alg)` is true, the following call sequence is equivalent to :code:`psa_sign_message(key, alg, msg, msg_len, ...)`:

    .. code-block:: xref

        psa_hash_operation_t op = {0};
        uint8_t hash[PSA_HASH_MAX_SIZE];
        size_t hash_len;
        psa_hash_setup(&op, PSA_ALG_GET_HASH(alg));
        psa_hash_update(&op, msg, msg_len);
        psa_hash_finish(&op, hash, sizeof(hash), &hash_len);
        psa_sign_hash(key, alg, hash, hash_len, ...);

    This excludes hash-and-sign algorithms that require a encoded or modified hash for the signature step in the algorithm, such as `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`. For such algorithms, `PSA_ALG_IS_SIGN_HASH()` is true but `PSA_ALG_IS_HASH_AND_SIGN()` is false.

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
        An asymmetric key type. This can be a key pair type or a public key type.
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
