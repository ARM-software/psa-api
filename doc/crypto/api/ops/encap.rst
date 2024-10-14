.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 31

.. _encapsulation:

Key Encapsulation
=================

A key encapsulation effectively combines an ephemeral asymmetric key exchange, key derivation and a authenticated symmetric encryption. 

As the exact details of the key derivation stage depends on the protocol used, the encapsulation and decapsulation functions only perform the asymmetric portion. 

Encapsulation takes the counterparties public key, generates a new key pair, and emits a raw seed and encapsulated data to transferred to the other participant:

For ECIES, the data to transfer includes the ephemeral public key and encapsulated seed.
For ML-KEM, the data is a ciphertext of the PKE, conveying a random seed for the shared secret.

The raw seed can then be passed to a KDF function to produce the symmetric encryption key or keys. 

The encapsulated data and encrypted message can be sent to the counter party. 

Decapsulation uses a private half of a key pair, with the encapsulated data received from the sender and recreated the raw seed. They can then use the same KDF to creates the keys needed to verify and decrypt the message.

Elliptic Curve Integrated Encryption Scheme
-------------------------------------------

The Elliptic Curve Integrated Encryption Scheme was fist proposed by Shoup, then improved by Ballare and Rogaway.

The original specification permitted a number of variants. This specification only defines the version specified in :cite-title:`SEC1`, that is with the use of labels and with the label size defined in bytes. 

It is possible that some applications may need to use older versions to interoperate with legacy systems. 

While the application can always implement this using the other algorithm functions provided, however, a specific implementation may choose to add these as a convenience with an Implementation-defined algorithm identifier.

.. macro:: PSA_ALG_ECIES_SEC1
:definition: ((psa_algorithm_t)0x0b000100)

.. summary::
The Elliptic Curve Integrated Encryption Scheme.

When used as a key's permitted-algorithm policy, the following uses are permitted:

*   In a call to `psa_encapsulate()` or `psa_decapsulate()`.

This encapsulation scheme is defined by :cite-title:`SEC1` §5.5.1 under the name Elliptic Curve Integrated Encryption Scheme.

This uses Cofactor ECDH. 

.. subsection:: Compatible key types

| :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)`

where ``family`` is a Weierstrass or Montgomery Elliptic curve family. That is, one of the following values:

*   ``PSA_ECC_FAMILY_SECT_XX``
*   ``PSA_ECC_FAMILY_SECP_XX``
*   `PSA_ECC_FAMILY_FRP`
*   `PSA_ECC_FAMILY_BRAINPOOL_P_R1`
*   `PSA_ECC_FAMILY_MONTGOMERY`

Module Lattice Encapsulation
----------------------------

The |API| supports Module Lattice Encapsulation as defined in :cite:`FIPS203`.

.. macro:: PSA_ALG_ML_KEM
:definition: ((psa_algorithm_t)0x0b000200)

.. summary::
Module Lattice Encapsulation.

When used as a key's permitted-algorithm policy, the following uses are permitted:

*   In a call to `psa_encapsulate()` or `psa_decapsulate()`.

.. subsection:: Compatible key types

| :code:`PSA_KEY_TYPE_ML-KEM`

.. _encapsulation-algorithms:

Encapsulation Algorithms
------------------------
.. function:: psa_encapsulate

.. summary::
Generate a new secret value, emitting it both as a key object and as data to send to a counter party. Depending on the protocol, this value may be used directly or may need to be passed to a KDF to derive encryption and authentication keys. 

.. param:: const psa_key_id_t * counterparty_key
The identifier for the public key of the peer. You must have previously imported this key using `psa_import_key()`, and specified the key attributes for the public key type corresponding to the type required for the encapsulation, and the usage usage `PSA_KEY_USAGE_ENCAPSULATE`.

.. param:: psa_algorithm_t alg
The encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

.. param:: const psa_key_attributes_t * attributes
The attributes for the new symmetric key.
This function uses the attributes as follows:

*   The key type.
    All encapsulation algorithms can output a key of type :code:`PSA_KEY_TYPE_DERIVE` or :code:`PSA_KEY_TYPE_HMAC`.
    encapsulation algorithms that produce a pseudo-random shared secret, can also output block-cipher key types, for example :code:`PSA_KEY_TYPE_AES`.
    Refer to the documentation of individual encapsulation  algorithms for more information.

The following attributes must be set for keys used in cryptographic operations:

*   The key permitted-algorithm policy, see :secref:`permitted-algorithms`.
*   The key usage flags, see :secref:`key-usage-flags`.

The following attributes must be set for keys that do not use the default volatile lifetime:

*   The key lifetime, see :secref:`key-lifetimes`.
*   The key identifier is required for a key with a persistent lifetime, see :secref:`key-identifiers`.

    The following attributes are optional:

    *   If the key size is nonzero, it must be equal to the size of the encapsulation shared secret.

.. note::
This is an input parameter: it is not updated with the final key attributes. The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.

.. param:: psa_key_id_t output_key
On success, an identifier for the newly created key. `PSA_KEY_ID_NULL` on failure. 

Its location, policy, and type are taken from ``attributes``.

The size of the returned key is always the bit-size of the shared secret, rounded up to a whole number of bytes. The size is of the shared secret is dependent on the encapsulation algorithm and cipher suite.

It is recommended that this key is used as an input to a key derivation operation to produce additional cryptographic keys.

For some encapsulation algorithms, the shared secret is also suitable for use as a key in cryptographic operations such as encryption.
Refer to the documentation of individual encapsulation algorithms for more information.

.. param:: uint8_t * encapsulation
Buffer where the encapsulated data is to be written, ready to be sent to the counterparty.

.. param:: size_t encapsulation_size
Size of the ``encapsulation`` buffer in bytes.
This must be at least :code:`PSA_ENCAPSULATION_OUTPUT_SIZE(alg)`.
A buffer of at least :code:`PSA_ENCAPSULATION_MAX_OUTPUT_SIZE`. is guaranteed not to fail due to buffer size for any supported encapsulation algorithm.

.. param:: size_t * encapsulation_length
On success, the number of bytes that make up the encapsulated data value. This is always less then :code:`PSA_ENCAPSULATION_OUTPUT_SIZE(alg)`.

.. return:: psa_status_t

.. retval:: PSA_SUCCESS
Success.
The bytes of ``encapsulation`` contain the data to be sent to the counterparty and ``key`` contains the identifier for the key to be used to encrypt the message. 

.. retval:: PSA_ERROR_NOT_SUPPORTED
The following conditions can result in this error:

*   ``alg`` is not supported or is not an encapsulation algorithm.
*   ``counterparty_key`` is not compatible with ``alg``
*   The output key attributes, as a whole, are not supported, either by the implementation in general or in the specified storage location.
.. retval:: PSA_ERROR_INVALID_ARGUMENT
The following conditions can result in this error:

*   ``alg`` is not a encapsulation algorithm.
*   ``counterparty_key`` is not a valid public key
*   ``counterparty_key`` is not compatible with ``alg``
*   The output key attributes in ``attributes`` are not valid :
    -   The key type is not valid for key agreement output.
    -   The key size is nonzero, and is not the size of the shared secret.
    -   The key lifetime is invalid.
    -   The key identifier is not valid for the key lifetime.
    -   The key usage flags include invalid values.
    -   The key's permitted-usage algorithm is invalid.
    -   The key attributes, as a whole, are invalid.

.. retval:: PSA_ERROR_BUFFER_TOO_SMALL
The size of the ``encapsulation`` buffer is too small.

.. retval:: PSA_ERROR_INSUFFICIENT_MEMORY

.. retval:: PSA_ERROR_COMMUNICATION_FAILURE

.. retval:: PSA_ERROR_CORRUPTION_DETECTED

.. retval:: PSA_ERROR_BAD_STATE
The library requires initializing by a call to `psa_crypto_init()`.

.. function:: psa_decapsulate

.. summary::
Uses a private key to decapsulate a shared secret from encapsulated data received from a counter party. Depending on the protocol, this secret may be used suitabkle to be used directly, or may need to be passed to a KDF to derive encryption and authentication keys. 

.. param:: conts uint8_t * encapsulation
Buffer containing the encapsulation that was received from the counterparty.

.. param:: size_t encapsulation_length
Size of the ``encapsulation`` buffer in bytes.

.. param:: const psa_key_id_t key
Identifier of the key belonging to the person receiving the encapsulated message. 
It must be an asymmetric key pair. 
The private half of the key pair must permit the usage `PSA_KEY_USAGE_DECAPSULATE`

.. param:: psa_algorithm_t alg
The encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

.. param:: const psa_key_attributes_t * attributes
The attributes for the new symmetric key.
This function uses the attributes as follows:

*   The key type.
    All encapsulation algorithms can output a key of type :code:`PSA_KEY_TYPE_DERIVE` or :code:`PSA_KEY_TYPE_HMAC`.
    encapsulation algorithms that produce a pseudo-random shared secret, can also output block-cipher key types, for example :code:`PSA_KEY_TYPE_AES`.
    Refer to the documentation of individual encapsulation  algorithms for more information.

The following attributes must be set for keys used in cryptographic operations:

*   The key permitted-algorithm policy, see :secref:`permitted-algorithms`.
*   The key usage flags, see :secref:`key-usage-flags`.

The following attributes must be set for keys that do not use the default volatile lifetime:

*   The key lifetime, see :secref:`key-lifetimes`.
*   The key identifier is required for a key with a persistent lifetime, see :secref:`key-identifiers`.

    The following attributes are optional:

    *   If the key size is nonzero, it must be equal to the size of the encapsulation shared secret.

.. note::
This is an input parameter: it is not updated with the final key attributes. The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.

.. param:: psa_key_id_t * output_key

On success, an identifier for the newly created key. `PSA_KEY_ID_NULL` on failure. 

Its location, policy, and type are taken from ``attributes``.

The size of the returned key is always the bit-size of the shared secret, rounded up to a whole number of bytes. The size is of the shared secret is dependent on the encapsulation algorithm and cipher suite.

It is recommended that this key is used as an input to a key derivation operation to produce additional cryptographic keys.

For some encapsulation algorithms, the shared secret is also suitable for use as a key in cryptographic operations such as encryption.
Refer to the documentation of individual encapsulation algorithms for more information.

*  The output is not verified. Key confirmation can be done to verify that both parties have the same key.
*  The appropriate steps to take are defined by the higher level protocol that is using the encapsulation method.

.. return:: psa_status_t
.. retval:: PSA_SUCCESS
Success.
``output_key`` contains the identifier for the shared secret. Depending on the protocol, this value may be used directly to decrypt the message, or may need to be passed to a KDF to derive decryption and authentication keys. 

In some algorithms, decapsulation failure cannot be detected, and simply results in incorrect output. Such failures will return `PSA_SUCCESS`. 

.. retval:: PSA_ERROR_NOT_SUPPORTED
The following conditions can result in this error:

The following conditions can result in this error:

*   ``alg`` is not supported or is not an encapsulation algorithm.
*   ``counterparty_key`` is not compatible with ``alg``
*   The output key attributes, as a whole, are not supported, either by the implementation in general or in the specified storage location.
.. retval:: PSA_ERROR_INVALID_ARGUMENT
The following conditions can result in this error:

*   ``alg`` is not a encapsulation algorithm.
*   ``counterparty_key`` is not a valid public key
*   ``counterparty_key`` is not compatible with ``alg``
*   The output key attributes in ``attributes`` are not valid :
    -   The key type is not valid for key agreement output.
    -   The key size is nonzero, and is not the size of the shared secret.
    -   The key lifetime is invalid.
    -   The key identifier is not valid for the key lifetime.
    -   The key usage flags include invalid values.
    -   The key's permitted-usage algorithm is invalid.
    -   The key attributes, as a whole, are invalid.
*   ``encapsulation`` is not obviously valid for the selected algorithm, for example, the implementation can detect that it is the incorrect length. Or, for ECIES, the public key is not a valid point on the curve. 

.. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
.. retval:: PSA_ERROR_COMMUNICATION_FAILURE
.. retval:: PSA_ERROR_CORRUPTION_DETECTED
.. retval:: PSA_ERROR_BAD_STATE
The library requires initializing by a call to `psa_crypto_init()`.

Support macros
--------------

.. macro:: PSA_ALG_IS_ENCAPSULATION
:definition: /* specification-defined value */

.. summary::
Whether the specified algorithm is a full encapsulation algorithm.

.. param:: alg
An algorithm identifier: a value of type `psa_algorithm_t`.

.. return::
``1`` if ``alg`` is a full encapsulation algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ENCAPSULATION_OUTPUT_SIZE
:definition: /* implementation-defined value */

.. summary::
Sufficient output buffer size for `psa_encapsulate()` for the given algorithm and key.

.. param:: key_type
A supported key type.

.. param:: key_bits
The size of the key in bits.

.. param:: alg
        An encapsulation algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

.. return::
A sufficient output buffer size for the specified key type and size. An implementation can return either ``0`` or a correct size for an algorithm, key type and size that it recognizes, but does not support. If the parameters are not valid, the return value is unspecified.

If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate()` will not fail due to an insufficient buffer size. The actual size of the output might be smaller in any given call.

See also `PSA_ENCAPSULATION_OUTPUT_MAX_SIZE`.

.. macro:: PSA_ENCAPSULATION_OUTPUT_MAX_SIZE
:definition: /* implementation-defined value */

.. summary::
Sufficient output buffer size for `psa_encapsulate()`, for any of the supported key types and encapsulation algorithms.

If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate()` will not fail due to an insufficient buffer size.

See also `PSA_ENCAPSULATION_OUTPUT_SIZE()`.

