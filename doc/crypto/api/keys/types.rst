.. SPDX-FileCopyrightText: Copyright 2018-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 13

.. _key-types:

Key types
=========

Key type encoding
-----------------

.. typedef:: uint16_t psa_key_type_t

    .. summary::
        Encoding of a key type.

    This is a structured bitfield that identifies the category and type of key. The range of key type values is divided as follows:

    :code:`PSA_KEY_TYPE_NONE == 0`
        Reserved as an invalid key type.
    :code:`0x0001 – 0x7fff`
        Specification-defined key types.
        Key types defined by this standard always have bit 15 clear.
        Unallocated key type values in this range are reserved for future use.
    :code:`0x8000 – 0xffff`
        Implementation-defined key types.
        Implementations that define additional key types must use an encoding with bit 15 set.
        The related support macros will be easier to write if these key encodings also respect the bitwise structure used by standard encodings.

    The :secref:`appendix-encodings` appendix provides a full definition of the key type encoding.

.. macro:: PSA_KEY_TYPE_NONE
    :definition: ((psa_key_type_t)0x0000)

    .. summary::
        An invalid key type value.

    Zero is not the encoding of any key type.

Key categories
--------------

.. macro:: PSA_KEY_TYPE_IS_UNSTRUCTURED
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an unstructured array of bytes.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

    This encompasses both symmetric keys and non-key data.

    See :secref:`symmetric-keys` for a list of symmetric key types.

.. macro:: PSA_KEY_TYPE_IS_ASYMMETRIC
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is asymmetric: either a key pair or a public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

    See :secref:`asymmetric-keys` for a list of asymmetric key types.

.. macro:: PSA_KEY_TYPE_IS_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is the public part of a key pair.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a key pair containing a private part and a public part.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.


.. _symmetric-keys:

Symmetric keys
--------------

.. macro:: PSA_KEY_TYPE_RAW_DATA
    :definition: ((psa_key_type_t)0x1001)

    .. summary::
        Raw data.

    A "key" of this type cannot be used for any cryptographic operation. Applications can use this type to store arbitrary data in the keystore.

    The bit size of a raw key must be a non-zero multiple of 8. The maximum size of a raw key is :scterm:`IMPLEMENTATION DEFINED`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_HKDF` (non-secret inputs)
        | `PSA_ALG_HKDF_EXPAND` (non-secret inputs)
        | `PSA_ALG_HKDF_EXTRACT` (non-secret inputs)
        | `PSA_ALG_TLS12_PRF` (non-secret inputs)
        | `PSA_ALG_TLS12_PSK_TO_MS` (non-secret inputs)

.. macro:: PSA_KEY_TYPE_HMAC
    :definition: ((psa_key_type_t)0x1100)

    .. summary::
        HMAC key.

    The key policy determines which underlying hash algorithm the key can be used for.

    The bit size of an HMAC key must be a non-zero multiple of 8. An HMAC key is typically the same size as the output of the underlying hash algorithm. An HMAC key that is longer than the block size of the underlying hash algorithm will be hashed before use.

    When an HMAC key is created that is longer than the block size, it is :scterm:`implementation defined` whether the implementation stores the original HMAC key, or the hash of the HMAC key. If the hash of the key is stored, the key size reported by `psa_get_key_attributes()` will be the size of the hashed key.

    .. note::

        :code:`PSA_HASH_LENGTH(alg)` provides the output size of hash algorithm ``alg``, in bytes.

        :code:`PSA_HASH_BLOCK_LENGTH(alg)` provides the block size of hash algorithm ``alg``, in bytes.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_HMAC`

.. macro:: PSA_KEY_TYPE_DERIVE
    :definition: ((psa_key_type_t)0x1200)

    .. summary::
        A secret for key derivation.

    This key type is for high-entropy secrets only. For low-entropy secrets, `PSA_KEY_TYPE_PASSWORD` should be used instead.

    These keys can be used in the `PSA_KEY_DERIVATION_INPUT_SECRET` or `PSA_KEY_DERIVATION_INPUT_PASSWORD` input step of key derivation algorithms.

    The key policy determines which key derivation algorithm the key can be used for.

    The bit size of a secret for key derivation must be a non-zero multiple of 8. The maximum size of a secret for key derivation is :scterm:`IMPLEMENTATION DEFINED`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_HKDF` (secret input)
        | `PSA_ALG_HKDF_EXPAND` (secret input)
        | `PSA_ALG_HKDF_EXTRACT` (secret input)
        | `PSA_ALG_TLS12_PRF` (secret input)
        | `PSA_ALG_TLS12_PSK_TO_MS` (secret input)

.. macro:: PSA_KEY_TYPE_PASSWORD
    :definition: ((psa_key_type_t)0x1203)

    .. summary::
        A low-entropy secret for password hashing or key derivation.

    This key type is suitable for passwords and passphrases which are typically intended to be memorizable by humans, and have a low entropy relative to their size.
    It can be used for randomly generated or derived keys with maximum or near-maximum entropy, but `PSA_KEY_TYPE_DERIVE` is more suitable for such keys.
    It is not suitable for passwords with extremely low entropy, such as numerical PINs.

    These keys can be used in the `PSA_KEY_DERIVATION_INPUT_PASSWORD` input step of key derivation algorithms.
    Algorithms that accept such an input were designed to accept low-entropy secret and are known as *password hashing* or *key stretching* algorithms.

    These keys cannot be used in the `PSA_KEY_DERIVATION_INPUT_SECRET` input step of key derivation algorithms, as the algorithms expect such an input to have high entropy.

    The key policy determines which key derivation algorithm the key can be used for, among the permissible subset defined above.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_PBKDF2_HMAC()` (password input)
        | `PSA_ALG_PBKDF2_AES_CMAC_PRF_128` (password input)

.. macro:: PSA_KEY_TYPE_PASSWORD_HASH
    :definition: ((psa_key_type_t)0x1205)

    .. summary::
        A secret value that can be used to verify a password hash.

    The key policy determines which key derivation algorithm the key can be used for, among the same permissible subset as for `PSA_KEY_TYPE_PASSWORD`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_PBKDF2_HMAC()` (key output and verification)
        | `PSA_ALG_PBKDF2_AES_CMAC_PRF_128` (key output and verification)

.. macro:: PSA_KEY_TYPE_PEPPER
    :definition: ((psa_key_type_t)0x1206)

    .. summary::
        A secret value that can be used when computing a password hash.

    The key policy determines which key derivation algorithm the key can be used for, among the subset of algorithms that can use pepper.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_PBKDF2_HMAC()` (salt input)
        | `PSA_ALG_PBKDF2_AES_CMAC_PRF_128` (salt input)

.. macro:: PSA_KEY_TYPE_AES
    :definition: ((psa_key_type_t)0x2400)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the AES block cipher.

    The size of the key is related to the AES algorithm variant. For algorithms except the XTS block cipher mode, the following key sizes are used:

    *   AES-128 uses a 16-byte key : ``key_bits = 128``
    *   AES-192 uses a 24-byte key : ``key_bits = 192``
    *   AES-256 uses a 32-byte key : ``key_bits = 256``

    For the XTS block cipher mode (`PSA_ALG_XTS`), the following key sizes are used:

    *   AES-128-XTS uses two 16-byte keys : ``key_bits = 256``
    *   AES-192-XTS uses two 24-byte keys : ``key_bits = 384``
    *   AES-256-XTS uses two 32-byte keys : ``key_bits = 512``

    The AES block cipher is defined in :cite-title:`FIPS197`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_CBC_MAC`
        | `PSA_ALG_CMAC`
        | `PSA_ALG_CTR`
        | `PSA_ALG_CFB`
        | `PSA_ALG_OFB`
        | `PSA_ALG_XTS`
        | `PSA_ALG_CBC_NO_PADDING`
        | `PSA_ALG_CBC_PKCS7`
        | `PSA_ALG_ECB_NO_PADDING`
        | `PSA_ALG_CCM`
        | `PSA_ALG_GCM`

.. macro:: PSA_KEY_TYPE_ARIA
    :definition: ((psa_key_type_t)0x2406)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the ARIA block cipher.

    The size of the key is related to the ARIA algorithm variant. For algorithms except the XTS block cipher mode, the following key sizes are used:

    *   ARIA-128 uses a 16-byte key : ``key_bits = 128``
    *   ARIA-192 uses a 24-byte key : ``key_bits = 192``
    *   ARIA-256 uses a 32-byte key : ``key_bits = 256``

    For the XTS block cipher mode (`PSA_ALG_XTS`), the following key sizes are used:

    *   ARIA-128-XTS uses two 16-byte keys : ``key_bits = 256``
    *   ARIA-192-XTS uses two 24-byte keys : ``key_bits = 384``
    *   ARIA-256-XTS uses two 32-byte keys : ``key_bits = 512``

    The ARIA block cipher is defined in :RFC-title:`5794`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_CBC_MAC`
        | `PSA_ALG_CMAC`
        | `PSA_ALG_CTR`
        | `PSA_ALG_CFB`
        | `PSA_ALG_OFB`
        | `PSA_ALG_XTS`
        | `PSA_ALG_CBC_NO_PADDING`
        | `PSA_ALG_CBC_PKCS7`
        | `PSA_ALG_ECB_NO_PADDING`
        | `PSA_ALG_CCM`
        | `PSA_ALG_GCM`

.. macro:: PSA_KEY_TYPE_DES
    :definition: ((psa_key_type_t)0x2301)

    .. summary::
        Key for a cipher or MAC algorithm based on DES or 3DES (Triple-DES).

    The size of the key determines which DES algorithm is used:

    *   Single DES uses an 8-byte key : ``key_bits = 64``
    *   2-key 3DES uses a 16-byte key : ``key_bits = 128``
    *   3-key 3DES uses a 24-byte key : ``key_bits = 192``

    .. warning::
        Single DES and 2-key 3DES are weak and strongly deprecated and are only recommended for decrypting legacy data.

        3-key 3DES is weak and deprecated and is only recommended for use in legacy applications.

    The DES and 3DES block ciphers are defined in :cite-title:`SP800-67`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_CBC_MAC`
        | `PSA_ALG_CMAC`
        | `PSA_ALG_CTR`
        | `PSA_ALG_CFB`
        | `PSA_ALG_OFB`
        | `PSA_ALG_XTS`
        | `PSA_ALG_CBC_NO_PADDING`
        | `PSA_ALG_CBC_PKCS7`
        | `PSA_ALG_ECB_NO_PADDING`

.. macro:: PSA_KEY_TYPE_CAMELLIA
    :definition: ((psa_key_type_t)0x2403)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the Camellia block cipher.

    The size of the key is related to the Camellia algorithm variant. For algorithms except the XTS block cipher mode, the following key sizes are used:

    *   Camellia-128 uses a 16-byte key : ``key_bits = 128``
    *   Camellia-192 uses a 24-byte key : ``key_bits = 192``
    *   Camellia-256 uses a 32-byte key : ``key_bits = 256``

    For the XTS block cipher mode (`PSA_ALG_XTS`), the following key sizes are used:

    *   Camellia-128-XTS uses two 16-byte keys : ``key_bits = 256``
    *   Camellia-192-XTS uses two 24-byte keys : ``key_bits = 384``
    *   Camellia-256-XTS uses two 32-byte keys : ``key_bits = 512``

    The Camellia block cipher is defined in :cite-title:`NTT-CAM` and also described in :RFC-title:`3713`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_CBC_MAC`
        | `PSA_ALG_CMAC`
        | `PSA_ALG_CTR`
        | `PSA_ALG_CFB`
        | `PSA_ALG_OFB`
        | `PSA_ALG_XTS`
        | `PSA_ALG_CBC_NO_PADDING`
        | `PSA_ALG_CBC_PKCS7`
        | `PSA_ALG_ECB_NO_PADDING`
        | `PSA_ALG_CCM`
        | `PSA_ALG_GCM`

.. macro:: PSA_KEY_TYPE_SM4
    :definition: ((psa_key_type_t)0x2405)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the SM4 block cipher.

    For algorithms except the XTS block cipher mode, the SM4 key size is 128 bits (16 bytes).

    For the XTS block cipher mode (`PSA_ALG_XTS`), the SM4 key size is 256 bits (two 16-byte keys).

    The SM4 block cipher is defined in :cite-title:`CSTC0002`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_CBC_MAC`
        | `PSA_ALG_CMAC`
        | `PSA_ALG_CTR`
        | `PSA_ALG_CFB`
        | `PSA_ALG_OFB`
        | `PSA_ALG_XTS`
        | `PSA_ALG_CBC_NO_PADDING`
        | `PSA_ALG_CBC_PKCS7`
        | `PSA_ALG_ECB_NO_PADDING`
        | `PSA_ALG_CCM`
        | `PSA_ALG_GCM`

.. macro:: PSA_KEY_TYPE_ARC4
    :definition: ((psa_key_type_t)0x2002)

    .. summary::
        Key for the ARC4 stream cipher.

    .. warning::
        The ARC4 cipher is weak and deprecated and is only recommended for use in legacy applications.

    The ARC4 cipher supports key sizes between 40 and 2048 bits, that are multiples of 8. (5 to 256 bytes)

    Use algorithm `PSA_ALG_STREAM_CIPHER` to use this key with the ARC4 cipher.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_STREAM_CIPHER`

.. macro:: PSA_KEY_TYPE_CHACHA20
    :definition: ((psa_key_type_t)0x2004)

    .. summary::
        Key for the ChaCha20 stream cipher or the ChaCha20-Poly1305 AEAD algorithm.

    The ChaCha20 key size is 256 bits (32 bytes).

    *   Use algorithm `PSA_ALG_STREAM_CIPHER` to use this key with the ChaCha20 cipher for unauthenticated encryption. See `PSA_ALG_STREAM_CIPHER` for details of this algorithm.

    *   Use algorithm `PSA_ALG_CHACHA20_POLY1305` to use this key with the ChaCha20 cipher and Poly1305 authenticator for AEAD. See `PSA_ALG_CHACHA20_POLY1305` for details of this algorithm.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_STREAM_CIPHER`
        | `PSA_ALG_CHACHA20_POLY1305`


.. _asymmetric-keys:

RSA keys
--------

.. macro:: PSA_KEY_TYPE_RSA_KEY_PAIR
    :definition: ((psa_key_type_t)0x7001)

    .. summary::
        RSA key pair: both the private and public key.

    The size of an RSA key is the bit size of the modulus.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_RSA_OAEP`
        | `PSA_ALG_RSA_PKCS1V15_CRYPT`
        | `PSA_ALG_RSA_PKCS1V15_SIGN`
        | `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`
        | `PSA_ALG_RSA_PSS`
        | `PSA_ALG_RSA_PSS_ANY_SALT`

.. macro:: PSA_KEY_TYPE_RSA_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4001)

    .. summary::
        RSA public key.

    The size of an RSA key is the bit size of the modulus.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_RSA_OAEP` (encryption only)
        | `PSA_ALG_RSA_PKCS1V15_CRYPT` (encryption only)
        | `PSA_ALG_RSA_PKCS1V15_SIGN` (signature verification only)
        | `PSA_ALG_RSA_PKCS1V15_SIGN_RAW` (signature verification only)
        | `PSA_ALG_RSA_PSS` (signature verification only)
        | `PSA_ALG_RSA_PSS_ANY_SALT` (signature verification only)

.. macro:: PSA_KEY_TYPE_IS_RSA
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an RSA key. This includes both key pairs and public keys.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

Elliptic Curve keys
-------------------

.. typedef:: uint8_t psa_ecc_family_t

    .. summary::
        The type of identifiers of an elliptic curve family.

    The curve identifier is required to create an ECC key using the `PSA_KEY_TYPE_ECC_KEY_PAIR()` or `PSA_KEY_TYPE_ECC_PUBLIC_KEY()` macros.

    The specific ECC curve within a family is identified by the ``key_bits`` attribute of the key.

    The range of Elliptic curve family identifier values is divided as follows:

    :code:`0x00 – 0x7f`
        ECC family identifiers defined by this standard.
        Unallocated values in this range are reserved for future use.
    :code:`0x80 – 0xff`
        Implementations that define additional families must use an encoding in this range.

.. macro:: PSA_KEY_TYPE_ECC_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Elliptic curve key pair: both the private and public key.

    The size of an elliptic curve key is the bit size associated with the curve, that is, the bit size of *q* for a curve over a field *F*\ :sub:`q`. See the documentation of each Elliptic curve family for details.

    .. param:: curve
        A value of type `psa_ecc_family_t` that identifies the ECC curve family to be used.

    .. subsection:: Compatible algorithms

        Elliptic curve key pairs can be used in Asymmetric signature and Key agreement algorithms.

        The set of compatible algorithms depends on the Elliptic curve key family. See the Elliptic curve family for details.

.. macro:: PSA_KEY_TYPE_ECC_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Elliptic curve public key.

    .. param:: curve
        A value of type `psa_ecc_family_t` that identifies the ECC curve family to be used.

    The size of an elliptic curve public key is the same as the corresponding private key. See `PSA_KEY_TYPE_ECC_KEY_PAIR()` and the documentation of each Elliptic curve family for details.

    .. subsection:: Compatible algorithms

        Elliptic curve public keys can be used for verification in Asymmetric signature algorithms.

        The set of compatible algorithms depends on the Elliptic curve key family. See each Elliptic curve family for details.

.. macro:: PSA_ECC_FAMILY_SECP_K1
    :definition: ((psa_ecc_family_t) 0x17)

    .. summary::
        SEC Koblitz curves over prime fields.

    This family comprises the following curves:

    *   secp192k1 : ``key_bits = 192``
    *   secp224k1 : ``key_bits = 225``
    *   secp256k1 : ``key_bits = 256``

    They are defined in :cite-title:`SEC2`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_SECP_R1
    :definition: ((psa_ecc_family_t) 0x12)

    .. summary::
        SEC random curves over prime fields.

    This family comprises the following curves:

    *   secp192r1 : ``key_bits = 192``
    *   secp224r1 : ``key_bits = 224``
    *   secp256r1 : ``key_bits = 256``
    *   secp384r1 : ``key_bits = 384``
    *   secp521r1 : ``key_bits = 521``

    They are defined in :cite:`SEC2`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_SECP_R2
    :definition: ((psa_ecc_family_t) 0x1b)

    .. summary::
        .. warning::
            This family of curves is weak and deprecated.

    This family comprises the following curves:

    *   secp160r2 : ``key_bits = 160`` *(Deprecated)*

    It is defined in the superseded :cite-title:`SEC2v1`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_SECT_K1
    :definition: ((psa_ecc_family_t) 0x27)

    .. summary::
        SEC Koblitz curves over binary fields.

    This family comprises the following curves:

    *   sect163k1 : ``key_bits = 163`` *(Deprecated)*
    *   sect233k1 : ``key_bits = 233``
    *   sect239k1 : ``key_bits = 239``
    *   sect283k1 : ``key_bits = 283``
    *   sect409k1 : ``key_bits = 409``
    *   sect571k1 : ``key_bits = 571``

    They are defined in :cite:`SEC2`.

    .. warning::
        The 163-bit curve sect163k1 is weak and deprecated and is only recommended for use in legacy applications.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_SECT_R1
    :definition: ((psa_ecc_family_t) 0x22)

    .. summary::
        SEC random curves over binary fields.

    This family comprises the following curves:

    *   sect163r1 : ``key_bits = 163`` *(Deprecated)*
    *   sect233r1 : ``key_bits = 233``
    *   sect283r1 : ``key_bits = 283``
    *   sect409r1 : ``key_bits = 409``
    *   sect571r1 : ``key_bits = 571``

    They are defined in :cite:`SEC2`.

    .. warning::
        The 163-bit curve sect163r1 is weak and deprecated and is only recommended for use in legacy applications.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_SECT_R2
    :definition: ((psa_ecc_family_t) 0x2b)

    .. summary::
        SEC additional random curves over binary fields.

    This family comprises the following curves:

    *   sect163r2 : ``key_bits = 163`` *(Deprecated)*

    It is defined in :cite:`SEC2`.

    .. warning::
        The 163-bit curve sect163r2 is weak and deprecated and is only recommended for use in legacy applications.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_BRAINPOOL_P_R1
    :definition: ((psa_ecc_family_t) 0x30)

    .. summary::
        Brainpool P random curves.

    This family comprises the following curves:

    *   brainpoolP160r1 : ``key_bits = 160`` *(Deprecated)*
    *   brainpoolP192r1 : ``key_bits = 192``
    *   brainpoolP224r1 : ``key_bits = 224``
    *   brainpoolP256r1 : ``key_bits = 256``
    *   brainpoolP320r1 : ``key_bits = 320``
    *   brainpoolP384r1 : ``key_bits = 384``
    *   brainpoolP512r1 : ``key_bits = 512``

    They are defined in :rfc-title:`5639`.

    .. warning::
        The 160-bit curve brainpoolP160r1 is weak and deprecated and is only recommended for use in legacy applications.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_FRP
    :definition: ((psa_ecc_family_t) 0x33)

    .. summary::
        Curve used primarily in France and elsewhere in Europe.

    This family comprises one 256-bit curve:

    *   FRP256v1 : ``key_bits = 256``

    This is defined by :cite-title:`FRP`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_DETERMINISTIC_ECDSA`
        | `PSA_ALG_ECDSA`
        | `PSA_ALG_ECDSA_ANY`
        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_MONTGOMERY
    :definition: ((psa_ecc_family_t) 0x41)

    .. summary::
        Montgomery curves.

    This family comprises the following Montgomery curves:

    *   Curve25519 : ``key_bits = 255``
    *   Curve448 : ``key_bits = 448``

    Curve25519 is defined in :cite-title:`Curve25519`. Curve448 is defined in :cite-title:`Curve448`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_ECDH` (key pair only)

.. macro:: PSA_ECC_FAMILY_TWISTED_EDWARDS
    :definition: ((psa_ecc_family_t) 0x42)

    .. summary::
        Twisted Edwards curves.

    This family comprises the following twisted Edwards curves:

    *   Edwards25519 : ``key_bits = 255``. This curve is birationally equivalent to Curve25519.
    *   Edwards448 : ``key_bits = 448``. This curve is birationally equivalent to Curve448.

    Edwards25519 is defined in :cite-title:`Ed25519`. Edwards448 is defined in :cite-title:`Curve448`.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_PURE_EDDSA`
        | `PSA_ALG_ED25519PH` (Edwards25519 only)
        | `PSA_ALG_ED448PH` (Edwards448 only)


.. macro:: PSA_KEY_TYPE_IS_ECC
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an elliptic curve key, either a key pair or a public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_ECC_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an elliptic curve key pair.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an elliptic curve public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_ECC_GET_FAMILY
    :definition: /* specification-defined value */

    .. summary::
        Extract the curve family from an elliptic curve key type.

    .. param:: type
        An elliptic curve key type: a value of type `psa_key_type_t` such that :code:`PSA_KEY_TYPE_IS_ECC(type)` is true.

    .. return:: psa_ecc_family_t
        The elliptic curve family id, if ``type`` is a supported elliptic curve key. Unspecified if ``type`` is not a supported elliptic curve key.

Diffie Hellman keys
-------------------

.. typedef:: uint8_t psa_dh_family_t

    .. summary::
        The type of identifiers of a finite-field Diffie-Hellman group family.

    The group family identifier is required to create a finite-field Diffie-Hellman key using the `PSA_KEY_TYPE_DH_KEY_PAIR()` or `PSA_KEY_TYPE_DH_PUBLIC_KEY()` macros.

    The specific Diffie-Hellman group within a family is identified by the ``key_bits`` attribute of the key.

    The range of Diffie-Hellman group family identifier values is divided as follows:

    :code:`0x00 – 0x7f`
        DH group family identifiers defined by this standard.
        Unallocated values in this range are reserved for future use.
    :code:`0x80 – 0xff`
        Implementations that define additional families must use an encoding in this range.

.. macro:: PSA_KEY_TYPE_DH_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Finite-field Diffie-Hellman key pair: both the private key and public key.

    .. param:: group
        A value of type `psa_dh_family_t` that identifies the Diffie-Hellman group family to be used.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_FFDH`

.. macro:: PSA_KEY_TYPE_DH_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Finite-field Diffie-Hellman public key.

    .. param:: group
        A value of type `psa_dh_family_t` that identifies the Diffie-Hellman group family to be used.

    .. subsection:: Compatible algorithms

        None. Finite-field Diffie-Hellman public keys are exported to use in a key agreement algorithm, and the peer key is provided to the `PSA_ALG_FFDH` key agreement algorithm as a buffer of key data.

.. macro:: PSA_DH_FAMILY_RFC7919
    :definition: ((psa_dh_family_t) 0x03)

    .. summary::
        Finite-field Diffie-Hellman groups defined for TLS in RFC 7919.

    This family includes groups with the following key sizes (in bits): 2048, 3072, 4096, 6144, 8192.
    An implementation can support all of these sizes or only a subset.

    Keys is this group can only be used with the `PSA_ALG_FFDH` key agreement algorithm.

    These groups are defined by :rfc-title:`7919#A`.

.. macro:: PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        The key pair type corresponding to a public key type.

    .. param:: type
        A public key type or key pair type.

    .. return::
        The corresponding key pair type. If ``type`` is not a public key or a key pair, the return value is undefined.

    If ``type`` is a key pair type, it will be left unchanged.

.. macro:: PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        The public key type corresponding to a key pair type.

    .. param:: type
        A public key type or key pair type.

    .. return::
        The corresponding public key type. If ``type`` is not a public key or a key pair, the return value is undefined.

    If ``type`` is a public key type, it will be left unchanged.

.. macro:: PSA_KEY_TYPE_IS_DH
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a Diffie-Hellman key, either a key pair or a public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_DH_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a Diffie-Hellman key pair.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_DH_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a Diffie-Hellman public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_DH_GET_FAMILY
    :definition: /* specification-defined value */

    .. summary::
        Extract the group family from a Diffie-Hellman key type.

    .. param:: type
        A Diffie-Hellman key type: a value of type `psa_key_type_t` such that :code:`PSA_KEY_TYPE_IS_DH(type)` is true.

    .. return:: psa_dh_family_t
        The Diffie-Hellman group family id, if ``type`` is a supported Diffie-Hellman key. Unspecified if ``type`` is not a supported Diffie-Hellman key.

Module Lattice keys
-------------------

PSA supports Module Lattice Cryptography as defined in :cite:`FIPS 203` and :cite:`FIPS 204`. 

There are two related, but separate algorithms a key encapsulation method, ML-KEM and a signature method ML-DSA. 

.. macro:: PSA_KEY_TYPE_MLKEM_KEY_PAIR
    :definition: ((psa_key_type_t)0xy001)

    .. summary::
        MLKEM key pair: contains both the decapsulation and encapsulation keys.
        PSA Crypto treats decapsulation keys as private keys and encapsulation keys as public keys. 
        
        The size of an ML-KEM key is specified by the numeric part of the parameter set identifier defined in FIPS 203.
        
        The parameter sets refer to the key strength, the actual size of the key
        
        .. list-table:: Sizes (in bytes) of keys and cipher texts for ML-KEM
           :header-rows: 1

           * - Size
             - Parameter Set
             - Encapsulation key
             - Decapsulation key 
             - Ciphertext

           * - 512
             - ML-KEM-512
             - 800
             - 1632
             - 768
           
           * - 768
             - ML-KEM-768
             - 1184
             - 2400
             - 1088
             
           * - 1024
             - ML-KEM-1024
             - 1568
             - 3168
             - 1568

        In all cases the shared secret produced is 32-bytes, 256-bits long.
        The shared secret can be used directly or passed to a PRF to derive further keys. 

    .. subsection:: Compatible algorithms

        | `PSA_ALG_MLKEM`

.. macro:: PSA_KEY_TYPE_ML_KEM _PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4001)

    .. summary::
        ML-KEM public key.

    The size of an ML-KEM key is the numeric part of the parameter set identifier.

    .. subsection:: Compatible algorithms

        | `PSA_ALG_MLKEM` (encapsulation only)
        | 
.. macro:: PSA_KEY_TYPE_IS_MLKEM
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an ML-KEM key. This includes both key pairs and public keys.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_MLDSA_KEY_PAIR
    :definition: ((psa_key_type_t)0xy001)

    .. summary::
        An ML_DSA key pair: contains both the public and private keys.
        
        The size of an ML-DSA key is specified by the numeric part of the parameter set identifier defined in FIPS 203.
        
        The parameter sets refer to the dimensions of the matrix A, and do not directly define key size.
        
        .. list-table:: Sizes (in bytes) of keys and cipher texts for ML-KEM
           :header-rows: 1

           * - Size
             - Parameter Set
             - Private key
             - Public key 
             - Signature
           
           * - 44
             - ML-DSA-44
             - 2560
             - 1312
             - 2420
             
           * - 65
             - ML-DSA-65
             - 4032
             - 1952
             - 3309
             
           * - 87
             - ML-DSA-87
             - 4896
             - 2592
             - 4627

    .. subsection:: Compatible algorithms

        | `PSA_ALG_MLDSA_SIGN`

.. macro:: PSA_KEY_TYPE_MLDSA_PUBLIC_KEY
    :definition: ((psa_key_type_t)0xy001)

    .. summary::
        A ML-DSA public key.
        
        The size of an ML-DSA key is specified by the numeric part of the parameter set identifier defined in FIPS 203.
        
        The parameter sets refer to the key strength, the actual size of the key 

    .. subsection:: Compatible algorithms

        | `PSA_ALG_MLDSA_SIGN` (verification only)

.. macro:: PSA_KEY_TYPE_IS_MLDSA
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an ML-SIG key. This includes both key pairs and public keys.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

Attribute accessors
-------------------

.. function:: psa_set_key_type

    .. summary::
        Declare the type of a key.

    .. param:: psa_key_attributes_t * attributes
        The attribute object to write to.
    .. param:: psa_key_type_t type
        The key type to write. If this is `PSA_KEY_TYPE_NONE`, the key type in ``attributes`` becomes unspecified.

    .. return:: void

    This function overwrites any key type previously set in ``attributes``.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.


.. function:: psa_get_key_type

    .. summary::
        Retrieve the key type from key attributes.

    .. param:: const psa_key_attributes_t * attributes
        The key attribute object to query.

    .. return:: psa_key_type_t
        The key type stored in the attribute object.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.


.. function:: psa_get_key_bits

    .. summary::
        Retrieve the key size from key attributes.

    .. param:: const psa_key_attributes_t * attributes
        The key attribute object to query.

    .. return:: size_t
        The key size stored in the attribute object, in bits.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.


.. function:: psa_set_key_bits

    .. summary::
        Declare the size of a key.

    .. param:: psa_key_attributes_t * attributes
        The attribute object to write to.
    .. param:: size_t bits
        The key size in bits. If this is ``0``, the key size in ``attributes`` becomes unspecified. Keys of size ``0`` are not supported.

    .. return:: void

    This function overwrites any key size previously set in ``attributes``.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.
