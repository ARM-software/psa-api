Key Encapsulation
=================

A key encapsulation effectively combines an ephemeral asymmetric key exchange, key derivation and a authenticated symmetric encryption. 

As the exact details of the key derivation stage depends on the protocol used, the encapsulation and decapsulation functions only perform the asymmetric portion. 

Encapsulation takes the counterparties public key, generates a new key pair, and emits the public key. It also creates a raw and an encapsulated seed value. 

The raw seed can then be passed to a KDF function to produce the symmetric encryption key or keys. 

The public key, encapsulated key and encrypted message can be sent to the counter party. 

Decapsulation uses a private half of a key pair, with the public key and encapsulated seed received from the sender and recreated the raw seed. They can then use the same KDF to creates the keys needed to verify and decrypt the message.

Elliptic Curve Integrated Encryption Scheme
-------------------------------------------

The Elliptic Curve Integrated Encryption Scheme was fist proposed by Shoup, then improved by Ballare and Rogaway.

The original specification permitted a number of variants. This specification only defines the version specified in [SEC1], that is with the use of labels and with the label size defined in bytes. 

It is possible that some applications may need to use older versions to interoperate with legacy systems. 

While the application can always implement this using the other algorithm functions provided, however, an implementation may choose to add these as a convenience in the implementation numbering space. 

.. macro:: PSA_ALG_ECIES_SEC1
    :definition: ((psa_algorithm_t)0x09yyyxxxx)

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

PSA Crypto supports Module Lattice Encapsulation as defined in :city:`FIPS 203`.

.. macro:: PSA_ALG_MLKEM
    :definition: ((psa_algorithm_t)0x09yyyxxxx)

    .. summary::
       Module Lattice Encapsulation.

       When used as a key's permitted-algorithm policy, the following uses are permitted:

       *   In a call to `psa_encapsulate()` or `psa_decapsulate()`.

       .. subsection:: Compatible key types

           | :code:`PSA_KEY_TYPE_MLKEM`

.. _encapsulation-algorithms:

Encapsulation Algorithms
------------------------
.. function:: psa_encapsulate

    .. summary::
        Generate a new key pair and a use that to encapsulate a new secret value, emitting it both as a key object and an encapsulation to send to a counter party along with the public key from the ephemeral key pair. Depending on the protocol, this key may be used directly or may need to be passed to a KDF to derive encryption and authentication keys. 

    .. param:: const psa_key_id_t * counterparty_key
        The identifier for the public key of the peer. You must have previously imported this key using `psa_import_key()`, and specified the key attributes for the public key type corresponding to the type required for the encapsulation, and the usage usage `PSA_KEY_USAGE_ENCAPSULATE`.

    .. param:: uint8_t * ephemeral_public_key
        Buffer where the ephemeral public key key is to be written, ready to be sent to the counterparty. The content of the buffer will be in the same format as `psa_export_key()` for a key of the same type as ``counterparty_key``.
        
    .. param:: size_t ephemeral_public_key_size
        Size of the ``ephemeral_public_key`` buffer in bytes.
        This must be at least :code:`PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(alg)`.
        A buffer of at least :code:`PSA_EXPORT_PUBLIC_KEY_MAX_OUTPUT_SIZE`. is guaranteed not to fail due to buffer size for any supported encapsulation algorithm.

    .. param:: psa_algorithm_t alg
        The ful encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true and :code:`PSA_ALG_IS_RAW_ENCAPSULATION(alg)` is false .

    .. param:: const psa_key_attributes_t * attributes
        The attributes for the new symmetric key.
        This function uses the attributes as follows:

        *   The key type is required. It cannot be an asymmetric public key.
        *   The key size is required. It must be a valid size for the key type.
        *   The key permitted-algorithm policy is required for keys that will be used for a cryptographic operation, see :secref:`permitted-algorithms`.
        *   The key usage flags define what operations are permitted with the key, see :secref:`key-usage-flags`.
        *   The key lifetime and identifier are required for a persistent key.
        
        .. note::
            This is an input parameter: it is not updated with the final key attributes. The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.
        
    .. param:: psa_key_id_t * output_key
        On success, an identifier for the newly created key. `PSA_KEY_ID_NULL` on failure.
        
    .. param:: uint8_t * encapsulation
        Buffer where the encapsulated key is to be written, ready to be sent to the counterparty.
        
    .. param:: size_t encapsulation_size
        Size of the ``encapsulation`` buffer in bytes.
        This must be at least :code:`PSA_ENCAPSULATION_OUTPUT_SIZE(alg)`.
        A buffer of at least :code:`PSA_ENCAPSULATION_MAX_OUTPUT_SIZE`. is guaranteed not to fail due to buffer size for any supported encapsulation algorithm.
        
    .. param:: size_t * encapsulation_length
        On success, the number of bytes that make up the hash value. This is always :code:`PSA_ENCAPSULATION_OUTPUT_SIZE(alg)`.

    .. return:: psa_status_t

    .. retval:: PSA_SUCCESS
        Success.
        The bytes of ``encapsulation`` contain the encapsulated key, the bytes of ``ephemeral_public_key`` contain the public key and ``output_key`` contains the identifier for the key to be used to encrypt the message. 

    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not an encapsulation algorithm.

    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not a encapsulation algorithm.

    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``encapsulation`` or the ``ephemeral_public_key`` buffer is too small.

    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY

    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE

    .. retval:: PSA_ERROR_CORRUPTION_DETECTED

    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

.. function:: psa_decapsulate

    .. summary::
        Uses a private key to decapsulate an encapsulated key received from a counter party. Depending on the protocol, this key may be used directly or may need to be passed to a KDF to derive encryption and authentication keys. 

    .. param:: const psa_key_id_t * peer_key
        Public key of the peer. The peer key must be in the same format that `psa_import_key()` accepts for the public key type corresponding to the type of ``private_key``. That is, this function performs the equivalent of :code:`psa_import_key(..., peer_key, peer_key_length)`, with key attributes indicating the public key type corresponding to the type of ``private_key``. For example, for ECC keys, this means that peer_key is interpreted as a point on the curve that the private key is on. The standard formats for public keys are documented in the documentation of `psa_export_public_key()`.
        
    .. param:: size_t peer_key_length
        Size of the ``encapsulation`` buffer in bytes.
        
    .. param:: const psa_key_id_t * private_key
        Identifier of the key belonging to the person receiving the encapsulated message. 
        It must be an asymmetric key pair. 
        The private half of the key pair must permit the usage `PSA_KEY_USAGE_DECAPSULATE`

    .. param:: conts uint8_t * encapsulation
        Buffer containing the encapsulated key that was received from the counterparty.
        
    .. param:: size_t encapsulation_size
        Size of the ``encapsulation`` buffer in bytes.

    .. param:: psa_algorithm_t alg
        The encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

    .. param:: const psa_key_attributes_t * attributes
        The attributes for the new key.
        This function uses the attributes as follows:

        *   The key type is required. It cannot be an asymmetric public key.
        *   The key size is required. It must be a valid size for the key type.
        *   The key permitted-algorithm policy is required for keys that will be used for a cryptographic operation, see :secref:`permitted-algorithms`.
        *   The key usage flags define what operations are permitted with the key, see :secref:`key-usage-flags`.
        *   The key lifetime and identifier are required for a persistent key.

        .. note::
            This is an input parameter: it is not updated with the final key attributes. The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.
        
    .. param:: psa_key_id_t * output_key
        On success, an identifier for the newly created key. `PSA_KEY_ID_NULL` on failure.
        
    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.

    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not an encapsulation algorithm.

    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not an encapsulation algorithm.
                
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
        Sufficient output buffer size for `psa_encapsulate()`.

    .. param:: key_type
        A supported key type.
    .. param:: key_bits
        The size of the key in bits.

    .. return::
        A sufficient output buffer size for the specified key type and size. An implementation can return either ``0`` or a correct size for a key type and size that it recognizes, but does not support. If the parameters are not valid, the return value is unspecified.

    If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate()` will not fail due to an insufficient buffer size. The actual size of the output might be smaller in any given call.

    See also `PSA_ENCAPSULATION_OUTPUT_MAX_SIZE`.

.. macro:: PSA_ENCAPSULATION_OUTPUT_MAX_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient output buffer size for `psa_encapsulate()`, for any of the supported key types and encapsulation algorithms.

    If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate()` will not fail due to an insufficient buffer size.

    See also `PSA_ENCAPSULATION_OUTPUT_SIZE()`.

