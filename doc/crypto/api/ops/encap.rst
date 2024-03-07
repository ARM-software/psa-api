Key Encapsulation
=================

Elliptic Curve Integrated Encryption Scheme
-------------------------------------------

The Elliptic Curve Integrated Encryption Scheme was fist proposed by Shoup, then imporved by Ballare and Rogaway.

The original specification permitted a number of variants. This specification only defines the version specified in [SEC1], that is with the use of labels and with the label size defined in bytes. 

It is possible that some applications may need to use older versions to interoperate with legacy systems. 
While the application can always implement this using the other algorithm functions provided, however, an implementation may choose to add these as a convenience in the implementation numbering space. 

.. macro:: PSA_ALG_ECIES
    :definition: ((psa_algorithm_t)0x09yyyxxxx)

    .. summary::
       The Elliptic Curve Integrated Encryption Scheme.

       This algorithm can only be used when combined with a key derivation operation using `PSA_ALG_ENCAPSULATION()` in a call to `psa_encapsulate_key()`

       When used as a key's permitted-algorithm policy, the following uses are permitted:

       *   In a call to `psa_encapsulate_key()` or `psa_decapsulate_key()`, with any combined key establishment and key derivation algorithm constructed with `PSA_ALG_ECIES`.

       This encapsulation scheme is defined by :cite-title:`SEC1` §5.5.1 under the name Elliptic Curve Integrated Encryption Scheme.

       .. subsection:: Compatible key types

           | :code:`PSA_KEY_TYPE_ECC_KEY_PAIR(family)`

           where ``family`` is a Weierstrass or Montgomery Elliptic curve family. That is, one of the following values:

           *   ``PSA_ECC_FAMILY_SECT_XX``
           *   ``PSA_ECC_FAMILY_SECP_XX``
           *   `PSA_ECC_FAMILY_FRP`
           *   `PSA_ECC_FAMILY_BRAINPOOL_P_R1`
           *   `PSA_ECC_FAMILY_MONTGOMERY`

.. macro:: PSA_ALG_ENCAPSULATION
    :definition: /* specification-defined value */

    .. summary::
        Macro to build a combined algorithm that chains a key encapsulation with a key derivation.

    .. param:: ka_alg
        A encapsulation algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(ka_alg)` is true.
    .. param:: kdf_alg
        A key derivation algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_KEY_DERIVATION(kdf_alg)` is true.

    .. return::
        The corresponding encapsulation and derivation algorithm.

        Unspecified if ``ka_alg`` is not a supported key establlishment algorithm or ``kdf_alg`` is not a supported key derivation algorithm.

    A combined encapsulation algorithm is used in a call to `psa_encapsulate_key()`.

    The component parts of a encapsulation algorithm can be extracted using `PSA_ALG_ENCAPSULATION_GET_BASE()` and `PSA_ALG_ENCAPSULATION_GET_KDF()`.

    .. subsection:: Compatible key types

        The resulting combined encapsulation algorithm is compatible with the same key types as the raw encapsulation algorithm used to construct it.


Encapsulation
-------------

.. function:: psa_encapsulate_key

    .. summary::
        Generate a new key, emitting it both as a key object and an encapsulation to send to a counter party. 


    .. param:: const psa_key_id_t * counterparty_key
        Public key of the peer. The peer key must be in the same format that `psa_import_key()` accepts for the public key type corresponding to the type of ``private_key``. That is, this function performs the equivalent of :code:`psa_import_key(..., peer_key, peer_key_length)`, with key attributes indicating the public key type corresponding to the type of ``private_key``. For example, for ECC keys, this means that peer_key is interpreted as a point on the curve that the private key is on. The standard formats for public keys are documented in the documentation of `psa_export_public_key()`.

    .. param:: const psa_key_id_t * private_key
        Identifier of the key belong to the person performing the encapsulation. 
        It must be an asymmetric key pair. 
        The key must permit the usage `PSA_KEY_USAGE_ENCAPSULATE_KEY`

    .. param:: psa_algorithm_t alg
        The ful encapsulation algorithm to use: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true and :code:`PSA_ALG_IS_RAW_ENCAPSULATION(alg)` .

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
        
    .. param:: uint8_t * encapsulation
        Buffer where the encapsulated key is to be written, ready to be sent to the counterparty.
        
    .. param:: size_t encapsulation_size
        Size of the ``encapsulation`` buffer in bytes.
        This must be at least :code:`PSA_ENCAPSULATION_OUTPUT_SIZE(alg)`.
        A buffer of at least :code:`PSA_ENCAPSULATION_MAX_OUTPUT_SIZE`. is guaranteed not to fial due to buffer size for any supported encapsulation algorithm.
        
    .. param:: size_t * encapsulation_length
        On success, the number of bytes that make up the hash value. This is always :code:`PSA_ENCAPSULATION_OUTPUT_SIZE(alg)`.

    .. return:: psa_status_t

    .. retval:: PSA_SUCCESS
        Success.
        The bytes of ``encapsulation`` contain the encapsulated key and ``output_key`` contains the identifier for the key to be used to encrypt the message. 

    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not an encapsulation algorithm.

    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not a encapsulation algorithm.

    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``encapsulation`` buffer is too small.
        `PSA_ENCAPSULATION_OUTPUT_SIZE()` can be used to determine a sufficient buffer size.
        
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY

    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE

    .. retval:: PSA_ERROR_CORRUPTION_DETECTED

    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.


.. function:: psa_decapsulate_key

    .. summary::
        Uses a private key to decapsulate an encapsulation received from a counter party. 

    .. param:: const psa_key_id_t * counterparty_key
        Public key of the peer. The peer key must be in the same format that `psa_import_key()` accepts for the public key type corresponding to the type of ``private_key``. That is, this function performs the equivalent of :code:`psa_import_key(..., peer_key, peer_key_length)`, with key attributes indicating the public key type corresponding to the type of ``private_key``. For example, for ECC keys, this means that peer_key is interpreted as a point on the curve that the private key is on. The standard formats for public keys are documented in the documentation of `psa_export_public_key()`.

    .. param:: const psa_key_id_t * private_key
        Identifier of the key belonging to the person to whom the encapsulated message has been sent. 
        It must be an asymmetric key pair. 
        The key must permit the usage `PSA_KEY_USAGE_ENCAPSULATE_KEY`

    .. param:: conts uint8_t * encapsulation
        Buffer containing the encapsulated keythat was received from the counterparty.
        
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
        *   

        
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.


Support macros
--------------

.. macro:: PSA_ALG_ENCAPSULATION_GET_BASE
    :definition: /* specification-defined value */

    .. summary::
        Get the raw key encapsulation algorithm from a full encapsulation algorithm.

    .. param:: alg
        A key encapsulation algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

    .. return::
        The underlying raw key encapsulation algorithm if ``alg`` is a key encapsulation algorithm.

        Unspecified if ``alg`` is not a key encapsulation algorithm or if it is not supported by the implementation.

    See also `PSA_ALG_ENCAPSULATION()` and `PSA_ALG_ENCAPSULATION_GET_KDF()`.

.. macro:: PSA_ALG_ENCAPSULATION_GET_KDF
    :definition: /* specification-defined value */

    .. summary::
        Get the key derivation algorithm used in a full encapsulation algorithm.

    .. param:: alg
        A encapsulation algorithm: a value of type `psa_algorithm_t` such that :code:`PSA_ALG_IS_ENCAPSULATION(alg)` is true.

    .. return::
        The underlying key derivation algorithm if ``alg`` is a encapsulation algorithm.

        Unspecified if ``alg`` is not a encapsulation algorithm or if it is not supported by the implementation.

    See also `PSA_ALG_ENCAPSULATION()` and `PSA_ALG_ENCAPSULATION_GET_BASE()`.

.. macro:: PSA_ALG_IS_RAW_ENCAPSULATION
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a raw encapsulation algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a raw encapsulation algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    A raw encapsulation algorithm is one that does not specify a key derivation function. Usually, raw encapsulation algorithms are constructed directly with a ``PSA_ALG_xxx`` macro while non-raw encapsulation algorithms are constructed with `PSA_ALG_ENCAPSULATION()`.

    The raw encapsulation algorithm can be extracted from a full encapsulation algorithm identifier using `PSA_ALG_ENCAPSULATION_GET_BASE()`.

.. macro:: PSA_ALG_IS_ENCAPSULATION
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a full encapsulation algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a full encapsulation algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    A full  encapsulation algorithm is one that specifies a key derivation function as well as an encapsulation function. Usually, encapsulation algorithms are constructed with `PSA_ALG_ENCAPSULATION()` while non-raw encapsulation algorithms are constructed directly with a ``PSA_ALG_xxx`` macro.

    The raw encapsulation algorithm can be extracted from a full encapsulation algorithm identifier using `PSA_ALG_ENCAPSULATION_GET_BASE()`.


.. macro:: PSA_ALG_IS_ECIES
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an Elliptic Curve Integrated Encryption Scheme algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an Elliptic Curve Integrated Encryption Scheme algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported key agreement algorithm identifier.

    This includes the raw Elliptic Curve Integrated Encryption Scheme algorithm as well as Elliptic Curve Integrated Encryption Scheme followed by any supporter key derivation algorithm.

.. macro:: PSA_ENCAPSULATION_OUTPUT_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient output buffer size for `psa_encapsulate_key()`.

    .. param:: key_type
        A supported key type.
    .. param:: key_bits
        The size of the key in bits.

    .. return::
        A sufficient output buffer size for the specified key type and size. An implementation can return either ``0`` or a correct size for a key type and size that it recognizes, but does not support. If the parameters are not valid, the return value is unspecified.

    If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate_key()` will not fail due to an insufficient buffer size. The actual size of the output might be smaller in any given call.

    See also `PSA_ENCAPSULATION_OUTPUT_MAX_SIZE`.

.. macro:: PSA_ENCAPSULATION_OUTPUT_MAX_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient output buffer size for `psa_encapsulate_key()`, for any of the supported key types and encapsulation algorithms.

    If the size of the output buffer is at least this large, it is guaranteed that `psa_encapsulate_key()` will not fail due to an insufficient buffer size.

    See also `PSA_ENCAPSULATION_OUTPUT_SIZE()`.




