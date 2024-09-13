.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 30

.. _key-wrap:

Key wrapping
============

Key wrapping is the process of encrypting a key, so that the resulting ciphertext can be stored, or transported, in a form that maintains the confidentiality of the key material.
Key unwrapping reverses this process, extracting the key from the ciphertext.

Some key-wrapping algorithms also provide integrity protection, to ensure that modification of the ciphertext can be detected.
Key-wrapping algorithms can wrap some of the key attributes and policy in the output.


.. _wrapped-key-formats:

Wrapped key formats
-------------------

Some key-wrapping algorithms do not require a specific format for the key material that is input to the wrapping procedure.
For this kind of key-wrapping algorithm, the |API| permits any of the supported key export formats to be used to prepare the data for wrapping.
This includes the default key formats described in the :secref:`key-types` chapter, and the additional formats described in :secref:`key-formats`.
For example, `PSA_ALG_AES_KWP` is a generic wrapping algorithm that provides confidentiality for the key.

Other key-wrapping procedures define both the format of the wrapped key material and the algorithm that is used to perform the wrapping.
These specialized wrapped-key formats are defined here.

Wrapped-key formats typically encode the wrapping algorithm within the output data.
If a wrapped-key format has a single associated wrapping algorithm, use the generic `PSA_ALG_WRAP` algorithm identifier to wrap and unwrap keys.
If there is a choice of wrapping algorithm, the chosen algorithm must be specified when wrapping a key, but `PSA_ALG_WRAP` can be used to unwrap the key.


.. todo:: RFC 5958/PKCS#8 also supports encryption and authentication of the key data.

    This would either be a *EncryptedPrivateKeyInfo* structure (PKCS#8) or one of the CMS content types.
    This requires one or more additional format specifiers.

.. macro:: PSA_KEY_FORMAT_ENCRYPTED_PRIVATE_KEY_INFO
    :definition: /* implementation-defined value */

    .. summary::
        The *EncryptedPrivateKeyInfo* key format for RSA and elliptic curve key-pairs.

    .. todo:: Update all of this for EncryptedPrivateKeyInfo

    OneAsymmetricKey is defined by :RFC-title:`5958#2`.
    OneAsymmetricKey is an update to the PKCS#8 *PrivateKeyInfo* format defined by :RFC-title:`5208`.
    Encoding of specific key types is defined in other documents:

    *   :RFC-title:`8017` defines the encoding of RSA keys.
    *   :RFC-title:`5915` defines the encoding of Weierstrass elliptic curve keys.
    *   :RFC-title:`8410` defines the encoding of Montgomery and Edwards elliptic curve keys.

    When exporting a key in this format:

    *   The public key is always included in the output.
    *   The output is :term:`DER` encoded by default.
        For output that is :term:`PEM` encoded, use the `PSA_KEY_FORMAT_OPTION_PEM` option.

    When exporting a Weierstrass elliptic curve key in this format:

    *   The *ECPoint* containing the key value is uncompressed by default.
        For the compressed encoding, use the `PSA_KEY_FORMAT_OPTION_EC_POINT_COMPRESSED` option.
    *   The *ECParameters* element uses a *namedCurve* by default.
        To output specified domain parameters instead, use the `PSA_KEY_FORMAT_OPTION_SPECIFIED_EC_DOMAIN` option.

    .. subsection:: Compatible key types

        *   `PSA_KEY_TYPE_ECC_KEY_PAIR`
        *   `PSA_KEY_TYPE_RSA_KEY_PAIR`

    .. subsection:: Key format options

        *   `PSA_KEY_FORMAT_OPTION_PEM`
        *   `PSA_KEY_FORMAT_OPTION_EC_POINT_COMPRESSED` (for Weierstrass elliptic curve keys)
        *   `PSA_KEY_FORMAT_OPTION_SPECIFIED_EC_DOMAIN` (for Weierstrass elliptic curve keys)

    .. subsection:: Compatible key-wrapping algorithms

        *   :issue:`TBD`

.. todo:: Do we also need a CMS content type format for encrypted OneAsymmetricKey data?


.. _key-wrap-algorithms:

Key-wrapping algorithms
-----------------------

.. macro:: PSA_ALG_WRAP
    :definition: /* TBD */

    .. summary::
        Generic key-wrapping algorithm.

    Use this algorithm with wrapped-key formats:

    *   When wrapping a key, for formats that have a single applicable wrapping algorithm.
    *   When unwrapping a key, for formats that encode the wrapping algorithm.

    .. subsection:: Compatible key formats

        *   `PSA_KEY_FORMAT_ENCRYPTED_PRIVATE_KEY_INFO`

    .. todo::
        I introduced this to simplify the application code when the key-wrapping algorithm is determined by the wrapped-key format, or the wrapped key data itself.

        The other parameters to the wrap/unwrap APIs match the behavior of formatted import and export, which is to expect a default value such as `PSA_KEY_TYPE_NONE` or ``0`` to indicate 'use the determined value'. In contrast to the suggestion here to use a dedicated value.

        The approach here more closely matches the `PSA_ALG_STREAM_CIPHER` algorithm for use with key types that pre-determine the algorithm (such as ChaCha).

        There is additional issue to consider: what should the permitted-algorithm be for wrapping keys that might be used with this algorithm? Or can this be a wild card that matches itself, or any specific algorithm that is applicable to the chosen key format?


.. macro:: PSA_ALG_AES_KW
    :definition: /* TBD */

    .. summary::
        The AES-KW key-wrapping algorithm.

    To wrap formatted keys that are not a multiple of the AES block size, `PSA_ALG_AES_KWP` can be used.

    .. subsection:: Compatible key formats

        This algorithm can wrap any formatted key that is an exact multiple of the 16-byte AES block size.
        For example, use `PSA_KEY_FORMAT_DEFAULT` to wrap 128-bit and 256-bit AES keys.


.. macro:: PSA_ALG_AES_KWP
    :definition: /* TBD */

    .. summary::
        The AES-KWP key-wrapping algorithm with padding.

    .. subsection:: Compatible key formats

        This algorithm can wrap any formatted key that is no longer than 255 blocks of the AES block-cipher.
        That is, a maximum of 4080 bytes.

Key wrapping functions
----------------------

.. todo::
    Do we need a new pair of usage flags for wrapping keys?

    Could we reuse `PSA_KEY_USAGE_ENCRYPT` and `PSA_KEY_USAGE_DECRYPT` - these are already reused for ciphers, AEAD and asymmetric encryption.

    *   This matches the existing usage of these flags for 'encrypt' or 'encrypt and integrity protect' operations.
    *   This would not enable key reuse, as the permitted-algorithm would have to be a specific key wrapping algorithm.

.. function:: psa_unwrap_key

    .. summary::
        Unwrap and import a key using a specified wrapping key.

    .. param:: const psa_key_attributes_t * attributes
        The attributes for the new key.

        Depending on the specified key format, and the attributes encoded in the wrapped-key data, some of the key attributes can be optional.

        The following attributes are required for formats that do not specify a key type:

        *   When the format does not specify a key type: the key type in ``attributes`` determines how the decrypted ``data`` buffer is interpreted.
        *   When the format does specify a key type: if the key type in ``attributes`` has a non-default value, it must be equal to the determined key type.

        The following attributes must be set for keys used in cryptographic operations:

        *   The key permitted-algorithm policy, see :secref:`permitted-algorithms`.
        *   The key usage flags, see :secref:`key-usage-flags`.

        These attributes are combined with any policy that is encoded in the wrapped-key data, so that both sets of restrictions apply :issue:`(this needs further thought & discussion)`.

        The following attributes must be set for keys that do not use the default volatile lifetime:

        *   The key lifetime, see :secref:`key-lifetimes`.
        *   The key identifier is required for a key with a persistent lifetime, see :secref:`key-identifiers`.

        The following attributes are optional:

        *   If the key size is nonzero, it must be equal to the key size determined from ``data``.

        .. note::
            This is an input parameter: it is not updated with the final key attributes.
            The final attributes of the new key can be queried by calling `psa_get_key_attributes()` with the key's identifier.
    .. param:: psa_key_id_t wrapping_key
        Identifier of the key to use for the unwrapping operation.
        It must permit the usage `PSA_KEY_USAGE_UNWRAP`.
    .. param:: psa_algorithm_t alg
        The key-wrapping algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_WRAP(alg)` is true.
    .. param:: psa_key_format_t format
        The format of the wrapped key data.
        One of the ``PSA_KEY_FORMAT_XXX`` values, or an implementation-specific format.
    .. param:: const uint8_t * data
        Buffer containing the wrapped key data.
        The content of this buffer is interpreted according to the key format ``format`` and unwrapping algorithm ``alg``.
        The type declared in ``attributes`` is used if the format and key data do not specify a key type.
    .. param:: size_t data_length
        Size of the ``data`` buffer in bytes.
    .. param:: psa_key_id_t * key
        On success, an identifier for the newly created key.
        `PSA_KEY_ID_NULL` on failure.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        If the key is persistent, the key material and the key's metadata have been saved to persistent storage.
    .. retval:: PSA_ERROR_ALREADY_EXISTS
        This is an attempt to create a persistent key, and there is already a persistent key with the given identifier.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        The wrapped key data could not be authenticated.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``wrapping_key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not a key-wrapping algorithm.
        *   ``wrapping_key`` is not supported for use with ``alg``.
        *   The key format is not supported by the implementation, or not supported with the chosen algorithm.
        *   The key attributes, as a whole, are not supported, either by the implementation in general or in the specified storage location.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not a key-wrapping algorithm.
        *   ``wrapping_key`` is not compatible with ``alg``.
        *   The key type is invalid, or is `PSA_KEY_TYPE_NONE` when a type is required.
        *   The key size is nonzero, and is incompatible with the wrapped key data in ``data``.
        *   The key lifetime is invalid.
        *   The key identifier is not valid for the key lifetime.
        *   The key usage flags include invalid values.
        *   The key's permitted-usage algorithm is invalid.
        *   The key attributes, as a whole, are invalid.
        *   The key format is invalid.
        *   The key data is not correctly formatted for the key format or the key type.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The following conditions can result in this error:

        *    The wrapping key does not have the `PSA_KEY_USAGE_UNWRAP` flag, or it does not permit the requested algorithm.
        *    The implementation does not permit creating a key with the specified attributes due to some implementation-specific policy.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_INSUFFICIENT_STORAGE
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    The key is unwrapped and extracted from the provided ``data`` buffer, which is interpreted according to the specified key format and key-wrapping algorithm.
    Its location is taken from ``attributes``, its type and policy are determined by the ``format``, the ``data``, and the ``attributes``.

    If a wrapped-key format, such as `PSA_KEY_FORMAT_ENCRYPTED_PRIVATE_KEY_INFO`, or the wrapped key data determines the key-wrapping algorithm, then ``alg`` must either match the determined key-wrapping algorithm or be `PSA_ALG_WRAP`.
    :issue:`Should this be PSA_ALG_NONE, which is more aligned with the other parameters? How does this interact with key policy?`

    For non-default key formats, the key format either specifies the key type, or the wrapped key data encodes the key type.
    For example, `PSA_KEY_FORMAT_RSA_PRIVATE_KEY` is always an RSA key pair, while the `PSA_KEY_FORMAT_ENCRYPTED_PRIVATE_KEY_INFO` format includes a data element that specifies whether it is an RSA or elliptic curve key-pair.
    If the key type is determined by the format and the data, then :code:``psa_get_key_type(attributes)`` must either match the determined key type or be `PSA_KEY_TYPE_NONE`.

    The wrapped key data determines the key size.
    :code:``psa_get_key_bits(attributes)`` must either match the determined key size or be ``0``.
    Implementations must reject an attempt to import a key of size zero.

    The resulting key can only be used in a way that conforms to both the policy included in the wrapped key data, and the policy specified in the ``attributes`` parameter :issue:`(the following is place-holder cut and paste from psa_copy_key())`:

    *   The usage flags on the resulting key are the bitwise-and of the usage flags on the source policy and the usage flags in ``attributes``.
    *   If both permit the same algorithm or wildcard-based algorithm, the resulting key has the same permitted algorithm.
    *   If either of the policies permits an algorithm and the other policy permits a wildcard-based permitted algorithm that includes this algorithm, the resulting key uses this permitted algorithm.
    *   If the policies do not permit any algorithm in common, this function fails with the status :code:`PSA_ERROR_INVALID_ARGUMENT`.

    As a result, the new key cannot be used for operations that were not permitted by the imported key data.

    .. todo:: The proposed constraints on key policy need to be revised in alignment with the approach decided for `psa_import_formatted_key()`.

    .. note::
        The |API| does not support asymmetric private key objects outside of a key pair.
        When unwrapping a private key, the corresponding key-pair type is created.
        If the imported key data does not contain the public key, then the implementation will reconstruct the public key from the private key as needed.

    .. admonition:: Implementation note

        To unwrap and import a key using a built-in or hidden key-wrapping key, it is recommended to define an implementation-specific key format, and use this in a call to `psa_import_formatted_key()`.
        The custom key format can be used to indicate that the data is a key wrapped with the hidden key.

        It is recommended that implementations reject wrapped key data if it might be erroneous, for example, if it is the wrong type or is truncated.

.. function:: psa_wrap_key

    .. summary::
        Wrap and export a key using a specified wrapping key.

    .. param:: psa_key_id_t wrapping_key
        Identifier of the key to use for the wrapping operation.
        It must permit the usage `PSA_KEY_USAGE_WRAP`.
    .. param:: psa_algorithm_t alg
        The key-wrapping algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_WRAP(alg)` is true.
    .. param:: psa_key_format_t format
        The required export format.
        One of the ``PSA_KEY_FORMAT_XXX`` values, or an implementation-specific format.
    .. param:: psa_key_format_option_t options
        Formatting options to use.
        One of the ``PSA_KEY_FORMAT_OPTION_XXX`` values, an implementation-specific option, or a bitwise-or of them.
    .. param:: psa_key_id_t key
        Identifier of the key to wrap.
        It must permit the usage `PSA_KEY_USAGE_EXPORT`.
    .. param:: uint8_t * data
        Buffer where the wrapped key data is to be written.
    .. param:: size_t data_size
        Size of the ``data`` buffer in bytes.
        This must be appropriate for the key:

        *   The required output size is :code:`PSA_WRAP_KEY_OUTPUT_SIZE(wrap_key_type, alg, format, options, type, bits)`, where ``wrap_key_type`` is the type of the wrapping key, ``alg`` is the key-wrapping algorithm, ``format`` is the key format, ``options`` is the format options, ``type`` is the type of the key being wrapped, and ``bits`` is the bit-size of the key being wrapped.
        *   `PSA_WRAP_KEY_PAIR_MAX_SIZE` evaluates to the maximum wrapped output size of any supported key pair, in any supported combination of key-wrapping algorithm, wrapping-key type, key format and options.
        *   This API defines no maximum size for wrapped symmetric keys. Arbitrarily large data items can be stored in the key store, for example certificates that correspond to a stored private key or input material for key derivation.
    .. param:: size_t * data_length
        On success, the number of bytes that make up the wrapped key data.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The first ``(*data_length)`` bytes of ``data`` contain the wrapped key.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        The following conditions can result in this error:

        *   ``wrapping_key`` is not a valid key identifier.
        *   ``key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The following conditions can result in this error:

        *   The wrapping key does not have the `PSA_KEY_USAGE_WRAP` flag, or it does not permit the requested algorithm.
        *   The key to be wrapped does not have the `PSA_KEY_USAGE_EXPORT` flag.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``alg`` is not a key-wrapping algorithm.
        *   ``wrapping_key`` is not compatible with ``alg``.
        *   The key format is not valid.
        *   The key format is not compatible with ``alg``.
        *   The key format is not applicable to the key type of ``key``.
        *   The key format option is not applicable to the key format.

        .. todo::
            Align behavior with `psa_export_formatted_key()` for inapplicable format options.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``alg`` is not supported or is not a key-wrapping algorithm.
        *   ``wrapping_key`` is not supported for use with ``alg``.
        *   The storage location of ``key`` does not support export of the key.
        *   The implementation does not support export of keys with the type of ``key``.
        *   The implementation does not support key export in the requested key format or format options.
    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``data`` buffer is too small.
        `PSA_WRAP_KEY_OUTPUT_SIZE()` or `PSA_WRAP_KEY_PAIR_MAX_SIZE` can be used to determine a sufficient buffer size.
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to `psa_crypto_init()`.

    Wrap a key from the key store into a data buffer using a specified key format, wrapping algorithm, and key-wrapping key.
    On success, the output contains the wrapped key value, and, depending on the format, some of the key attributes.
    The policy of the key to be wrapped must have the usage flag `PSA_KEY_USAGE_EXPORT` set.

    Some key-wrapping use cases can use a generic key-wrapping algorithm, such as `PSA_ALG_AES_KWP`, to encrypt any type of key, using any key format. See :secref:`key-wrap-algorithms`.

    Other use cases require a specific wrapped key format, such as `PSA_KEY_FORMAT_ENCRYPTED_PRIVATE_KEY_INFO`, which can be used for specific key types and with specific algorithms. Where the algorithm is determined by the wrapped-key format, ``alg`` must either match the key-wrapping algorithm or be `PSA_ALG_WRAP`.
    :issue:`Ditto - should this be PSA_ALG_NONE? And how does this interact with key policy?`

    Some key formats can optionally include additional content or use different encodings.
    These can be selected by using one or more of the ``PSA_KEY_FORMAT_OPTION_XXX`` values.
    The format options that are applicable depend on the chosen key format, and the type of the key to be wrapped.
    See :secref:`key-formats`.

    The output of this function can be passed to `psa_unwrap_key()`, specifying the same format, to create an equivalent key object.

Support macros
--------------

.. macro:: PSA_WRAP_KEY_OUTPUT_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient output buffer size for `psa_export_formatted_key()`.

    .. param:: wrap_key_type
       A supported key-wrapping key type.
    .. param:: alg
       A supported key-wrapping algorithm.
    .. param:: format
        A supported key format.
    .. param:: options
        A set of supported key format options.
    .. param:: key_type
        A supported key type.
    .. param:: key_bits
        The size of the key in bits.

    .. return::
        If the parameters are valid and supported, return a buffer size in bytes that guarantees that `psa_wrap_key()` will not fail with :code:`PSA_ERROR_BUFFER_TOO_SMALL`. If the parameters are a valid combination that is not supported by the implementation, this macro must return either a sensible size or ``0``. If the parameters are not valid, the return value is unspecified.

    See also `PSA_EXPORT_FORMATTED_KEY_PAIR_MAX_SIZE`, `PSA_EXPORT_FORMATTED_PUBLIC_KEY_MAX_SIZE`, and `PSA_EXPORT_FORMATTED_ASYMMETRIC_KEY_MAX_SIZE`.

.. macro:: PSA_WRAP_KEY_PAIR_MAX_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient buffer size for exporting any formatted asymmetric key pair.

    This value must be a sufficient buffer size when calling `psa_wrap_key()` to export any asymmetric key pair that is supported by the implementation, regardless of the exact key type, key size, key format, and format options.

    See also `PSA_EXPORT_FORMATTED_KEY_OUTPUT_SIZE()`, `PSA_EXPORT_FORMATTED_PUBLIC_KEY_MAX_SIZE`, and `PSA_EXPORT_FORMATTED_ASYMMETRIC_KEY_MAX_SIZE`.
