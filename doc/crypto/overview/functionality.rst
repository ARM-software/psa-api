.. SPDX-FileCopyrightText: Copyright 2018-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _functionality-overview:

Functionality overview
======================

This section provides a high-level overview of the functionality provided by the interface defined in this specification. Refer to the API definition for a detailed description, which begins with :secref:`library-management`.

:secref:`future` describes features that might be included in future versions of this specification.

Due to the modularity of the interface, almost every part of the library is optional. The only mandatory function is `psa_crypto_init()`.

Library management
------------------

Applications must call `psa_crypto_init()` to initialize the library before using any other function.

.. _key-overview:

Key management
--------------

Applications always access keys indirectly via an identifier, and can perform operations using a key without accessing the key material. This allows keys to be *non-extractable*, where an application can use a key but is not permitted to obtain the key material. Non-extractable keys are bound to the device, can be rate-limited and can have their usage restricted by policies.

Each key has a set of attributes that describe the key and the policy for using the key. A `psa_key_attributes_t` object contains all of the attributes, which is used when creating a key and when querying key attributes.

The key attributes include:

*   A type and size that describe the key material. See :secref:`key-types-intro`.
*   The key identifier that the application uses to refer to the key. See :secref:`key-ids`.
*   A lifetime that determines when the key material is destroyed, and where it is stored. See :secref:`key-life`.
*   A policy that determines how the key can be used. See :secref:`key-usage-policies`.

Keys are created using one of the *key creation functions*:

*   `psa_import_key()`
*   `psa_generate_key()`
*   `psa_generate_key_custom()`
*   `psa_key_derivation_output_key()`
*   `psa_key_derivation_output_key_custom()`
*   `psa_key_agreement()`
*   `psa_encapsulate()`
*   `psa_decapsulate()`
*   `psa_pake_get_shared_key()`
*   `psa_copy_key()`
*   `psa_attach_key()`

These output the key identifier, that is used to access the key in all other parts of the API.

All of the key attributes are set when the key is created and cannot be changed without destroying the key first. If the original key permits copying, then the application can specify a different lifetime or restricted policy for the copy of the key.

A call to `psa_destroy_key()` destroys the key material, and will cause any active operations that are using the key to fail. Therefore an application must not destroy a key while an operation using that key is in progress, unless the application is prepared to handle a failure of the operation.

.. _key-types-intro:

Key types
~~~~~~~~~

Each cryptographic algorithm requires a key that has the right form, in terms of the size of the key material and its numerical properties. The key type and key size encode that information about a key, and determine whether the key is compatible with a cryptographic algorithm.

Additional non-cryptographic key types enable applications to store other secret values in the keystore.

See :secref:`key-types`.

.. _key-ids:

Key identifiers
~~~~~~~~~~~~~~~

Key identifiers are integral values that act as permanent names for persistent keys, or as transient references to volatile keys. Key identifiers are defined by the application for persistent keys, and by the implementation for volatile keys and for built-in keys.

Key identifiers are output from a successful call to one of the key creation functions.

Valid key identifiers must have distinct values within the same application. If the implementation provides :term:`caller isolation`, then key identifiers are local to each application.

See :secref:`key-identifiers`.

.. _key-life:

Key lifetimes
~~~~~~~~~~~~~

The lifetime of a key indicates where it is stored and which application and system actions will create and destroy it.

There are two main types of lifetimes: *volatile* and *persistent*.

Volatile keys are automatically destroyed when the application instance terminates or on a power reset of the device. Volatile key identifiers are allocated by the implementation when the key is created. Volatile keys can be explicitly destroyed with a call to `psa_destroy_key()`.

Persistent keys are preserved until the application explicitly destroys them or until an implementation-specific device management event occurs, for example, a factory reset. The key identifier for a persistent key is set by the application when creating the key, and remains valid throughout the lifetime of the key, even if the application instance that created the key terminates.

See :secref:`key-lifetimes`.

.. _key-usage-policies:

Key policies
~~~~~~~~~~~~

All keys have an associated policy that regulates which operations are permitted on the key. Each key policy is a set of usage flags and a specific algorithm that is permitted with the key. See :secref:`key-policy`.

Recommendations of minimum standards for key management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most implementations provide the following functions:

*   `psa_import_key()`. The exceptions are implementations that only give access to a key or keys that are provisioned by proprietary means, and do not allow the main application to use its own cryptographic material.

*   `psa_get_key_attributes()` and the ``psa_get_key_xxx()`` accessor functions. They are easy to implement, and it is difficult to write applications and to diagnose issues without being able to check the metadata.

*   `psa_export_public_key()`. This function is usually provided if the implementation supports any asymmetric algorithm, since public-key cryptography often requires the delivery of a public key that is associated with a protected private key.

*   `psa_export_key()`. However, highly constrained implementations that are designed to work only with short-term keys, or only with long-term non-extractable keys, do not need to provide this function.

Cryptographic operations
------------------------

The API supports cryptographic operations through two kinds of interfaces:

*   A *single-part* function performs a whole operation in a single function call. For example, compute, verify, encrypt or decrypt. See :secref:`single-part-functions`.

*   A *multi-part operation* is a set of functions that work with a stored operation state. This provides more control over operation configuration, piecewise processing of large input data, or handling for multi-step processes. See :secref:`multi-part-operations`.

Depending on the mechanism, one or both kind of interfaces may be provided.

.. _single-part-functions:

Single-part Functions
~~~~~~~~~~~~~~~~~~~~~

Single-part functions are APIs that implement the cryptographic operation in a single function call. This is the easiest API to use when all of the inputs and outputs fit into the application memory.

Single-part functions do not meet the needs of all use cases:

*   Some use cases involve messages that are too large to be assembled in memory, or require non-default configuration of the algorithm. These use cases require the use of a `multi-part operation <multi-part-operations>`.


.. _multi-part-operations:

Multi-part operations
~~~~~~~~~~~~~~~~~~~~~

Multi-part operations are APIs which split a single cryptographic operation into a sequence of separate steps. This enables fine control over the configuration of the cryptographic operation, and allows the message data to be processed in fragments instead of all at once. For example, the following situations require the use of a multi-part operation:

*   Processing messages that cannot be assembled in memory.
*   Using a deterministic IV for unauthenticated encryption.
*   Providing the IV separately for unauthenticated encryption or decryption.
*   Separating the AEAD authentication tag from the cipher text.
*   Password-authenticated key exchange (PAKE) is a multi-step process.

Each multi-part operation defines a specific object type to maintain the state of the operation. These types are implementation-defined.

All multi-part operations follow the same pattern of use, which is shown in :numref:`fig-multi-part`.

.. figure::  /figure/multi_part_operation.*
    :name: fig-multi-part

    General state model for a multi-part operation

The typical sequence of actions with a multi-part operation is as follows:

1.  **Allocate:** Allocate memory for an operation object of the appropriate type. The application can use any allocation strategy: stack, heap, static, etc.

#.  **Initialize:** Initialize or assign the operation object by one of the following methods:

    -   Set it to logical zero. This is automatic for static and global variables. Explicit initialization must use the associated ``PSA_xxx_OPERATION_INIT`` macro as the type is implementation-defined.
    -   Set it to all-bits zero. This is automatic if the object was allocated with ``calloc()``.
    -   Assign the value of the associated macro ``PSA_xxx_OPERATION_INIT``.
    -   Assign the result of calling the associated function ``psa_xxx_operation_init()``.

    The resulting object is now *inactive*.

    It is an error to initialize an operation object that is in *active* or *error* states. This can leak memory or other resources.

#.  **Setup:** Start a new multi-part operation on an *inactive* operation object. Each operation object will define one or more setup functions to start a specific operation.

    On success, a setup function will put an operation object into an *active* state. On failure, the operation object will remain *inactive*.

#.  **Update:** Update an *active* operation object. Each operation object defines one or more update functions, which are used to provide additional parameters, supply data for processing or generate outputs.

    On success, the operation object remains *active*. On failure, the operation object will enter an *error* state.

#.  **Finish:** To end the operation, call the applicable finishing function. This will take any final inputs, produce any final outputs, and then release any resources associated with the operation.

    On success, the operation object returns to the *inactive* state. On failure, the operation object will enter an *error* state.

#.  **Abort:** An operation can be aborted at any stage during its use by calling the associated ``psa_xxx_abort()`` function. This will release any resources associated with the operation and return the operation object to the *inactive* state.

    Any error that occurs to an operation while it is in an *active* state will result in the operation entering an *error* state. The application must call the associated ``psa_xxx_abort()`` function to release the operation resources and return the object to the *inactive* state.

    ``psa_xxx_abort()`` can be called on an *inactive* operation, and this has no effect.

.. rationale::

    *Why do multi-part operations require an explicit call to abort the operation after a failure?*

    Implicit-abort is easy to describe, and appears to be easy to use, but is complex to implement in non-trivial implementations; in comparison, explicit-abort is equally easy to understand, does not typically result in more complex usage code, and is easy to implement.

    In a non-trivial implementation there is more than one layer of software or hardware that has resources or state that needs to be released or reset when aborting the operation. For example, a client/server implementation (such as NSPE/SPE in a platform compliant with :cite-title:`PSM`) or a sw/hw implementation (driver/secure-element) or multi-layer design (client/service/driver/secure-element).

    Errors that might trigger an error state can occur or be detected in any of those layers.

    *   Implicit-abort requires that this error causes a downward **and** upward cascading abort to be applied to all layers of the stack so that the operation is fully reset and all resources released before the function call that triggered the error returns to the application.

    *   Explicit-abort only requires that the layer that detected the error records the error state and propagates the error back out to the caller. Resource release and state reset is not required, and lower layers do not need to be reset at this stage. Reset occurs from the application layer down through the stack as the follow-up abort call.

    For many applications, there is also (non-psa/crypto) local activity during a multipart operation that can give rise to errors that would result in the application choosing to abort the operation. Thus, requiring the application to always call ``psa_xxx_abort()`` on an error does not automatically lead to extra code in the application, and may have no effect on the application code size.

Once an operation object is returned to the *inactive* state, it can be reused
by calling one of the applicable setup functions again.

If a multi-part operation object is not initialized before use, the behavior is undefined.

If a multi-part operation function determines that the operation object is not in any valid state, it can return :code:`PSA_ERROR_CORRUPTION_DETECTED`.

If a multi-part operation function is called with an operation object in the wrong state, the function will return :code:`PSA_ERROR_BAD_STATE` and the operation object will enter the *error* state.

It is safe to move a multi-part operation object to a different memory location, for example, using a bitwise copy, and then to use the object in the new location. For example, an application can allocate an operation object on the stack and return it, or the operation object can be allocated within memory managed by a garbage collector. However, this does not permit the following behaviors:

*   Moving the object while a function is being called on the object. This is not safe. See also :secref:`concurrency`.
*   Working with both the original and the copied operation objects. This requires cloning the operation, which is only available for hash operations using `psa_hash_clone()`.

Each type of multi-part operation can have multiple *active* states. Documentation for the specific operation describes the configuration and update functions, and any requirements about their usage and ordering.

Symmetric cryptography
~~~~~~~~~~~~~~~~~~~~~~

This specification defines interfaces for the following types of symmetric
cryptographic operation:

*   Message digests, commonly known as hash functions. See :secref:`hashes`.
*   Message authentication codes (MAC). See :secref:`macs`.
*   Symmetric ciphers. See :secref:`ciphers`.
*   Authenticated encryption with associated data (AEAD). See :secref:`aead`.
*   Key derivation. See :secref:`kdf`.

Key derivation only provides multi-part operation, to support the flexibility required by these type of algorithms.

.. _symmetric-crypto-example:

Example of the symmetric cryptography API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Here is an example of a use case where a master key is used to generate both a message encryption key and an IV for the encryption, and the derived key and IV are then used to encrypt a message.

1.  Derive the message encryption material from the master key.

    a.  Initialize a `psa_key_derivation_operation_t` object to zero or to `PSA_KEY_DERIVATION_OPERATION_INIT`.
    #.  Call `psa_key_derivation_setup()` with `PSA_ALG_HKDF` as the algorithm.
    #.  Call `psa_key_derivation_input_key()` with the step `PSA_KEY_DERIVATION_INPUT_SECRET` and the master key.
    #.  Call `psa_key_derivation_input_bytes()` with the step `PSA_KEY_DERIVATION_INPUT_INFO` and a public value that uniquely identifies the message.
    #.  Populate a `psa_key_attributes_t` object with the derived message encryption key’s attributes.
    #.  Call `psa_key_derivation_output_key()` to create the derived message key.
    #.  Call `psa_key_derivation_output_bytes()` to generate the derived IV.
    #.  Call `psa_key_derivation_abort()` to release the key-derivation operation memory.

#.  Encrypt the message with the derived material.

    a.  Initialize a `psa_cipher_operation_t` object to zero or to `PSA_CIPHER_OPERATION_INIT`.
    #.  Call `psa_cipher_encrypt_setup()` with the derived message encryption key.
    #.  Call `psa_cipher_set_iv()` using the derived IV retrieved above.
    #.  Call `psa_cipher_update()` one or more times to encrypt the message.
    #.  Call `psa_cipher_finish()` at the end of the message.

#.  Call `psa_destroy_key()` to clear the generated key.

Asymmetric cryptography
~~~~~~~~~~~~~~~~~~~~~~~

This specification defines interfaces for the following types of asymmetric cryptographic operation:

*   Asymmetric encryption (also known as public-key encryption). See :secref:`pke`.
*   Asymmetric signature. See :secref:`sign`.
*   Two-way key agreement (also known as key establishment). See :secref:`key-agreement`.
*   Key encapsulation. See :secref:`key-encapsulation`.
*   Password-authenticated key exchange (PAKE). See :secref:`pake`.

For asymmetric encryption, the API provides *single-part* functions.

For asymmetric signature, the API provides single-part functions.

For key agreement, the API provides single-part functions and an additional input method for a key-derivation operation.

For key encapsulation, the API provides single-part functions.

For PAKE, the API provides a *multi-part* operation.


Randomness and key generation
-----------------------------

We strongly recommended that implementations include a random generator, consisting of a cryptographically secure pseudorandom generator (CSPRNG), which is adequately seeded with a cryptographic-quality hardware entropy source, commonly referred to as a true random number generator (TRNG). Constrained implementations can omit the random generation functionality if they do not implement any algorithm that requires randomness internally, and they do not provide a key-generation functionality. For example, a special-purpose component for signature verification can omit this.

It is recommended that applications use `psa_generate_key()`, `psa_cipher_generate_iv()` or `psa_aead_generate_nonce()` to generate suitably-formatted random data, as applicable. In addition, the API includes a function `psa_generate_random()` to generate and extract arbitrary random data.
