.. SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Password-authenticated key exchange (PAKE)
==========================================

This is a proposed PAKE interface for :cite-title:`PSA-CRYPT`.
It is not part of the official |API| yet.

.. note::

    The content of this specification is not part of the stable |API| and may change substantially from version to version.

Algorithm encoding
------------------

A new algorithm category is added for PAKE algorithms. The algorithm category table in `[PSA-CRYPT]` Appendix B is extended with the information in :numref:`table-pake-algorithm-category`.

.. csv-table:: New algorithm identifier categories
    :name: table-pake-algorithm-category
    :header-rows: 1
    :align: left
    :widths: auto

    Algorithm category, CAT, Category details
    PAKE, ``0x0A``, See :secref:`pake-encoding`

.. _pake-encoding:

PAKE algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~

The algorithm identifier for PAKE algorithms defined in this specification are encoded as shown in :numref:`fig-pake-encoding`.

.. figure:: /figure/pake_encoding.*
    :name: fig-pake-encoding

    PAKE algorithm encoding

The defined values for PAKE-TYPE are shown in :numref:`table-pake-type`.

.. csv-table:: PAKE algorithm sub-type values
    :name: table-pake-type
    :header-rows: 1
    :align: left
    :widths: auto

    PAKE algorithm, PAKE-TYPE, Algorithm identifier, Algorithm value
    J-PAKE, ``0x01``, `PSA_ALG_JPAKE`, ``0x0A000100``

Changes and additions to the Programming API
--------------------------------------------

.. header:: psa/crypto-pake
    :copyright: Copyright 2018-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
    :license: Apache-2.0

    /* This file contains reference definitions for implementation of the
     * PSA Certified Crypto API v1.2 PAKE Extension beta.2
     *
     * These definitions must be embedded in, or included by, psa/crypto.h
     */


.. _pake-algorithms:

PAKE algorithms
~~~~~~~~~~~~~~~

.. macro:: PSA_ALG_IS_PAKE
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a password-authenticated key exchange.

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a password-authenticated key exchange (PAKE) algorithm, ``0`` otherwise.
        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_JPAKE
    :definition: ((psa_algorithm_t)0x0a000100)

    .. summary::
        The Password-authenticated key exchange by juggling (J-PAKE) algorithm.

    This is J-PAKE as defined by :RFC-title:`8236`, instantiated with the following parameters:

    *   The group can be either an elliptic curve or defined over a finite field.
    *   Schnorr Non-Interactive Zero-Knowledge Proof (NIZKP) as defined by :RFC-title:`8235`, using the same group as the J-PAKE algorithm.
    *   A cryptographic hash function.

    J-PAKE does not confirm the shared secret key that results from the key exchange.

    To select these parameters and set up the cipher suite, initialize a `psa_pake_cipher_suite_t` object, and call the following functions in any order:

    .. code-block:: xref

        psa_pake_cipher_suite_t cipher_suite = PSA_PAKE_CIPHER_SUITE_INIT;

        psa_pake_cs_set_algorithm(&cipher_suite, PSA_ALG_JPAKE);
        psa_pake_cs_set_primitive(&cipher_suite,
                                  PSA_PAKE_PRIMITIVE(type, family, bits));
        psa_pake_cs_set_hash(&cipher_suite, hash);
        psa_pake_cs_set_key_confirmation(&cipher_suite, PSA_PAKE_UNCONFIRMED_KEY);

    More information on selecting a specific Elliptic curve or Diffie-Hellman field is provided with the `PSA_PAKE_PRIMITIVE_TYPE_ECC` and `PSA_PAKE_PRIMITIVE_TYPE_DH` constants.

    The J-PAKE operation follows the protocol shown in :numref:`fig-jpake`.

    .. figure:: /figure/j-pake.*
        :name: fig-jpake

        The J-PAKE protocol.

        The variable names *x1*, *g1*, and so on, are taken from the finite field implementation of J-PAKE in :RFC:`8236#2`. Details of the computation for the key shares and zero-knowledge proofs are in :RFC:`8236` and :RFC:`8235`.

    J-PAKE does not assign roles to the participants, so it is not necessary to call `psa_pake_set_role()`.

    J-PAKE requires both an application and a peer identity. If the peer identity provided to `psa_pake_set_peer()` does not match the data received from the peer, then the call to `psa_pake_input()` for the `PSA_PAKE_STEP_ZK_PROOF` step will fail with :code:`PSA_ERROR_INVALID_SIGNATURE`.

    The following steps demonstrate the application code for 'User' in :numref:`fig-jpake`.
    The input and output steps must be carried out in exactly the same sequence as shown.

    1.  To prepare a J-Pake operation, initialize and set up a :code:`psa_pake_operation_t` object by calling the following functions:

        .. code-block:: xref

            psa_pake_operation_t jpake = PSA_PAKE_OPERATION_INIT;

            psa_pake_setup(&jpake, pake_key, &cipher_suite);
            psa_pake_set_user(&jpake, ...);
            psa_pake_set_peer(&jpake, ...);

        The password is provided as key ``pake_key``, with type :code:`PSA_KEY_TYPE_PASSWORD` or :code:`PSA_KEY_TYPE_PASSWORD_HASH`.
        This can be the password text itself, in an agreed character encoding, or some value derived from the password as required by a higher level protocol.

        The key material is used as an array of bytes, which is converted to an integer as described in :cite-title:`SEC1` §2.3.8, before reducing it modulo *q*.
        Here, *q* is the order of the group defined by the cipher-suite primitive.
        `psa_pake_setup()` will return an error if the result of the conversion and reduction is ``0``.

    After setup, the key exchange flow for J-PAKE is as follows:

    1.  To get the first round data that needs to be sent to the peer, call:

        .. code-block:: xref

            // Get g1
            psa_pake_output(&jpake, PSA_PAKE_STEP_KEY_SHARE, ...);
            // Get V1, the ZKP public key for x1
            psa_pake_output(&jpake, PSA_PAKE_STEP_ZK_PUBLIC, ...);
            // Get r1, the ZKP proof for x1
            psa_pake_output(&jpake, PSA_PAKE_STEP_ZK_PROOF, ...);
            // Get g2
            psa_pake_output(&jpake, PSA_PAKE_STEP_KEY_SHARE, ...);
            // Get V2, the ZKP public key for x2
            psa_pake_output(&jpake, PSA_PAKE_STEP_ZK_PUBLIC, ...);
            // Get r2, the ZKP proof for x2
            psa_pake_output(&jpake, PSA_PAKE_STEP_ZK_PROOF, ...);

    #.  To provide the first round data received from the peer to the operation, call:

        .. code-block:: xref

            // Set g3
            psa_pake_input(&jpake, PSA_PAKE_STEP_KEY_SHARE, ...);
            // Set V3, the ZKP public key for x3
            psa_pake_input(&jpake, PSA_PAKE_STEP_ZK_PUBLIC, ...);
            // Set r3, the ZKP proof for x3
            psa_pake_input(&jpake, PSA_PAKE_STEP_ZK_PROOF, ...);
            // Set g4
            psa_pake_input(&jpake, PSA_PAKE_STEP_KEY_SHARE, ...);
            // Set V4, the ZKP public key for x4
            psa_pake_input(&jpake, PSA_PAKE_STEP_ZK_PUBLIC, ...);
            // Set r4, the ZKP proof for x4
            psa_pake_input(&jpake, PSA_PAKE_STEP_ZK_PROOF, ...);

    #.  To get the second round data that needs to be sent to the peer, call:

        .. code-block:: xref

            // Get A
            psa_pake_output(&jpake, PSA_PAKE_STEP_KEY_SHARE, ...);
            // Get V5, the ZKP public key for x2*s
            psa_pake_output(&jpake, PSA_PAKE_STEP_ZK_PUBLIC, ...);
            // Get r5, the ZKP proof for x2*s
            psa_pake_output(&jpake, PSA_PAKE_STEP_ZK_PROOF, ...);

    #.  To provide the second round data received from the peer to the operation call:

        .. code-block:: xref

            // Set B
            psa_pake_input(&jpake, PSA_PAKE_STEP_KEY_SHARE, ...);
            // Set V6, the ZKP public key for x4*s
            psa_pake_input(&jpake, PSA_PAKE_STEP_ZK_PUBLIC, ...);
            // Set r6, the ZKP proof for x4*s
            psa_pake_input(&jpake, PSA_PAKE_STEP_ZK_PROOF, ...);

    #.  To use the shared secret, extract it as a key. For example, to extract a derivation key for HKDF-SHA-256:

        .. code-block:: xref

            // Set up the key attributes
            psa_key_attributes_t att = PSA_KEY_ATTRIBUTES_INIT;
            psa_key_set_type(&att, PSA_KEY_TYPE_DERIVE);
            psa_key_set_usage_flags(&att, PSA_KEY_USAGE_DERIVE);
            psa_key_set_algorithm(&att, PSA_ALG_HKDF(PSA_ALG_SHA256));

            // Get Ka=Kb=K
            psa_key_id_t shared_key;
            psa_pake_get_shared_key(&jpake, &att, &shared_key);

    For more information about the format of the values which are passed for each step, see :secref:`pake-steps`.

    If the verification of a Zero-knowledge proof provided by the peer fails, then the corresponding call to `psa_pake_input()` for the `PSA_PAKE_STEP_ZK_PROOF` step will return :code:`PSA_ERROR_INVALID_SIGNATURE`.

    .. warning::

        At the end of this sequence there is a cryptographic guarantee that only a peer that used the same password is able to compute the same key.
        But there is no guarantee that the peer is the participant it claims to be, or that the peer used the same password during the exchange.

        At this point, authentication is implicit --- material encrypted or authenticated using the computed key can only be decrypted or verified by someone with the same key.
        The peer is not authenticated at this point, and no action should be taken by the application which assumes that the peer is authenticated, for example, by accessing restricted files.

        To make the authentication explicit, there are various methods to confirm that both parties have the same key. See :RFC:`8236#5` for two examples.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_PASSWORD`
        | :code:`PSA_KEY_TYPE_PASSWORD_HASH`


.. _pake-primitive:

PAKE primitives
~~~~~~~~~~~~~~~

A PAKE algorithm specifies a sequence of interactions between the participants.
Many PAKE algorithms are designed to allow different cryptographic primitives to be used for the key establishment operation, so long as all the participants are using the same underlying cryptography.

The cryptographic primitive for a PAKE operation is specified using a `psa_pake_primitive_t` value, which can be constructed using the `PSA_PAKE_PRIMITIVE()` macro, or can be provided as a numerical constant value.

A PAKE primitive is required when constructing a PAKE cipher-suite object, `psa_pake_cipher_suite_t`, which fully specifies the PAKE operation to be carried out.


.. typedef:: uint8_t psa_pake_primitive_type_t

    .. summary::
        Encoding of the type of the PAKE's primitive.

    The range of PAKE primitive type values is divided as follows:

    :code:`0x00`
        Reserved as an invalid primitive type.
    :code:`0x01 – 0x7f`
        Specification-defined primitive type.
        Primitive types defined by this standard always have bit 7 clear.
        Unallocated primitive type values in this range are reserved for future use.
    :code:`0x80 – 0xff`
        Implementation-defined primitive type.
        Implementations that define additional primitive types must use an encoding with bit 7 set.

    For specification-defined primitive types, see the documentation of individual ``PSA_PAKE_PRIMITIVE_TYPE_XXX`` constants.

.. macro:: PSA_PAKE_PRIMITIVE_TYPE_ECC
    :definition: ((psa_pake_primitive_type_t)0x01)

    .. summary::
        The PAKE primitive type indicating the use of elliptic curves.

    The values of the ``family`` and ``bits`` components of the PAKE primitive identify a specific elliptic curve, using the same mapping that is used for ECC keys.
    See the definition of ``psa_ecc_family_t``.
    Here ``family`` and ``bits`` refer to the values used to construct the PAKE primitive using `PSA_PAKE_PRIMITIVE()`.

    Input and output during the operation can involve group elements and scalar values:

    *   The format for group elements is the same as that for public keys on the specific Elliptic curve.
        For more information, consult the documentation of key formats in `[PSA-CRYPT]`.
    *   The format for scalars is the same as that for private keys on the specific Elliptic curve.
        For more information, consult the documentation of key formats in `[PSA-CRYPT]`.


.. macro:: PSA_PAKE_PRIMITIVE_TYPE_DH
    :definition: ((psa_pake_primitive_type_t)0x02)

    .. summary::
        The PAKE primitive type indicating the use of Diffie-Hellman groups.

    The values of the ``family`` and ``bits`` components of the PAKE primitive identify a specific Diffie-Hellman group, using the same mapping that is used for Diffie-Hellman keys.
    See the definition of ``psa_dh_family_t``.
    Here ``family`` and ``bits`` refer to the values used to construct the PAKE primitive using `PSA_PAKE_PRIMITIVE()`.

    Input and output during the operation can involve group elements and scalar values:

    *   The format for group elements is the same as that for public keys in the specific Diffie-Hellman group.
        For more information, consult the documentation of key formats in `[PSA-CRYPT]`.
    *   The format for scalars is the same as that for private keys in the specific Diffie-Hellman group.
        For more information, consult the documentation of key formats in `[PSA-CRYPT]`.


.. typedef:: uint8_t psa_pake_family_t

    .. summary::
        Encoding of the family of the primitive associated with the PAKE.

    For more information see the documentation of individual ``PSA_PAKE_PRIMITIVE_TYPE_XXX`` constants.

.. typedef:: uint32_t psa_pake_primitive_t

    .. summary::
        Encoding of the primitive associated with the PAKE.

    PAKE primitive values are constructed using `PSA_PAKE_PRIMITIVE()`.

    .. rationale::

        An integral type is required for `psa_pake_primitive_t` to enable values of this type to be compile-time-constants. This allows them to be used in ``case`` statements, and used to calculate static buffer sizes with `PSA_PAKE_OUTPUT_SIZE()` and `PSA_PAKE_INPUT_SIZE()`.

.. macro:: PSA_PAKE_PRIMITIVE
    :definition: /* specification-defined value */

    .. summary::
        Construct a PAKE primitive from type, family and bit-size.

    .. param:: pake_type
        The type of the primitive: a value of type `psa_pake_primitive_type_t`.
    .. param:: pake_family
        The family of the primitive.
        The type and interpretation of this parameter depends on ``pake_type``.
        For more information, consult the documentation of individual `psa_pake_primitive_type_t` constants.
    .. param:: pake_bits
        The bit-size of the primitive: a value of type ``size_t``.
        The interpretation of this parameter depends on ``family``.
        For more information, consult the documentation of individual `psa_pake_primitive_type_t` constants.

    .. return:: psa_pake_primitive_t
        The constructed primitive value.
        Return ``0`` if the requested primitive can't be encoded as `psa_pake_primitive_t`.


.. _pake-cipher-suite:

PAKE cipher suites
~~~~~~~~~~~~~~~~~~

Most PAKE algorithms have parameters that must be specified by the application. These parameters include the following:

*   The cryptographic primitive used for key establishment, specified using a `PAKE primitive <pake-primitive>`.
*   A cryptographic hash algorithm.
*   Whether the application requires the shared secret before, or after, it is confirmed.

The `psa_pake_cipher_suite_t` object is used to fully specify a PAKE operation, combining the PAKE algorithm, and the above parameters.

A PAKE cipher suite is required when setting up a PAKE operation in `psa_pake_setup()`.


.. typedef:: /* implementation-defined type */ psa_pake_cipher_suite_t

    .. summary::
        The type of an object describing a PAKE cipher suite.

    This is the object that represents the cipher suite used for a PAKE algorithm. The PAKE cipher suite specifies the PAKE algorithm, and the options selected for that algorithm. The cipher suite includes the following attributes:

    *   The PAKE algorithm itself.
    *   The PAKE primitive, which identifies the prime order group used for the key exchange operation. See :secref:`pake-primitive`.
    *   The hash algorithm to use in the operation.
    *   Whether to confirm the shared secret.

    This is an implementation-defined type. Applications that make assumptions about the content of this object will result in implementation-specific behavior, and are non-portable.

    Before calling any function on a PAKE cipher suite object, the application must initialize it by any of the following means:

    *   Set the object to all-bits-zero, for example:

        .. code-block:: xref

            psa_pake_cipher_suite_t cipher_suite;
            memset(&cipher_suite, 0, sizeof(cipher_suite));

    *   Initialize the object to logical zero values by declaring the object as static or global without an explicit initializer, for example:

        .. code-block:: xref

            static psa_pake_cipher_suite_t cipher_suite;

    *   Initialize the object to the initializer `PSA_PAKE_CIPHER_SUITE_INIT`, for example:

        .. code-block:: xref

            psa_pake_cipher_suite_t cipher_suite = PSA_PAKE_CIPHER_SUITE_INIT;

    *   Assign the result of the function `psa_pake_cipher_suite_init()` to the object, for example:

        .. code-block:: xref

            psa_pake_cipher_suite_t cipher_suite;
            cipher_suite = psa_pake_cipher_suite_init();

    Following initialization, the cipher-suite object contains the following values:

    .. list-table::
        :header-rows: 1
        :widths: 1 4
        :align: left

        *   -   Attribute
            -   Value

        *   -   algorithm
            -   :code:`PSA_ALG_NONE` --- an invalid algorithm identifier.
        *   -   primitive
            -   ``0`` --- an invalid PAKE primitive.
        *   -   hash
            -   :code:`PSA_ALG_NONE` --- an invalid algorithm identifier.
        *   -   key confirmation
            -   `PSA_PAKE_CONFIRMED_KEY` --- requesting that the secret key is confirmed before it can be returned.

    The algorithm and primitive values must be set for all PAKE algorithms, the hash and key confirmation values are required for some PAKE algorithms.

    .. admonition:: Implementation note

        Implementations are recommended to define the cipher-suite object as a simple data structure, with fields corresponding to the individual cipher suite attributes.
        In such an implementation, each function ``psa_pake_cs_set_xxx()`` sets a field and the corresponding function ``psa_pake_cs_get_xxx()`` retrieves the value of the field.

        An implementations can report attribute values that are equivalent to the original one, but have a different encoding.
        For example, an implementation can use a more compact representation for attributes where many bit-patterns are invalid or not supported, and store all values that it does not support as a special marker value.
        In such an implementation, after setting an invalid value, the corresponding get function returns an invalid value which might not be the one that was originally stored.

.. macro:: PSA_PAKE_CIPHER_SUITE_INIT
    :definition: /* implementation-defined value */

    .. summary::
        This macro returns a suitable initializer for a PAKE cipher suite object of type `psa_pake_cipher_suite_t`.

.. function:: psa_pake_cipher_suite_init

    .. summary::
        Return an initial value for a PAKE cipher suite object.

    .. return:: psa_pake_cipher_suite_t

.. function:: psa_pake_cs_get_algorithm

    .. summary::
        Retrieve the PAKE algorithm from a PAKE cipher suite.

    .. param:: const psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to query.

    .. return:: psa_algorithm_t
        The PAKE algorithm stored in the cipher suite object.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. function:: psa_pake_cs_set_algorithm

    .. summary::
        Declare the PAKE algorithm for the cipher suite.

    .. param:: psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to write to.
    .. param:: psa_algorithm_t alg
        The PAKE algorithm to write: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_PAKE(alg)` is true.

    .. return:: void

    This function overwrites any PAKE algorithm previously set in ``cipher_suite``.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. function:: psa_pake_cs_get_primitive

    .. summary::
        Retrieve the primitive from a PAKE cipher suite.

    .. param:: const psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to query.

    .. return:: psa_pake_primitive_t
        The primitive stored in the cipher suite object.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. function:: psa_pake_cs_set_primitive

    .. summary::
        Declare the primitive for a PAKE cipher suite.

    .. param:: psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to write to.
    .. param:: psa_pake_primitive_t primitive
        The PAKE primitive to write: a value of type `psa_pake_primitive_t`.
        If this is ``0``, the primitive type in ``cipher_suite`` becomes unspecified.

    .. return:: void

    This function overwrites any primitive previously set in ``cipher_suite``.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. function:: psa_pake_cs_get_hash

    .. summary::
        Retrieve the hash algorithm from a PAKE cipher suite.

    .. param:: const psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to query.

    .. return:: psa_pake_primitive_t
        The hash algorithm stored in the cipher suite object.
        The return value is :code:`PSA_ALG_NONE` if the PAKE is not parametrized by a hash algorithm, or if the hash algorithm is not set.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. function:: psa_pake_cs_set_hash

    .. summary::
        Declare the hash algorithm for a PAKE cipher suite.

    .. param:: psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to write to.
    .. param:: psa_algorithm_t hash_alg
        The hash algorithm to write: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true.
        If this is :code:`PSA_ALG_NONE`, the hash algorithm in ``cipher_suite`` becomes unspecified.

    .. return:: void

    This function overwrites any hash algorithm previously set in ``cipher_suite``.

    The documentation of individual PAKE algorithms specifies which hash algorithms are compatible, or if no hash algorithm is required.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. macro:: PSA_PAKE_CONFIRMED_KEY
    :definition: 0

    .. summary:: A key confirmation value that indicates an confirmed key in a PAKE cipher suite.

    This key confirmation value will result in the PAKE algorithm exchanging data to verify that the shared key is identical for both parties. This is the default key confirmation value in an initialized PAKE cipher suite object.

    Some algorithms do not include confirmation of the shared key.

.. macro:: PSA_PAKE_UNCONFIRMED_KEY
    :definition: 1

    .. summary:: A key confirmation value that indicates an unconfirmed key in a PAKE cipher suite.

    This key confirmation value will result in the PAKE algorithm terminating prior to confirming that the resulting shared key is identical for both parties.

    Some algorithms do not support returning an unconfirmed shared key.

    .. warning::

        When the shared key is not confirmed as part of the PAKE operation, the application is responsible for mitigating risks that arise from the possible mismatch in the output keys.

.. function:: psa_pake_cs_get_key_confirmation

    .. summary::
        Retrieve the key confirmation from a PAKE cipher suite.

    .. param:: const psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to query.

    .. return:: uint32_t
        A key confirmation value: either `PSA_PAKE_CONFIRMED_KEY` or `PSA_PAKE_UNCONFIRMED_KEY`.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs.
        It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. function:: psa_pake_cs_set_key_confirmation

    .. summary::
        Declare the key confirmation from a PAKE cipher suite.

    .. param:: psa_pake_cipher_suite_t* cipher_suite
        The cipher suite object to write to.
    .. param:: uint32_t key_confirmation
        The key confirmation value to write: either `PSA_PAKE_CONFIRMED_KEY` or `PSA_PAKE_UNCONFIRMED_KEY`.

    .. return:: void

    This function overwrites any key confirmation previously set in ``cipher_suite``.

    The documentation of individual PAKE algorithms specifies which key confirmation values are valid for the algorithm.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs.
        It can be efficiently implemented as a ``static inline`` function or a function-like macro.

.. _pake-roles:

PAKE roles
~~~~~~~~~~

Some PAKE algorithms need to know which role each participant is taking in the algorithm. For example:

*   Augmented PAKE algorithms typically have a client and a server participant.
*   Some symmetric PAKE algorithms need to assign an order to the participants.

.. typedef:: uint8_t psa_pake_role_t

    .. summary::
        Encoding of the application role in a PAKE algorithm.

    This type is used to encode the application's role in the algorithm being executed.
    For more information see the documentation of individual PAKE role constants.

.. macro:: PSA_PAKE_ROLE_NONE
    :definition: ((psa_pake_role_t)0x00)

    .. summary::
        A value to indicate no role in a PAKE algorithm.

    This value can be used in a call to `psa_pake_set_role()` for symmetric PAKE algorithms which do not assign roles.

.. macro:: PSA_PAKE_ROLE_FIRST
    :definition: ((psa_pake_role_t)0x01)

    .. summary::
        The first peer in a balanced PAKE.

    Although balanced PAKE algorithms are symmetric, some of them need the peers to be ordered for the transcript calculations.
    If the algorithm does not need a specific ordering, then either do not call `psa_pake_set_role()`, or use `PSA_PAKE_ROLE_NONE` as the role parameter.

.. macro:: PSA_PAKE_ROLE_SECOND
    :definition: ((psa_pake_role_t)0x02)

    .. summary::
        The second peer in a balanced PAKE.

    Although balanced PAKE algorithms are symmetric, some of them need the peers to be ordered for the transcript calculations.
    If the algorithm does not need a specific ordering, then either do not call `psa_pake_set_role()`, or use `PSA_PAKE_ROLE_NONE` as the role parameter.

.. macro:: PSA_PAKE_ROLE_CLIENT
    :definition: ((psa_pake_role_t)0x11)

    .. summary::
        The client in an augmented PAKE.

    Augmented PAKE algorithms need to differentiate between client and server.

.. macro:: PSA_PAKE_ROLE_SERVER
    :definition: ((psa_pake_role_t)0x12)

    .. summary::
        The server in an augmented PAKE.

    Augmented PAKE algorithms need to differentiate between client and server.


.. _pake-steps:

PAKE step types
~~~~~~~~~~~~~~~

.. typedef:: uint8_t psa_pake_step_t

    .. summary::
        Encoding of input and output steps for a PAKE algorithm.

    Some PAKE algorithms need to exchange more data than a single key share.
    This type encodes additional input and output steps for such algorithms.

.. macro:: PSA_PAKE_STEP_KEY_SHARE
    :definition: ((psa_pake_step_t)0x01)

    .. summary::
        The key share being sent to or received from the peer.

    The format for both input and output using this step is the same as the format for public keys on the group specified by the PAKE operation's primitive.

    The public key formats are defined in the documentation for :code:`psa_export_public_key()`.

    For information regarding how the group is determined, consult the documentation `PSA_PAKE_PRIMITIVE()`.

.. macro:: PSA_PAKE_STEP_ZK_PUBLIC
    :definition: ((psa_pake_step_t)0x02)

    .. summary::
        A Schnorr NIZKP public key.

    This is the ephemeral public key in the Schnorr Non-Interactive Zero-Knowledge Proof, this is the value denoted by *V* in :RFC:`8235`.

    The format for both input and output at this step is the same as that for public keys on the group specified by the PAKE operation's primitive.

    For more information on the format, consult the documentation of :code:`psa_export_public_key()`.

    For information regarding how the group is determined, consult the documentation `PSA_PAKE_PRIMITIVE()`.

.. macro:: PSA_PAKE_STEP_ZK_PROOF
    :definition: ((psa_pake_step_t)0x03)

    .. summary::
        A Schnorr NIZKP proof.

    This is the proof in the Schnorr Non-Interactive Zero-Knowledge Proof, this is the value denoted by *r* in :RFC:`8235`.

    Both for input and output, the value at this step is an integer less than the order of the group specified by the PAKE operation's primitive.
    The format depends on the group as well:

    *   For Montgomery curves, the encoding is little endian.
    *   For other Elliptic curves, and for Diffie-Hellman groups, the encoding is big endian. See :cite:`SEC1` §2.3.8.

    In both cases leading zeroes are permitted as long as the length in bytes does not exceed the byte length of the group order.

    For information regarding how the group is determined, consult the documentation `PSA_PAKE_PRIMITIVE()`.


.. _pake-operation:

Multi-part PAKE operations
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. typedef:: /* implementation-defined type */ psa_pake_operation_t

    .. summary::
        The type of the state object for PAKE operations.

    Before calling any function on a PAKE operation object, the application must initialize it by any of the following means:

    *   Set the object to all-bits-zero, for example:

        .. code-block:: xref

            psa_pake_operation_t operation;
            memset(&operation, 0, sizeof(operation));

    *   Initialize the object to logical zero values by declaring the object as static or global without an explicit initializer, for example:

        .. code-block:: xref

            static psa_pake_operation_t operation;

    *   Initialize the object to the initializer `PSA_PAKE_OPERATION_INIT`, for example:

        .. code-block:: xref

            psa_pake_operation_t operation = PSA_PAKE_OPERATION_INIT;

    *   Assign the result of the function `psa_pake_cipher_suite_init()` to the object, for example:

        .. code-block:: xref

            psa_pake_operation_t operation;
            operation = psa_pake_operation_init();

    This is an implementation-defined type. Applications that make assumptions about the content of this object will result in implementation-specific behavior, and are non-portable.

.. macro:: PSA_PAKE_OPERATION_INIT
    :definition: /* implementation-defined value */

    .. summary::
        This macro returns a suitable initializer for a PAKE operation object of type `psa_pake_operation_t`.

.. function:: psa_pake_operation_init

    .. summary::
        Return an initial value for a PAKE operation object.

    .. return:: psa_pake_operation_t

.. function:: psa_pake_setup

    .. summary::
        Setup a password-authenticated key exchange.

    .. param:: psa_pake_operation_t *operation
        The operation object to set up.
        It must have been initialized as per the documentation for `psa_pake_operation_t` and not yet in use.
    .. param:: psa_key_id_t password_key
        Identifier of the key holding the password or a value derived from the password.
        It must remain valid until the operation terminates.
        It must be of type :code:`PSA_KEY_TYPE_PASSWORD` or :code:`PSA_KEY_TYPE_PASSWORD_HASH`.
        It must permit the usage :code:`PSA_KEY_USAGE_DERIVE`.
    .. param:: const psa_pake_cipher_suite_t *cipher_suite
        The cipher suite to use.
        A PAKE cipher suite fully characterizes a PAKE algorithm, including the PAKE algorithm.

        The cipher suite must be compatible with the key type of ``password_key``.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success. The operation is now active.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be inactive.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_HANDLE
        ``password_key`` is not a valid key identifier.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        ``psssword_key`` does not have the :code:`PSA_KEY_USAGE_DERIVE` flag, or it does not permit the algorithm in ``cipher_suite``.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   The algorithm in ``cipher_suite`` is not a PAKE algorithm.
        *   The PAKE primitive in ``cipher_suite`` is not compatible with the PAKE algorithm.
        *   The hash algorithm in ``cipher_suite`` is invalid, or not compatible with the PAKE algorithm and primitive.
        *   The key confirmation value in ``cipher_suite`` is not compatible with the PAKE algorithm and primitive.
        *   The key type for ``password_key`` is not :code:`PSA_KEY_TYPE_PASSWORD` or :code:`PSA_KEY_TYPE_PASSWORD_HASH`.
        *   ``password_key`` is not compatible with ``cipher_suite``.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   The algorithm in ``cipher_suite`` is not a supported PAKE algorithm.
        *   The PAKE primitive in ``cipher_suite`` is not supported or not compatible with the PAKE algorithm.
        *   The hash algorithm in ``cipher_suite`` is not supported, or not compatible with the PAKE algorithm and primitive.
        *   The key confirmation value in ``cipher_suite`` is not supported, or not compatible, with the PAKE algorithm and primitive.
        *   The key type or key size of ``password_key`` is not supported with ``cipher suite``.
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    The sequence of operations to set up a password-authenticated key exchange operation is as follows:

    1.  Allocate a PAKE operation object which will be passed to all the functions listed here.
    #.  Initialize the operation object with one of the methods described in the documentation for `psa_pake_operation_t`.
        For example, using `PSA_PAKE_OPERATION_INIT`.
    #.  Call `psa_pake_setup()` to specify the cipher suite.
    #.  Call ``psa_pake_set_xxx()`` functions on the operation to complete the setup.
        The exact sequence of ``psa_pake_set_xxx()`` functions that needs to be called depends on the algorithm in use.

    A typical sequence of calls to perform a password-authenticated key exchange:

    1.  Call :code:`psa_pake_output(operation, PSA_PAKE_STEP_KEY_SHARE, ...)` to get the key share that needs to be sent to the peer.
    #.  Call :code:`psa_pake_input(operation, PSA_PAKE_STEP_KEY_SHARE, ...)` to provide the key share that was received from the peer.
    #.  Depending on the algorithm additional calls to `psa_pake_output()` and `psa_pake_input()` might be necessary.
    #.  Call `psa_pake_get_shared_key()` to access the shared secret.

    Refer to the documentation of individual PAKE algorithms for details on the required set up and operation for each algorithm, and for constraints on the format and content of valid passwords.
    See :secref:`pake-algorithms`.

    After a successful call to `psa_pake_setup()`, the operation is active, and the application must eventually terminate the operation. The following events terminate an operation:

    *   A successful call to `psa_pake_get_shared_key()`.
    *   A call to `psa_pake_abort()`.

    If `psa_pake_setup()` returns an error, the operation object is unchanged. If a subsequent function call with an active operation returns an error, the operation enters an error state.

    To abandon an active operation, or reset an operation in an error state, call `psa_pake_abort()`.

    ..
        See :secref:`multi-part-operations`. :issue:`add this when integrated to main specification`

.. function:: psa_pake_set_role

    .. summary::
        Set the application role for a password-authenticated key exchange.

    .. param:: psa_pake_operation_t *operation
        Active PAKE operation.
    .. param:: psa_pake_role_t role
        A value of type `psa_pake_role_t` indicating the application role in the PAKE algorithm.
        See :secref:`pake-roles`.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be active, and `psa_pake_set_role()`, `psa_pake_input()`, and `psa_pake_output()` must not have been called yet.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        ``role`` is not a valid PAKE role in the operation's algorithm.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        ``role`` is not a valid PAKE role, or is not supported for the operation's algorithm.
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED

    Not all PAKE algorithms need to differentiate the communicating participants.
    For PAKE algorithms that do not require a role to be specified, the application can do either of the following:

    *   Not call `psa_pake_set_role()` on the PAKE operation.
    *   Call `psa_pake_set_role()` with the `PSA_PAKE_ROLE_NONE` role.

    Refer to the documentation of individual PAKE algorithms for more information.
    See :secref:`pake-algorithms`.

.. function:: psa_pake_set_user

    .. summary::
        Set the user ID for a password-authenticated key exchange.

    .. param:: psa_pake_operation_t *operation
        Active PAKE operation.
    .. param:: const uint8_t *user_id
        The user ID to authenticate with.
    .. param:: size_t user_id_len
        Size of the ``user_id`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be active, and `psa_pake_set_user()`, `psa_pake_input()`, and `psa_pake_output()` must not have been called yet.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        ``user_id`` is not valid for the operation's algorithm and cipher suite.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The value of ``user_id`` is not supported by the implementation.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED

    Call this function to set the user ID.
    For PAKE algorithms that associate a user identifier with both participants in the session, also call `psa_pake_set_peer()` with the peer ID.
    For PAKE algorithms that associate a single user identifier with the session, call `psa_pake_set_user()` only.

    Refer to the documentation of individual PAKE algorithms for more information.
    See :secref:`pake-algorithms`.

.. function:: psa_pake_set_peer

    .. summary::
        Set the peer ID for a password-authenticated key exchange.

    .. param:: psa_pake_operation_t *operation
        Active PAKE operation.
    .. param:: const uint8_t *peer_id
        The peer's ID to authenticate.
    .. param:: size_t peer_id_len
        Size of the ``peer_id`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be active, and `psa_pake_set_peer()`, `psa_pake_input()`, and `psa_pake_output()` must not have been called yet.
        *   Calling `psa_pake_set_peer()` is invalid with the operation's algorithm.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        ``peer_id`` is not valid for the operation's algorithm and cipher suite.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The value of ``peer_id`` is not supported by the implementation.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED

    Call this function in addition to `psa_pake_set_user()` for PAKE algorithms that associate a user identifier with both participants in the session.
    For PAKE algorithms that associate a single user identifier with the session, call `psa_pake_set_user()` only.

    Refer to the documentation of individual PAKE algorithms for more information.
    See :secref:`pake-algorithms`.

.. function:: psa_pake_output

    .. summary::
        Get output for a step of a password-authenticated key exchange.

    .. param:: psa_pake_operation_t *operation
        Active PAKE operation.
    .. param:: psa_pake_step_t step
        The step of the algorithm for which the output is requested.
    .. param:: uint8_t *output
        Buffer where the output is to be written.
        The format of the output depends on the ``step``, see :secref:`pake-steps`.
    .. param:: size_t output_size
        Size of the ``output`` buffer in bytes.
        This must be appropriate for the cipher suite and output step:

        *   A sufficient output size is :code:`PSA_PAKE_OUTPUT_SIZE(alg, primitive, step)` where ``alg`` and ``primitive`` are the PAKE algorithm and primitive in the operation's cipher suite, and ``step`` is the output step.
        *   `PSA_PAKE_OUTPUT_MAX_SIZE` evaluates to the maximum output size of any supported PAKE algorithm, primitive and step.
    .. param:: size_t *output_length
        On success, the number of bytes of the returned output.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The first ``(*output_length)`` bytes of ``output`` contain the output.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be active and fully set up, and this call must conform to the algorithm's requirements for ordering of input and output steps.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        ``step`` is not compatible with the operation's algorithm.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        ``step`` is not supported with the operation's algorithm.
    .. retval:: PSA_ERROR_BUFFER_TOO_SMALL
        The size of the ``output`` buffer is too small.
        `PSA_PAKE_OUTPUT_SIZE()` or `PSA_PAKE_OUTPUT_MAX_SIZE` can be used to determine a sufficient buffer size.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_INSUFFICIENT_ENTROPY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    Depending on the algorithm being executed, you might need to call this function several times or you might not need to call this at all.

    The exact sequence of calls to perform a password-authenticated key exchange depends on the algorithm in use.
    Refer to the documentation of individual PAKE algorithms for more information.
    See :secref:`pake-algorithms`.

    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_pake_abort()`.

.. function:: psa_pake_input

    .. summary::
        Provide input for a step of a password-authenticated key exchange.

    .. param:: psa_pake_operation_t *operation
        Active PAKE operation.
    .. param:: psa_pake_step_t step
        The step for which the input is provided.
    .. param:: const uint8_t *input
        Buffer containing the input.
        The format of the input depends on the ``step``, see :secref:`pake-steps`.
    .. param:: size_t input_length
        Size of the ``input`` buffer in bytes.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The operation state is not valid: it must be active and fully set up, and this call must conform to the algorithm's requirements for ordering of input and output steps.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   ``step`` is not compatible with the operation's algorithm.
        *   The input is not valid for the operation's algorithm, cipher suite or ``step``.
    .. retval:: PSA_ERROR_INVALID_SIGNATURE
        The verification fails for a `PSA_PAKE_STEP_ZK_PROOF` input step.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The following conditions can result in this error:

        *   ``step`` is not supported with the operation's algorithm.
        *   The input is not supported for the operation's algorithm, cipher suite or ``step``.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    Depending on the algorithm being executed, you might need to call this function several times or you might not need to call this at all.

    The exact sequence of calls to perform a password-authenticated key exchange depends on the algorithm in use.
    Refer to the documentation of individual PAKE algorithms for more information.
    See :secref:`pake-algorithms`.

    `PSA_PAKE_INPUT_SIZE()` or `PSA_PAKE_INPUT_MAX_SIZE` can be used to allocate buffers of sufficient size to transfer inputs that are received from the peer into the operation.

    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_pake_abort()`.

.. function:: psa_pake_get_shared_key

    .. todo::

        Decide whether `psa_pake_get_shared_key()` can be called only once (and this terminates the operation), or if the application can sequentially extract multiple keys from the shared secret (much like can be done with a key derivation operation).

        If there are no use cases for multiple key extraction, then we should keep it simple and have a successful key extraction result in terminating the operation. This is the currently described behavior.

        Related: Does all of the shared secret need to be used to construct the output key?

    .. summary::
        Extract the shared secret from the PAKE as a key.

    .. param:: psa_pake_operation_t *operation
        Active PAKE operation.
    .. param:: const psa_key_attributes_t * attributes
        The attributes for the new key.
        This function uses the attributes as follows:

        *   The key type is required. It cannot be an asymmetric public key. :issue:`Should we place other restrictions - e.g. forbidding key types that consume a variable amount of input?`
        *   The key size is always determined from the PAKE shared secret. If the key size in ``attributes`` is nonzero, it must be equal to the size of the shared secret, in bits.

            The bit-size of the shared secret is :code:`PSA_PAKE_SECRET_KEY_BITS(alg, primitive, hash_alg)`, where ``alg``, ``primitive``, and ``hash_alg`` are the PAKE algorithm, primitive, and hash in the operation's cipher suite.

        *   The key permitted-algorithm policy is required for keys that will be used for a cryptographic operation.

            .. see :secref:`permitted-algorithms`.

        *   The key usage flags define what operations are permitted with the key.

            .. see :secref:`key-usage-flags`.

        *   The key lifetime and identifier are required for a persistent key.

        .. note::
            This is an input parameter: it is not updated with the final key attributes.
            The final attributes of the new key can be queried by calling :code:`psa_get_key_attributes()` with the key's identifier.

    .. param:: psa_key_id_t * key
        On success, an identifier for the newly created key. :code:`PSA_KEY_ID_NULL` on failure.


    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        If the key is persistent, the key material and the key's metadata have been saved to persistent storage.
    .. retval:: PSA_ERROR_BAD_STATE
        The following conditions can result in this error:

        *   The state of PAKE operation ``operation`` is not valid: it must be ready to return the shared secret.

            For an unconfirmed key, this will be when the key-exchange output and input steps are complete, but prior to any key-confirmation output and input steps.

            For a confirmed key, this will be when all key-exchange and key-confirmation output and input steps are complete.
        *   The library requires initializing by a call to :code:`psa_crypto_init()`.
    .. retval:: PSA_ERROR_ALREADY_EXISTS
        This is an attempt to create a persistent key, and there is already a persistent key with the given identifier.
    .. retval:: PSA_ERROR_NOT_SUPPORTED
        The key attributes, as a whole, are not supported for creation from a PAKE secret, either by the implementation in general or in the specified storage location.
    .. retval:: PSA_ERROR_INVALID_ARGUMENT
        The following conditions can result in this error:

        *   The key type is not valid for a PAKE output.
        *   The key size is nonzero, and is not the size of the shared secret.
        *   The key lifetime is invalid.
        *   The key identifier is not valid for the key lifetime.
        *   The key usage flags include invalid values.
        *   The key's permitted-usage algorithm is invalid.
        *   The key attributes, as a whole, are invalid.
    .. retval:: PSA_ERROR_NOT_PERMITTED
        The implementation does not permit creating a key with the specified attributes due to some implementation-specific policy.
    .. retval:: PSA_ERROR_INSUFFICIENT_MEMORY
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_STORAGE_FAILURE
    .. retval:: PSA_ERROR_DATA_CORRUPT
    .. retval:: PSA_ERROR_DATA_INVALID

    This is the final call in a PAKE operation, which retrieves the shared secret as a key.
    This key can be used directly in cryptographic operations such as encryption, but is more typically used as an input to key derivation operations to produce additional cryptographic keys.

    Depending on the key confirmation requested in the cipher suite, `psa_pake_get_shared_key()` must be called either before or after the key-confirmation output and input steps for the PAKE algorithm.
    The key confirmation affects the guarantees that can be made about the shared key:

    .. list-table::
        :class: borderless
        :widths: 1 4

        *   -   **Unconfirmed key**
            -   If the cipher suite used to set up the operation requested an unconfirmed key, the application must call `psa_pake_get_shared_key()` after the key-exchange output and input steps are completed.
                The PAKE algorithm provides a cryptographic guarantee that only a peer who used the same password, and identity inputs, is able to compute the same key.
                However, there is no guarantee that the peer is the participant it claims to be, and was able to compute the same key.

                Since the peer is not authenticated, no action should be taken that assumes that the peer is who it claims to be.
                For example, do not access restricted files on the peer's behalf until an explicit authentication has succeeded.

                .. note::
                    Some PAKE algorithms do not enable the output of the shared secret until it has been confirmed.

        *   -   **Confirmed key**
            -   If the cipher suite used to set up the operation requested a confirmed key, the application must call `psa_pake_get_shared_key()` after the key-exchange and key-confirmation output and input steps are completed.

                Following key confirmation, the PAKE algorithm provides a cryptographic guarantee that the peer used the same password and identity inputs, and has computed the identical shared secret key.

                Since the peer is not authenticated, no action should be taken that assumes that the peer is who it claims to be.
                For example, do not access restricted files on the peer's behalf until an explicit authentication has succeeded.

                .. note::
                    Some PAKE algorithms do not include any key-confirmation steps.

    This function can be called after the key exchange phase of the operation has completed.
    It injects the shared secret output of the PAKE into the provided key derivation operation.
    The input step :code:`PSA_KEY_DERIVATION_INPUT_SECRET` is used to input the shared key material into the key derivation operation.

    The exact sequence of calls to perform a password-authenticated key exchange depends on the algorithm in use.
    Refer to the documentation of individual PAKE algorithms for more information.
    See :secref:`pake-algorithms`.

    When this function returns successfully, ``operation`` becomes inactive.
    If this function returns an error status, the operation enters an error state and must be aborted by calling `psa_pake_abort()`.

.. function:: psa_pake_abort

    .. summary::
        Abort a PAKE operation.

    .. param:: psa_pake_operation_t * operation
        Initialized PAKE operation.

    .. return:: psa_status_t
    .. retval:: PSA_SUCCESS
        Success.
        The operation object can now be discarded or reused.
    .. retval:: PSA_ERROR_COMMUNICATION_FAILURE
    .. retval:: PSA_ERROR_CORRUPTION_DETECTED
    .. retval:: PSA_ERROR_BAD_STATE
        The library requires initializing by a call to :code:`psa_crypto_init()`.

    Aborting an operation frees all associated resources except for the ``operation`` object itself.
    Once aborted, the operation object can be reused for another operation by calling `psa_pake_setup()` again.

    This function can be called any time after the operation object has been initialized as described in `psa_pake_operation_t`.

    In particular, calling `psa_pake_abort()` after the operation has been terminated by a call to `psa_pake_abort()` or `psa_pake_get_shared_key()` is safe and has no effect.


Support macros
~~~~~~~~~~~~~~

.. macro:: PSA_PAKE_OUTPUT_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient output buffer size for `psa_pake_output()`, in bytes.

    .. param:: alg
        A PAKE algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_PAKE(alg)` is true.
    .. param:: primitive
        A primitive of type `psa_pake_primitive_t` that is compatible with algorithm ``alg``.
    .. param:: output_step
        A value of type `psa_pake_step_t` that is valid for the algorithm ``alg``.

    .. return::
        A sufficient output buffer size for the specified PAKE algorithm, primitive, and output step.
        An implementation can return either ``0`` or a correct size for a PAKE algorithm, primitive, and output step that it recognizes, but does not support.
        If the parameters are not valid, the return value is unspecified.

    If the size of the output buffer is at least this large, it is guaranteed that `psa_pake_output()` will not fail due to an insufficient buffer size.
    The actual size of the output might be smaller in any given call.

    See also `PSA_PAKE_OUTPUT_MAX_SIZE`

.. macro:: PSA_PAKE_OUTPUT_MAX_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient output buffer size for `psa_pake_output()` for any of the supported PAKE algorithms, primitives and output steps.

    If the size of the output buffer is at least this large, it is guaranteed that `psa_pake_output()` will not fail due to an insufficient buffer size.

    See also `PSA_PAKE_OUTPUT_SIZE()`.

.. macro:: PSA_PAKE_INPUT_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient buffer size for inputs to `psa_pake_input()`.

    .. param:: alg
        A PAKE algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_PAKE(alg)` is true.
    .. param:: primitive
        A primitive of type `psa_pake_primitive_t` that is compatible with algorithm ``alg``.
    .. param:: input_step
        A value of type `psa_pake_step_t` that is valid for the algorithm ``alg``.

    .. return::
        A sufficient buffer size for the specified PAKE algorithm, primitive, and input step.
        An implementation can return either ``0`` or a correct size for a PAKE algorithm, primitive, and output step that it recognizes, but does not support.
        If the parameters are not valid, the return value is unspecified.

    The value returned by this macro is guaranteed to be large enough for any valid input to `psa_pake_input()` in an operation with the specified parameters.

    This macro can be useful when transferring inputs from the peer into the PAKE operation.

    See also `PSA_PAKE_INPUT_MAX_SIZE`


.. macro:: PSA_PAKE_INPUT_MAX_SIZE
    :definition: /* implementation-defined value */

    .. summary::
        Sufficient buffer size for inputs to `psa_pake_input()` for any of the supported PAKE algorithms, primitives and input steps.

    This macro can be useful when transferring inputs from the peer into the PAKE operation.

    See also `PSA_PAKE_INPUT_SIZE()`.

.. macro:: PSA_PAKE_SECRET_KEY_BITS
    :definition: /* implementation-defined value */

    .. summary::
        The size of the secret key output from a PAKE algorithm, in bits.

    .. param:: alg
        A PAKE algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_PAKE(alg)` is true.
    .. param:: primitive
        A primitive of type `psa_pake_primitive_t` that is compatible with algorithm ``alg``.
    .. param:: hash_alg
        A hash algorithm: value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(alg)` is true.

    .. return::
        The size, in bits, of the shared secret produced by the specified PAKE algorithm, primitive, and associated hash algorithm.
        An implementation can return either ``0`` or a correct size for a PAKE algorithm, primitive, and hash algorithm that it recognizes, but does not support.
        If the parameters are not valid, the return value is unspecified.

    When extracting the shared secret using `psa_pake_get_shared_key()`, the application is not required to set the key size in the attributes.

    :issue:`Do we actually need this, if the only option is to extract all of the bits into the key?`
