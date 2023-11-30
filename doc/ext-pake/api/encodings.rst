.. SPDX-FileCopyrightText: Copyright 2022-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _pake-encodings:

Algorithm and key type encoding
===============================

These are encodings for a proposed PAKE interface for :cite-title:`PSA-CRYPT`.
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

The permitted values of HASH-TYPE depend on the specific PAKE algorithm.

..
    The permitted values of HASH-TYPE (see :numref:`table-hash-type`) depend on the specific PAKE algorithm.

.. csv-table:: PAKE algorithm sub-type values
    :name: table-pake-type
    :header-rows: 1
    :align: left
    :widths: auto

    PAKE algorithm, PAKE-TYPE, Algorithm identifier, Algorithm value
    J-PAKE, ``0x01``, :code:`PSA_ALG_JPAKE(hash)`, ``0x0A0001hh`` :sup:`a`
    SPAKE2+ with HMAC, ``0x04``, :code:`PSA_ALG_SPAKE2P_HMAC(hash)`, ``0x0A0004hh`` :sup:`a`
    SPAKE2+ with CMAC, ``0x05``, :code:`PSA_ALG_SPAKE2P_CMAC(hash)`, ``0x0A0005hh`` :sup:`a`
    SPAKE2+ for Matter, ``0x06``, :code:`PSA_ALG_SPAKE2P_MATTER`, ``0x0A000609``

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash``, used to construct the key derivation algorithm.

Key encoding
------------

A new type of asymmetric key is added for the SPAKE2+ algorithms. The Asymmetric key sub-type values table in `[PSA-CRYPT]` Appendix B is extended with the information in :numref:`table-spake2p-keys`.

.. csv-table:: New SPAKE2+ asymmetric key sub-type
    :name: table-spake2p-keys
    :header-rows: 1
    :align: left
    :widths: auto

    Asymmetric key type, ASYM-TYPE, Details
    SPAKE2+, 4, See :secref:`spakep2-key-encoding`

.. rationale::

    The ASYM-TYPE value 4 is selected as this has the same parity as the ECC sub-type, which have the value 1. The enables the same ECC-FAMILY and P values to be used when encoding a SPAKE2+ key type, as is used in the Elliptic Curve key types.

.. _spakep2-key-encoding:

SPAKE2+ key encoding
~~~~~~~~~~~~~~~~~~~~

The key type for SPAKE2+ keys defined in this specification are encoded as shown in :numref:`fig-spake2p-key-fields`.

.. figure:: ../figure/spake2p_key.*
    :name: fig-spake2p-key-fields

    SPAKE2+ key encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for ECC-FAMILY and P are shown in :numref:`table-spake2p-type`.

.. csv-table:: SPAKE2+ key family values
    :name: table-spake2p-type
    :header-rows: 1
    :align: left
    :widths: auto

    SPAKE2+ group, ECC-FAMILY, P, ECC family :sup:`a`, Public key value, Key pair value
    SECP R1, 0x09, 0, :code:`PSA_ECC_FAMILY_SECP_R1`, ``0x4412``, ``0x7412``
    Twisted Edwards, 0x21, 0, :code:`PSA_ECC_FAMILY_TWISTED_EDWARDS`, ``0x4442``, ``0x7442``

a.  The key type value is constructed from the Elliptic Curve family using either :code:`PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(family)` or :code:`PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(family)` as required.
