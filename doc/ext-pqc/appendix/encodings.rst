.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _pqc-encodings:

Algorithm and key type encoding
===============================

These are encodings for PQC algorithms and keys defined in this extension.
This information should be read in conjunction with :cite:`PSA-CRYPT` Appendix B.

.. note::

    These encodings will be integrated into a future version of `[PSA-CRYPT]`.

.. _pqc-algorithm-encoding:

Algorithm encoding
------------------


.. _hash-encoding:

Hash algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~

Additional hash algorithms defined by this extension are shown in :numref:`table-hash-type`.
See also *Hash algorithm encoding* in `[PSA-CRYPT]` Appendix B.

.. csv-table:: Hash algorithm sub-type values
    :name: table-hash-type
    :header-rows: 1
    :align: left
    :widths: auto

    Hash algorithm, HASH-TYPE, Algorithm identifier, Algorithm value
    SHA-256/192, ``0x0E``, `PSA_ALG_SHA_256_192`, ``0x0200000E``
    SHAKE128/256, ``0x16``, `PSA_ALG_SHAKE128_256`, ``0x02000016``
    SHAKE256/192, ``0x17``, `PSA_ALG_SHAKE256_192`, ``0x02000017``
    SHAKE256/256, ``0x18``, `PSA_ALG_SHAKE256_256`, ``0x02000018``

.. _sign-encoding:

Asymmetric signature algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Additional signature algorithms defined by this extension are shown in :numref:`table-sign-type`.
See also *Asymmetric signature algorithm encoding* in `[PSA-CRYPT]` Appendix B.

.. csv-table:: Asymmetric signature algorithm sub-type values
    :name: table-sign-type
    :header-rows: 1
    :align: left
    :widths: auto

    Signature algorithm, SIGN-TYPE, Algorithm identifier, Algorithm value
    Hedged SLH-DSA, ``0x40``, `PSA_ALG_SLH_DSA`, ``0x06004000``
    Deterministic SLH-DSA, ``0x41``, `PSA_ALG_DETERMINISTIC_SLH_DSA`, ``0x06004100``
    Hedged HashSLH-DSA, ``0x42``, :code:`PSA_ALG_HASH_SLH_DSA(hash)`, ``0x060042hh`` :sup:`a`
    Deterministic HashSLH-DSA, ``0x43``, :code:`PSA_ALG_DETERMINISTIC_HASH_SLH_DSA(hash)`, ``0x060043hh`` :sup:`a`
    Hedged ML-DSA, ``0x44``, `PSA_ALG_ML_DSA`, ``0x06004400``
    Deterministic ML-DSA, ``0x45``, `PSA_ALG_DETERMINISTIC_ML_DSA`, ``0x06004500``
    Hedged HashML-DSA, ``0x46``, :code:`PSA_ALG_HASH_ML_DSA(hash)`, ``0x060046hh`` :sup:`a`
    Deterministic HashML-DSA, ``0x47``, :code:`PSA_ALG_DETERMINISTIC_HASH_ML_DSA(hash)`, ``0x060047hh`` :sup:`a`
    LMS, ``0x48``, :code:`PSA_ALG_LMS`, ``0x06004800``
    HSS, ``0x49``, :code:`PSA_ALG_HSS`, ``0x06004900``
    XMSS, ``0x4A``, :code:`PSA_ALG_XMSS`, ``0x06004A00``
    |XMSS^MT|, ``0x4B``, :code:`PSA_ALG_XMSS_MT`, ``0x06004B00``

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash``, used to construct the signature algorithm.

.. _encapsulation-encoding:

Key-encapsulation algorithm encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Additional key-encapsulation algorithms defined by this extension are shown in :numref:`table-encapsulation-type`.

.. csv-table:: Encapsulation algorithm sub-type values
    :name: table-encapsulation-type
    :header-rows: 1
    :align: left
    :widths: auto

    Encapsulation algorithm, ENCAPS-TYPE, Algorithm identifier, Algorithm value
    ML-KEM, ``0x02``, `PSA_ALG_ML_KEM`, ``0x0C000200``

.. _pqc-key-encoding:

Key encoding
------------

Additional asymmetric key types defined by this extension are shown in :numref:`table-asymmetric-type`.
See also *Asymmetric key encoding* in `[PSA-CRYPT]` Appendix B.

.. csv-table:: Asymmetric key sub-type values
    :name: table-asymmetric-type
    :header-rows: 1
    :align: left
    :widths: auto

    Asymmetric key type, ASYM-TYPE, Details
    SLH-DSA, 3, See :secref:`slh-dsa-key-encoding`

.. _simple-asymmetric-key-encoding:

Non-parameterized asymmetric key encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Additional non-parameterized asymmetric key types defined by this extension are shown in :numref:`table-np-type`.
See also *Non-parameterized asymmetric key encoding* in `[PSA-CRYPT]` Appendix B.

.. csv-table:: Non-parameterized asymmetric key family values
    :name: table-np-type
    :header-rows: 1
    :align: left
    :widths: auto

    Key family, Public/pair, PAIR, NP-FAMILY, P, Key type, Key value
    ML-DSA, Public key, 0, 1, 0, `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY`, ``0x4002``
    , Key pair, 3, 1, 0, `PSA_KEY_TYPE_ML_DSA_KEY_PAIR`, ``0x7002``
    ML-KEM, Public key, 0, 2, 0, `PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY`, ``0x4004``
    , Key pair, 3, 2, 0, `PSA_KEY_TYPE_ML_KEM_KEY_PAIR`, ``0x7004``
    LMS, Public key, 0, 3, 1, `PSA_KEY_TYPE_LMS_PUBLIC_KEY`, ``0x4007``
    HSS, Public key, 0, 4, 0, `PSA_KEY_TYPE_HSS_PUBLIC_KEY`, ``0x4008``
    XMSS, Public key, 0, 5, 1, `PSA_KEY_TYPE_XMSS_PUBLIC_KEY`, ``0x400B``
    |XMSS^MT|, Public key, 0, 6, 1, `PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY`, ``0x400D``

.. _slh-dsa-key-encoding:

SLH-DSA key encoding
~~~~~~~~~~~~~~~~~~~~

The key type for SLH-DSA keys defined in this specification are encoded as shown in :numref:`fig-slh-dsa-key-fields`.

.. figure:: ../figure/encoding/slh_dsa_key.*
    :name: fig-slh-dsa-key-fields

    SLH-DSA key encoding

PAIR is either 0 for a public key, or 3 for a key pair.

The defined values for FAMILY and P are shown in :numref:`table-slh-dsa-type`.

.. csv-table:: SLH-DSA key family values
    :name: table-slh-dsa-type
    :header-rows: 1
    :align: left
    :widths: auto

    SLH-DSA key family, FAMILY, P, SLH-DSA family :sup:`a`, Public-key value, Key-pair value
    SLH-DSA-SHA2-\ *N*\ s, 0x01, 0, `PSA_SLH_DSA_FAMILY_SHA2_S`, ``0x4182``, ``0x7182``
    SLH-DSA-SHA2-\ *N*\ f, 0x02, 0, `PSA_SLH_DSA_FAMILY_SHA2_F`, ``0x4184``, ``0x7184``
    SLH-DSA-SHAKE-\ *N*\ s, 0x05, 1, `PSA_SLH_DSA_FAMILY_SHAKE_S`, ``0x418B``, ``0x718B``
    SLH-DSA-SHAKE-\ *N*\ f, 0x06, 1, `PSA_SLH_DSA_FAMILY_SHAKE_F`, ``0x418D``, ``0x718D``

a.  The SLH-DSA family values defined in the API also include the parity bit. The key type value is constructed from the SLH-DSA family using either :code:`PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY(family)` or :code:`PSA_KEY_TYPE_SLH_DSA_KEY_PAIR(family)` as required.
