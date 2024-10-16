.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
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
    SHAKE128-256, ``0x16``, `PSA_ALG_SHAKE128_256`, ``0x02000016``

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

a.  ``hh`` is the HASH-TYPE for the hash algorithm, ``hash``, used to construct the signature algorithm.

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

    SLH-DSA key family, FAMILY, P, SLH-DSA family :sup:`a`, Public key value, Key pair value
    SLH-DSA-SHA2-\ *N*\ s, 0x01, 0, `PSA_SLH_DSA_FAMILY_SHA2_S`, ``0x4182``, ``0x7182``
    SLH-DSA-SHA2-\ *N*\ f, 0x02, 0, `PSA_SLH_DSA_FAMILY_SHA2_F`, ``0x4184``, ``0x7184``
    SLH-DSA-SHAKE-\ *N*\ s, 0x05, 1, `PSA_SLH_DSA_FAMILY_SHAKE_S`, ``0x418b``, ``0x718b``
    SLH-DSA-SHAKE-\ *N*\ f, 0x06, 1, `PSA_SLH_DSA_FAMILY_SHAKE_F`, ``0x418d``, ``0x718d``

a.  The SLH-DSA family values defined in the API also include the parity bit. The key type value is constructed from the SLH-DSA family using either :code:`PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY(family)` or :code:`PSA_KEY_TYPE_SLH_DSA_KEY_PAIR(family)` as required.
