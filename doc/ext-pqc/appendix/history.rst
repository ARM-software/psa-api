.. SPDX-FileCopyrightText: Copyright 2024-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _changes:

Document change history
=======================

Changes between *Final 0* and *Final 1*
---------------------------------------

.. rubric:: Clarifications and fixes

*   Updated citations for ML-DSA and SLH-DSA key formats.
*   Provided a table of hash algorithm OIDs for use with the HashML-DSA and HashSLH-DSA algorithms.
    See :secref:`slh-dsa` and :secref:`ml-dsa`.

Changes between *Beta 3* and *Final 0*
--------------------------------------

.. rubric:: Clarifications and fixes

*   Finalized the key format specification for SLH-DSA, ML-KEM, and ML-DSA keys.
    The formats are unchanged from the Beta version of this specification.
    See :secref:`slh-dsa`, :secref:`ml-dsa`, and :secref:`ml-kem`.

Changes between *Beta 2* and *Beta 3*
-------------------------------------

.. rubric:: Other changes

*   Updated introduction to reflect GlobalPlatform assuming the governance of the PSA Certified evaluation scheme.

Changes between *Beta 1* and *Beta 2*
-------------------------------------

.. rubric:: Clarifications and fixes

*   Fixed the derivation of SLH-DSA key pairs to extract the correct number of bytes from the key derivation operation.
    See `PSA_KEY_TYPE_SLH_DSA_KEY_PAIR`.
*   Clarified that the standard key formats are used in the :code:`psa_import_key()` and :code:`psa_export_key()` functions.

Changes between *Beta 0* and *Beta 1*
-------------------------------------

.. rubric:: Clarifications and fixes

*   Added references from each section to the relevant APIs in :cite-title:`PSA-CRYPT`.

Beta release
------------

First release of the PQC Extension.

*   Added support for FIPS 203 ML-KEM key-encapsulation algorithm and keys.
    See :secref:`ml-kem`.
*   Added support for FIPS 204 ML-DSA signature algorithm and keys.
    See :secref:`ml-dsa`.
*   Added support for FIPS 205 SLH-DSA signature algorithm and keys.
    See :secref:`slh-dsa`.
*   Added support for LMS and HSS stateful hash-based signature verification and public keys.
    See :secref:`lms`.
*   Added support for XMSS and |XMSS^MT| stateful hash-based signature verification and public keys.
    See :secref:`xmss`.
