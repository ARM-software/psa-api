.. SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Changes to the API
==================

.. _changes:

Document change history
-----------------------

This section provides the detailed changes made between published version of the document.

Changes between *Beta 1* and *Beta 2*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Changes to the API
~~~~~~~~~~~~~~~~~~

*   Combined :code:`psa_pake_set_password_key()` with :code:`psa_pake_setup()`. This aligns the API better with other multi-part operations, and also enables an implementation to identify the key location when setting up the operation. This affects the following APIs:

   -   Removed :code:`psa_pake_set_password_key()`
   -   Changed :code:`psa_pake_setup()`: it now takes an additional parameter

*   Replaced :code:`psa_pake_get_implicit_key()` with :code:`psa_pake_get_shared_key()`. This returns a new key containing the shared secret, instead of injecting the shared secret into a key derivation operation.
*   Added a key confirmation attribute to the PAKE cipher suite. This indicates whether the application wants to extract the shared secret before, or after, key confirmation. See :secref:`pake-cipher-suite`. This adds the APIs `PSA_PAKE_CONFIRMED_KEY`, `PSA_PAKE_UNCONFIRMED_KEY`, `psa_pake_cs_set_key_confirmation()`, and `psa_pake_cs_get_key_confirmation()`.

*   Moved the hash algorithm parameter to the PAKE cipher suite into the PAKE algorithm identifier, instead of a separate attribute of the cipher suite. This also makes the hash algorithm value available to the `PSA_PAKE_OUTPUT_SIZE()` and `PSA_PAKE_INPUT_SIZE()` macros. This affects the following APIs:

   -   Removed :code:`psa_pake_cs_get_hash()` and :code:`psa_pake_cs_set_hash()`
   -   Changed `PSA_ALG_JPAKE()`: it now requires a ``hash_alg`` parameter
   -   Added `PSA_ALG_IS_JPAKE()`

Clarifications
~~~~~~~~~~~~~~

*   Clarified the behavior of the PAKE operation following a call to `psa_pake_setup()`.

Changes between *Beta 0* and *Beta 1*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Other changes
~~~~~~~~~~~~~

*   Relicensed the document under Attribution-ShareAlike 4.0 International with a patent license derived from Apache License 2.0. See :secref:`license`.
