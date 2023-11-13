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

*   Moved the hash algorithm parameter to the PAKE cipher suite into the PAKE algorithm identifier, instead of a separate attribute of the cipher suite. This also makes the hash algorithm value available to the `PSA_PAKE_OUTPUT_SIZE()` and `PSA_PAKE_INPUT_SIZE()` macros.

Clarifications
~~~~~~~~~~~~~~

*   Clarified the behavior of the PAKE operation following a call to `psa_pake_setup()`.

Changes between *Beta 0* and *Beta 1*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Other changes
~~~~~~~~~~~~~

*   Relicensed the document under Attribution-ShareAlike 4.0 International with a patent license derived from Apache License 2.0. See :secref:`license`.
