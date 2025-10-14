.. SPDX-FileCopyrightText: Copyright 2022, 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _change-history:

==============
Change history
==============

Changes between version 1.0.3 and version 1.0.4
-----------------------------------------------

*  Updated introduction to reflect GlobalPlatform assuming the governance of the PSA Certified evaluation scheme.

Changes between version 1.0.2 and version 1.0.3
-----------------------------------------------

*  Clarified the definition and scope of the :code:`PSA_ERROR_INVALID_HANDLE` status code.

Changes between version 1.0.1 and version 1.0.2
-----------------------------------------------

*  Removed the whitespace within the definition of some of the status codes. The whitespace was erroneously introduced during the separation from the :cite-title:`PSA-FFM`. This change is necessary to ensure that multiple definitions of the same status code are identical, as required by the C language.


Changes between version 1.0.0 and version 1.0.1
-----------------------------------------------

*  Moved the specification of the common error codes into a separate specification.
*  Relicensed the document under Attribution-ShareAlike 4.0 International with a patent license derived from Apache License 2.0. See :secref:`license`.
*  Generalized the definitions of the error codes to better fit all PSA Certified APIs.
*  Added definitions from other PSA Certified APIs:

   -  `PSA_ERROR_CORRUPTION_DETECTED`
   -  `PSA_ERROR_DATA_CORRUPT`
   -  `PSA_ERROR_DATA_INVALID`

*  Added `PSA_OPERATION_INCOMPLETE` to indicate that the requested operation is unfinished. This can be used to break long-running operations into smaller pieces.


Changes prior to version 1.0.0
------------------------------

The definition of the common status codes was incorporated in the :cite-title:`PSA-FFM` specification up until version 1.0.0.
