.. SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _change-history:

==============
Change history
==============

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
