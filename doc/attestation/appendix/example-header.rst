.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _appendix-example-header:

Example header file
-------------------

Each implementation of the |API| must provide a header file named :file:`psa/initial_attestation.h`, in which the interface elements in this specification are defined.

This appendix provides a example of the :file:`psa/initial_attestation.h` header file with all of the API elements. This can be used as a starting point or reference for an implementation.

.. note::

   Not all of the API elements are fully defined. An implementation must provide the full definition.

   The header will not compile without these missing definitions, and might require reordering to satisfy C compilation rules.

psa/inital_attestation.h
~~~~~~~~~~~~~~~~~~~~~~~~

.. insert-header:: psa/initial_attestation
