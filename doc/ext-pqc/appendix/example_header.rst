.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _example-header:

Example header file
-------------------

The API elements in this specification, once finalized, will be defined in :file:`psa/crypto.h`.

This is an example of the header file definition of the PQC API elements. This can be used as a starting point or reference for an implementation.

.. note::
    Not all of the API elements are fully defined. An implementation must provide the full definition.

    The header will not compile without these missing definitions, and might require reordering to satisfy C compilation rules.

psa/crypto.h
~~~~~~~~~~~~

.. insert-header:: psa/crypto-pqc
