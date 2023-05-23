﻿.. SPDX-FileCopyrightText: Copyright 2018-2019, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _intro:

Introduction
============

About Platform Security Architecture
------------------------------------

This document is one of a set of resources provided by Arm that can help organizations develop products that meet the security requirements of PSA Certified on Arm-based platforms. The PSA Certified scheme provides a framework and methodology that helps silicon manufacturers, system software providers and OEMs to develop more secure products. Arm resources that support PSA Certified range from threat models, standard architectures that simplify development and increase portability, and open-source partnerships that provide ready-to-use software. You can read more about PSA Certified here at :url:`www.psacertified.org` and find more Arm resources here at :url:`developer.arm.com/platform-security-resources`.

About the |API|
---------------

The interface described in this document is a PSA Certified API, that provides key/value storage interfaces for use with device-protected storage. The |API| describes two interfaces for storage:

.. csv-table::
    :widths: 3 7

    Internal Trusted Storage API, An interface for storage provided by the :term:`Platform Root of Trust` (PRoT).
    Protected Storage API, An interface for external protected storage.

The Internal Trusted Storage API must be implemented in the PRoT as described in the :cite-title:`PSM` specification.

If there are no :term:`Application Root of Trust` (ARoT) services that rely on it, the Protected Storage API can be implemented in the :term:`NSPE`. Otherwise, the Protected Storage API must be implemented in an ARoT within the :term:`SPE`.

You can find additional resources relating to the |API| here at :url:`arm-software.github.io/psa-api/storage`, and find other PSA Certified APIs here at :url:`arm-software.github.io/psa-api`.
