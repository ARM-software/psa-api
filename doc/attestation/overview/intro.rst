.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Introduction
============


About Platform Security Architecture
------------------------------------

This document is one of a set of resources provided by Arm that can help organizations develop products that meet the security requirements of PSA Certified on Arm-based platforms. The PSA Certified scheme provides a framework and methodology that helps silicon manufacturers, system software providers and OEMs to develop more secure products. Arm resources that support PSA Certified range from threat models, standard architectures that simplify development and increase portability, and open-source partnerships that provide ready-to-use software. You can read more about PSA Certified here at :url:`www.psacertified.org` and find more Arm resources here at :url:`developer.arm.com/platform-security-resources`.

About the |API|
---------------

The interface described in this document is a PSA Certified API, that provides a verifiable report of the state of the platform. The platform attestation service is provided by the :term:`Platform Root of Trust` and is described in :cite-title:`PSM`.

This document includes:

-  A set of common use cases. See :secref:`use cases`.
-  Information about the attestation report and the format. See :secref:`report`.
-  The associated Application Programming Interface (API). See :secref:`api`.

The |API| can be used either to directly produce verifiable evidence about the platform state in the context of a challenge-response interaction, or as a way to bootstrap trust in other attestation schemes. The PSA Certified framework provides the generic security features allowing OEM and service providers to integrate various attestation schemes on top of the Platform Root of Trust.

You can find additional resources relating to the |API| here at :url:`arm-software.github.io/psa-api/attestation`, and find other PSA Certified APIs here at :url:`arm-software.github.io/psa-api`.
