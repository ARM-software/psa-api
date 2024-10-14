.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Introduction
============

About Platform Security Architecture
------------------------------------

This document is one of a set of resources provided by Arm that can help organizations develop products that meet the security requirements of PSA Certified on Arm-based platforms. The PSA Certified scheme provides a framework and methodology that helps silicon manufacturers, system software providers and OEMs to develop more secure products. Arm resources that support PSA Certified range from threat models, standard architectures that simplify development and increase portability, and open-source partnerships that provide ready-to-use software. You can read more about PSA Certified here at :url:`www.psacertified.org` and find more Arm resources here at :url:`developer.arm.com/platform-security-resources`.

About the |API| PQC Extension
-----------------------------

This document defines an extension to the :cite-title:`PSA-CRYPT` specification, to provide support for :term:`Post-Quantum Cryptography` (PQC) algorithms, and specifically for the NIST-approved standards for ML-DSA, SLH-DSA, and ML-KEM.

When the proposed extension is sufficiently stable to be classed as Final, it will be integrated into a future version of `[PSA-CRYPT]`.

This specification must be read and implemented in conjunction with `[PSA-CRYPT]`. All of the conventions, design considerations, and implementation considerations that are described in `[PSA-CRYPT]` apply to this specification.

.. rationale:: Note

    This version of the document includes *Rationale* commentary that provides background information relating to the design decisions that led to the current proposal. This enables the reader to understand the wider context and alternative approaches that have been considered.


Objectives for the PQC Extension
--------------------------------

:issue:`TBD`
