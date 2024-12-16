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

Objectives for the PQC Extension
--------------------------------

Background
~~~~~~~~~~

The justification for developing new :term:`public-key cryptography` algorithms due to the risks posed by quantum computing are described by NIST in :cite-title:`NIST-PQC`.

.. admonition:: Extract from *Post-Quantum Cryptography*:

    *In recent years, there has been a substantial amount of research on quantum computers --- machines that exploit quantum mechanical phenomena to solve mathematical problems that are difficult or intractable for conventional computers. If large-scale quantum computers are ever built, they will be able to break many of the public-key cryptosystems currently in use. This would seriously compromise the confidentiality and integrity of digital communications on the Internet and elsewhere.  The goal of post-quantum cryptography (also called quantum-resistant cryptography) is to develop cryptographic systems that are secure against both quantum and classical computers, and can interoperate with existing communications protocols and networks.*

    *The question of when a large-scale quantum computer will be built is a complicated one. While in the past it was less clear that large quantum computers are a physical possibility, many scientists now believe it to be merely a significant engineering challenge. Some engineers even predict that within the next twenty or so years sufficiently large quantum computers will be built to break essentially all public key schemes currently in use. Historically, it has taken almost two decades to deploy our modern public key cryptography infrastructure.  Therefore, regardless of whether we can estimate the exact time of the arrival of the quantum computing era, we must begin now to prepare our information security systems to be able to resist quantum computing.*

NIST is hosting a project to collaboratively develop, analyze, refine, and select cryptographic schemes that are resistant to attack by both classical and quantum computing.

Selection of algorithms
~~~~~~~~~~~~~~~~~~~~~~~

PQC algorithms that have been standardized are obvious candidates for inclusion in the |API|. The current set of standards is the following:

*   :cite-title:`FIPS203`
*   :cite-title:`FIPS204`
*   :cite-title:`FIPS205`

Although the NIST standards for these algorithms are now finalized, the definition of keys in the |API| depends on import and export formats.
To maximize key exchange interoperability with other specifications, the default export format in the |API| should be aligned with the definitions selected for X.509 public-key infrastructure.
As the IETF process for defining the X.509 key formats is still ongoing at the time of publishing this document, the interfaces within this document are at BETA status.

However, it is not expected that other aspects of the API in this document will change when it becomes FINAL.

.. note::
    Although PQC algorithms that are draft standards could be considered, any definitions for these algorithms would be have to be considered experimental.
    Significant aspects of the algorithm, such as approved parameter sets, can change before publication of a final standard, potentially requiring a revision of any proposed interface for the |API|.
