.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Introduction
============

About Platform Security Architecture
------------------------------------

This document is one of a set of resources provided by Arm that can help organizations develop products that meet the security requirements of GlobalPlatform's PSA Certified evaluation scheme on Arm-based platforms.
The PSA Certified scheme provides a framework and methodology that helps silicon manufacturers, system software providers and OEMs to develop more secure products.
Arm resources that support PSA Certified range from threat models, standard architectures that simplify development and increase portability, and open-source partnerships that provide ready-to-use software.
You can read more about PSA Certified here at :url:`www.psacertified.org` and find more Arm resources here at :url:`developer.arm.com/platform-security-resources` and :url:`www.trustedfirmware.org`.

About the |API| PQC Extension
-----------------------------

This document defines an extension to the :cite-title:`PSA-CRYPT` specification, to provide support for :term:`Post-Quantum Cryptography` (PQC) algorithms.
Specifically, for the NIST-approved schemes for LMS, HSS, XMSS, |XMSS^MT|, ML-DSA, SLH-DSA, and ML-KEM.

This extension is now classed as Final, and it will be integrated into a future version of `[PSA-CRYPT]`.

This specification must be read and implemented in conjunction with `[PSA-CRYPT]`.
All of the conventions, design considerations, and implementation considerations that are described in `[PSA-CRYPT]` apply to this specification.

Objectives for the PQC Extension
--------------------------------

Background
~~~~~~~~~~

The justification for developing new :term:`public-key cryptography` algorithms due to the risks posed by quantum computing are described by NIST in :cite-title:`NIST-PQC`.

.. admonition:: Extract from *Post-Quantum Cryptography*:

    *In recent years, there has been a substantial amount of research on quantum computers --- machines that exploit quantum mechanical phenomena to solve mathematical problems that are difficult or intractable for conventional computers.
    If large-scale quantum computers are ever built, they will be able to break many of the public-key cryptosystems currently in use.
    This would seriously compromise the confidentiality and integrity of digital communications on the Internet and elsewhere.
    The goal of post-quantum cryptography (also called quantum-resistant cryptography) is to develop cryptographic systems that are secure against both quantum and classical computers, and can interoperate with existing communications protocols and networks.*

    *The question of when a large-scale quantum computer will be built is a complicated one. While in the past it was less clear that large quantum computers are a physical possibility, many scientists now believe it to be merely a significant engineering challenge.
    Some engineers even predict that within the next twenty or so years sufficiently large quantum computers will be built to break essentially all public key schemes currently in use.
    Historically, it has taken almost two decades to deploy our modern public key cryptography infrastructure.
    Therefore, regardless of whether we can estimate the exact time of the arrival of the quantum computing era, we must begin now to prepare our information security systems to be able to resist quantum computing.*

NIST is hosting a project to collaboratively develop, analyze, refine, and select cryptographic schemes that are resistant to attack by both classical and quantum computing.

Selection of algorithms
~~~~~~~~~~~~~~~~~~~~~~~

NIST PQC project finalists
^^^^^^^^^^^^^^^^^^^^^^^^^^

PQC algorithms that have been standardized are obvious candidates for inclusion in the |API|. The current set of standards is the following:

*   :cite-title:`FIPS203`
*   :cite-title:`FIPS204`
*   :cite-title:`FIPS205`

Although the NIST standards for these algorithms are now finalized, the definition of keys in the |API| depends on import and export formats.
To maximize key exchange interoperability with other specifications, the default export format in the |API| should be compatible with the definitions selected for X.509 public-key infrastructure.
The IETF process for defining the X.509 key formats is nearing completion, and decisions have be made regarding the key formats in the |API|.

.. note::
    Although PQC algorithms that are draft standards could be considered, any definitions for these algorithms would be have to be considered experimental.
    Significant aspects of the algorithm, such as approved parameter sets, can change before publication of a final standard, potentially requiring a revision of any proposed interface for the |API|.

Other NIST-approved schemes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

In :cite-title:`SP800-208`, NIST approved use of the following stateful hash-based signature (HBS) schemes:

*   The Leighton-Micali Signature (LMS) system, and its multi-tree variant, the Hierarchical Signature System (HSS/LMS).
    These are defined in :rfc-title:`8554`.
*   The eXtended Merkle Signature Scheme (XMSS), and its multi-tree variant |XMSS^MT|.
    These are defined in :rfc-title:`8391`.

HBS schemes have additional challenges with regards to deploying secure and resilient systems for signing operations. These challenges, outlined in `[SP800-208]` sections §1.2 and §8.1, result in a recommendation to use these schemes in a limited set of use cases, for example, authentication of firmware in constrained devices.

At present, it is not expected that the |API| will be used to create HBS private keys, or to carry out signing operations. However, there is a use case with the |API| for verification of HBS signatures. Therefore, for these HBS schemes, the |API| only provides support for public keys and signature verification algorithms.
