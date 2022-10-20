.. SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Introduction
============

About Platform Security Architecture
------------------------------------

This document is one of a set of resources provided by Arm that can help organizations develop products that meet the security requirements of PSA Certified on Arm-based platforms. The PSA Certified scheme provides a framework and methodology that helps silicon manufacturers, system software providers and OEMs to develop more secure products. Arm resources that support PSA Certified range from threat models, standard architectures that simplify development and increase portability, and open-source partnerships that provide ready-to-use software. You can read more about PSA Certified here at :url:`www.psacertified.org` and find more Arm resources here at :url:`developer.arm.com/platform-security-resources`.

About the |API| PAKE Extension
------------------------------

This document introduces an extension to the :cite-title:`PSA-CRYPT` specification, to provide support for :term:`Password-authenticated key exchange` (PAKE) algorithms, and specifically for the J-PAKE algorithm.

When the proposed extension is sufficiently stable to be classed as Final, it will be integrated into a future version of `[PSA-CRYPT]`.

This specification must be read and implemented in conjunction with `[PSA-CRYPT]`. All of the conventions, design considerations, and implementation considerations that are described in `[PSA-CRYPT]` apply to this specification.

.. note::

    This extension has been developed in conjunction with the :cite-title:`MBED-TLS` project, which is developing an implementation of the |API|.

.. rationale:: Note

    This version of the document includes *Rationale* commentary that provides background information relating to the design decisions that led to the current proposal. This enables the reader to understand the wider context and alternative approaches that have been considered.


Objectives for the PAKE Extension
---------------------------------

Scheme review
~~~~~~~~~~~~~

There are a number of PAKE protocols in circulation, but none of them are used widely in practice, and they are very different in scope and mechanics.
The API proposed for the |API| focuses on schemes that are most likely to be needed by users. A number of factors are used to identify important PAKE algorithms.

Wide deployment
^^^^^^^^^^^^^^^

Considering PAKE schemes with already wide deployment allows users with existing applications to migrate to the |API|.
Currently there is only one scheme with non-negligible success in the industry: Secure Remote Password (SRP).

Requests
^^^^^^^^

Some PAKE schemes have been requested by the community and need to be supported.
Currently, these are SPAKE2+ and J-PAKE (in particular the Elliptic Curve based variant, sometimes known as ECJPAKE)

Standardization
^^^^^^^^^^^^^^^

There are PAKE schemes that are being standardized and will be recommended for use in future protocols.
To ensure that the API is future proof, we need to consider these.
The CFRG recommends CPace and OPAQUE for use in IETF protocols.
These are also recommended for use in TLS and IKE in the future.

Applications
^^^^^^^^^^^^

Some of these schemes are used in popular protocols. This information confirms the choices already made and can help to extend the list in future:

.. list-table::
    :header-rows: 1
    :widths: auto
    :align: left

    *   -   PAKE scheme
        -   Protocols
    *   -   J-PAKE
        -   TLS, THREAD v1
    *   -   SPAKE2+
        -   CHIP
    *   -   SRP
        -   TLS
    *   -   OPAQUE
        -   TLS, IKE
    *   -   CPace
        -   TLS, IKE
    *   -   Dragonfly
        -   WPA3 (Before including the Dragonblood attack should be considered as well.)
    *   -   SPAKE
        -   Kerberos 5 v1.17
    *   -   PACE
        -   IKEv2
    *   -   AugPAKE
        -   IKEv2


Scope of the PAKE Extension
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following PAKE schemes are considered in the |API| design:

.. list-table::
    :header-rows: 1
    :widths: auto
    :align: left

    *   -   Balanced
        -   Augmented
    *   -   J-PAKE

            SPAKE2

            CPace
        -   SRP

            SPAKE2+

            OPAQUE

Scope of this specification
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The current API proposal provides the general interface for PAKE algorithms, and the specific interface for J-PAKE.

Out of scope
^^^^^^^^^^^^

PAKE protocols that do not fit into any of the above categories are not taken into consideration in the proposed API.
Some schemes like that are:

.. list-table::
    :header-rows: 1
    :widths: auto
    :align: left

    *   -   PAKE scheme
        -   Specification
    *   -   AMP
        -   IEEE 1363.2, ISO/IEC 11770-4
    *   -   BSPEKE2
        -   IEEE 1363.2
    *   -   PAKZ
        -   IEEE 1363.2
    *   -   PPK
        -   IEEE 1363.2
    *   -   SPEKE
        -   IEEE 1363.2
    *   -   WSPEKE
        -   IEEE 1363.2
    *   -   SPEKE
        -   IEEE 1363.2
    *   -   PAK
        -   IEEE 1363.2, X.1035, RFC 5683
    *   -   EAP-PWD
        -   RFC 5931
    *   -   EAP-EKE
        -   RFC 6124
    *   -   IKE-PSK
        -   RFC 6617
    *   -   PACE for IKEv2
        -   RFC 6631
    *   -   AugPAKE for IKEv2
        -   RFC 6628
    *   -   PAR
        -   IEEE 1363.2
    *   -   SESPAKE
        -   RFC 8133
    *   -   ITU-T
        -   X.1035
    *   -   SPAKE1
        -
    *   -   Dragonfly
        -
    *   -   B-SPEKE
        -
    *   -   PKEX
        -
    *   -   EKE
        -
    *   -   Augmented-EKE
        -
    *   -   PAK-X
        -
    *   -   PAKE
        -

The exception is SPAKE2, because of it is related to SPAKE2+.
