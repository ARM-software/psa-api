.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. Releases of this specification

.. release:: 1.0 beta 0
    :date: February 2019
    :confidentiality: Non-confidential

    Initial publication.

.. release:: 1.0.0
    :date: June 2019
    :confidentiality: Non-confidential

    First stable release with 1.0 API finalized.

    Uses the PSA Certified API common error status codes.

    Modified the API parameters to align with other PSA Certified APIs.

    Updated the claims and lifecycle to match the latest Platform Security Model.

    Updated CBOR example in the appendix.

.. release:: 1.0.1
    :date: August 2019
    :confidentiality: Non-confidential

    Recommend type byte 0x01 for arm_psa_UEID.

    Remove erroneous guidance regarding EAT’s origination claim.

.. release:: 1.0.2
    :date: February 2020
    :confidentiality: Non-confidential

    Clarify the claim number of Instance ID.

    Permit COSE-Mac0 for signing tokens (with appropriate warning).

    Update URLs.

.. release:: 1.0.3
    :date: October 2022
    :confidentiality: Non-confidential

    Relicensed as open source under CC BY-SA 4.0.

    CDDL definition added to the appendices.

    Example header file added to the appendices.

    Minor corrections and clarifications.

.. release-info::
    :extend:

    The detailed changes in each release are described in :secref:`document-history`.

.. References used within this specification

.. reference:: PSM
   :title: Platform Security Model
   :doc_no: ARM DEN 0128
   :url: developer.arm.com/documentation/den0128

.. reference:: PSA-STAT
    :title: PSA Certified Status code API
    :doc_no: ARM IHI 0097
    :url: arm-software.github.io/psa-api/status-code

.. reference:: PSA-FF-M
    :title: Arm® Platform Security Architecture Firmware Framework
    :doc_no: ARM DEN 0063
    :url: pages.arm.com/psa-apis

.. reference:: C99
    :title: ISO/IEC 9899:1999 --- Programming Languages --- C
    :author: ISO/IEC
    :publication: December 1999
    :url: www.iso.org/standard/29237.html

.. reference:: EAT
    :title: IETF Entity Attestation Token (EAT)
    :publication: Draft
    :url: datatracker.ietf.org/doc/draft-ietf-rats-eat

.. reference:: PSATOKEN
    :title: Arm's Platform Security Architecture (PSA) Attestation Token
    :publication: Draft
    :url: datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token

.. reference:: STD94
    :author: Bormann, C. and P. Hoffman
    :title: Concise Binary Object Representation (CBOR)
    :url: rfc-editor.org/info/std94
    :publication: December 2020

.. reference:: STD96
    :author: Schaad, J.
    :title: CBOR Object Signing and Encryption (COSE): Structures and Process
    :url: rfc-editor.org/info/std96
    :publication: August 2022

.. reference:: RFC8610
    :author: IETF
    :title: Concise Data Definition Language (CDDL)
    :url: tools.ietf.org/html/rfc8610

.. reference:: EAN-13
    :title: International Article Number
    :url: www.gs1.org/standards/barcodes/ean-upc


.. Terms used within this specification

.. term:: Concise Binary Object Representation
    :abbr: CBOR

    A format for encoding binary objects in a bitstream, defined in :cite-title:`STD94`.

.. term:: Entity Attestation Token
    :abbr: EAT

    A report format for attestation tokens, defined in :cite-title:`EAT`.

.. term:: Initial Attestation Key
    :abbr: IAK

    Typically, the Initial Attestation Key is a secret private key from an asymmetric key-pair accessible only to the Initial Attestation service within the :term:`Platform Root of Trust`. See :cite-title:`PSM`.

.. term:: PSA

    Platform Security Architecture

.. term:: Platform Root of Trust
    :abbr: PRoT

    The overall trust anchor for the system. This ensures the platform is securely booted and configured, and establishes the secure environments required to protect security services. See :cite-title:`PSM`.

.. term:: Immutable Platform Root of Trust

    Part of the :term:`Platform Root of Trust`, which is inherently trusted. This refers to the hardware and firmware that cannot be updated on a production device. See :cite-title:`PSM`.

.. scterm:: Implementation Defined

    Behavior that is not defined by this specification, but is defined and documented by individual implementations.

    Application developers can choose to depend on :sc:`IMPLEMENTATION DEFINED` behavior, but must be aware that their code might not be portable to another implementation.

.. term:: Secure Processing Environment
    :abbr: SPE

    This is the security domain that includes the :term:`Platform Root of Trust` domain.

.. term:: Non-secure Processing Environment
    :abbr: NSPE

    This is the security domain outside of the :term:`Secure Processing Environment`. It is the application domain, typically containing the application firmware and hardware.



.. potential-for-change::

    The contents of this specification are stable for version 1.0.

    The following may change in updates to the version 1.0 specification:

    * Small optional feature additions.
    * Clarifications.

    Significant additions, or any changes that affect the compatibility of the
    interfaces defined in this specification will only be included in a new major or
    minor version of the specification.

.. current-status::

   The token format defined within this specification has been superseded by the attestation token format defined in :cite-title:`PSATOKEN`. A future update to this specification will incorporate the new token definition.

.. about::
