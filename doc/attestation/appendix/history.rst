.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _document-history:

Document history
================

..  list-table::
    :class: longtable
    :header-rows: 1
    :widths: 3 17

    * - Date
      - Changes

    * - 2019-02-25
      - *1.0 Beta 0*

        * First public version for review

    * - 2019-06-12
      - *1.0.0*

        * First stable release
        * The API functions now use the shared ``psa_status_t`` return type.
        * Error values now use shared error codes, which are now defined in :file:`psa/error.h`.
        * Input parameters are now separate from output parameters. There are no longer any in/out parameters.
        * Size types have been replaced with ``size_t`` instead of ``uint32_t``.
        * Some parameter names have been changed to improve legibility.
        * The description of the Implementation ID claim has been rewritten to better match the definition in PSM.
        * Signer ID is no longer a mandatory part of the Software Components claim. However, it is needed for PSM compliance.
        * Explicitly describe which optional claims are required for PSM compliance.
        * Added lifecycle state (``PSA_LIFECYCLE_ASSEMBLY_AND_TEST``).
        * Clarifications and improvements to the description of some API elements and to the structure of the document.
        * Updated CBOR example in the appendix.
        * Added macro ``PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE``.

    * - 2019-08-16
      - *1.0.1*

        * Fixed typos and descriptions based on feedback.
        * Recommend type byte 0x01 for arm_psa_UEID.
        * Remove erroneous guidance regarding EAT's origination claim - it should not be used to find a verification service.

    * - 2020-02-06
      - *1.0.2*

        * Clarify the claim number of Instance ID
        * Permit COSE-Mac0 for signing tokens (with appropriate warning)
        * Update URLs

    * - 2022-10-17
      - *1.0.3*

        * Relicensed the document under Attribution-ShareAlike 4.0 International with a patent license derived from Apache License 2.0. See :secref:`license`.
        * Fix CBOR type of ``arm_psa_origination`` to text string. Spec and example were in conflict, and the example was correct.
        * Added CDDL definition to the appendices, which can be helpful to developers.
        * Instance ID definition for symmetric keys has been improved. The specific constructions are now recommended rather than normative.
        * Clarified the optionality of map entries in the Software Components claim. See :secref:`custom-claims`.

    * - 2025-09-23
      - *1.0.4*

        * Updated introduction to reflect GlobalPlatform assuming the governance of the PSA Certified evaluation scheme.

    * - 2024-??-??
      - *2.0.0*

        * Update the API to use the PSA attestation token, defined in :cite-title:`PSATOKEN`. The token and report format, CDDL definition, and example token are no longer required in this specification.
