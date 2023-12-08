.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _report:

Initial Attestation report
==========================

The attestation report returned by the |API| is formatted and encoded as a signed PSA Attestation Token. This is defined in :cite-title:`PSATOKEN`.

The PSA Attestation Token is an incompatible evolution of the original attestation format, that was specified in version 1.0 of the |API|. :issue:`Should this provide a citation for v1.0, or a URL to the 'all-versions' page for the API here?`

To comply with version |docversion| of the |API|, an implementation must only produce attestation reports that conform to :cite:`PSATOKEN`. :issue:`Is this repeat (of the first sentence) necessary or helpful?`

.. todo:: Determine if we need any clarification or guidance for constructing specific claims in the attestation token/report.

   For example:

   :numref:`tab-psa-token-notes` provides specific recommendations for the construction of some of the token claims.

   .. list-table:: Recommended construction of the token claims
      :name: tab-psa-token-notes
      :header-rows: 1
      :stub-columns: 1
      :widths: 1 4
      :align: left

      *  -  Claim
         -  Recommended construction

      *  -   Instance ID
         -   The construction of the 32-byte key-hash component of this claim depends on the type of :term:`Initial Attestation Key` (IAK):

               *  When using an asymmetric key-pair for the IAK, the Instance ID is a hash of the corresponding public key.
               *  When using a symmetric key for the IAK, it is recommended that the Instance ID is a double hash of the key --- ``InstanceID = H(H(IAK))``. This eliminates risks when exposing the key to different HMAC block size. For further information, read :rfc-title:`2104`.
