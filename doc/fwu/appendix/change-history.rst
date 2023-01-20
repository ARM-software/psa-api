.. SPDX-FileCopyrightText: Copyright 2020-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _change-history:

Document change history
=======================

Changes between version *1.0 Beta* and *1.0.0*
----------------------------------------------

.. rubric:: General changes

*

.. rubric:: API changes

*

Changes between version *0.7* and *1.0 Beta*
--------------------------------------------

.. rubric:: General changes

*  Relicensed the document under Attribution-ShareAlike 4.0 International with a patent license derived from Apache License 2.0. See :secref:`license`.

*  Removed Profile IDs, and discussion of SUIT and manifest formats

*  Revised and extended all of the early chapters covering the goals, architecture and design of the API.

*  Updated code examples to match the v1.0 API. See :secref:`examples`.

.. rubric:: API changes

*  Renamed :code:`psa_image_id_t` to `psa_fwu_component_t`, and changed the type to :code:`uint8_t`.

*  Renamed :code:`psa_image_info_t` to `psa_fwu_component_info_t`.

   -  Removed Image ID, Vendor ID and Class ID from `psa_fwu_component_info_t` structure.
   -  Removed :code:`psa_fwu_staging_info_t`, adding any important members directly to `psa_fwu_component_info_t`.

*  Renamed :code:`psa_image_version_t` to `psa_fwu_image_version_t`.

   -  Resized the fields in `psa_fwu_image_version_t` to align with other project structures.
   -  Added :code:`build` field to `psa_fwu_image_version_t`.

*  Reworked the state model to reflect the overall state of a firmware component, not a specific image.

   -  Renamed :code:`PSA_FWU_UNDEFINED` to `PSA_FWU_READY` - the default starting state for the state model.
   -  Renamed :code:`CANDIDATE` state to :code:`WRITING` state. The new definition is :code:`PSA_FWU_WRITING`.
   -  Renamed :code:`REBOOT_NEEDED` state to :code:`STAGED` state. The new definition is :code:`PSA_FWU_STAGED`.
   -  Renamed :code:`PENDING_INSTALL` state to :code:`TRIAL` state. The new definition is :code:`PSA_FWU_TRIAL`.
   -  Renamed :code:`INSTALLED` state to :code:`UPDATED` state. The new definition is :code:`PSA_FWU_UPDATED`.
   -  Renamed :code:`REJECTED` state to :code:`FAILED` state. The new definition is :code:`PSA_FWU_FAILED`.
   -  Reintroduced :code:`REJECTED` as a transient state when rollback has been requested, but reboot has not yet occurred.

*  Renamed some of the installation functions:

   -  Rename :code:`psa_fwu_set_manifest()` to :code:`psa_fwu_start()`. This call is now mandatory, but the manifest data is optional.
   -  Rename :code:`psa_fwu_request_rollback()` to :code:`psa_fwu_reject()`, to mirror :code:`psa_fwu_accept()`.
   -  Rename :code:`psa_fwu_abort()` to :code:`psa_fwu_clean()`.

*  Explicit support for concurrent installation of multiple components:

   -  Reintroduced :code:`CANDIDATE` state for an image that has been prepared for installation, but not installed.
   -  Add :code:`psa_fwu_finish()` to mark a new firmware image as ready for installation.
   -  Add :code:`psa_fwu_cancel()` to abandon an update that is being prepared.
   -  Removed the ``component_id`` parameter from :code:`psa_fwu_install()`, :code:`psa_fwu_accept()`, and :code:`psa_fwu_reject()`: these now act atomically on all components in the initial state for the operation.

*  Reference the standard definition of the status codes, and remove them from this specification. See :secref:`status-codes`.

   *  Rationalize the API-specific error codes. This removes the following error codes:

      -  :code:`PSA_ERROR_WRONG_DEVICE`
      -  :code:`PSA_ERROR_CURRENTLY_INSTALLING`
      -  :code:`PSA_ERROR_ALREADY_INSTALLED`
      -  :code:`PSA_ERROR_INSTALL_INTERRUPTED`
      -  :code:`PSA_ERROR_DECRYPTION_FAILURE`
      -  :code:`PSA_ERROR_MISSING_MANIFEST`

   *  Standardize the use of error codes, aligning with other PSA Certified APIs:

      -  Use :code:`PSA_ERROR_BAD_STATE` when operations are called in the wrong sequence.
      -  Use :code:`PSA_ERROR_DOES_NOT_EXIST` when operations are called with an unknown component Id.
      -  Use :code:`PSA_ERROR_NOT_PERMITTED` when firmware images do not comply with update policy.

*  Removed the discovery API functions and types

   -  :code:`psa_fwu_get_image_id_iterator()`
   -  :code:`psa_fwu_get_image_id_next()`
   -  :code:`psa_fwu_get_image_id_valid()`
   -  :code:`psa_fwu_get_image_id()`
   -  :code:`psa_fwu_iterator_t`

*  Removed Profile IDs, and discussion of SUIT and metadata formats


Changes between version *0.6* and *0.7*
---------------------------------------


This section describes detailed changes between past versions.

*  :code:`PSA_FWU_API_VERSION_MINOR` has increased from 6 to 7
*  :code:`psa_image_id_t` is now defined as a 32-bit integer. Functions no longer have a pointer type for this parameter.
*  UUID concept dropped from function names and parameters.
*  Added Vendor ID and Class ID to :code:`psa_image_info_t` structure.
*  Added Future changes section
*  Added error code and success code definitions
*  Fixed mistake: :code:`psa_fwu_abort` return type changed from void to :code:`psa_status_t`
*  Clarifications to the text
*  Replaced :code:`PSA_ERROR_ROLLBACK_DETECTED` with :code:`PSA_ERROR_NOT_PERMITTED`
*  Remove standardized image IDs until we get more feedback
*  Improvements to the Design Overview text
