.. SPDX-FileCopyrightText: Copyright 2020-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _programming-model:

Programming model
=================

.. _firmware-store:

The firmware store
------------------

For each component, depending on the state or progress of a firmware update, there can be one or more firmware images currently in the component's firmware store:

*  An *active* image that is actively in use by the system.
*  A *staged* image that is being prepared for installation.
*  A *backup* of the previous image that is being replaced, used to recover if an attempted update fails.
*  A *dirty* image that can be erased.

For a component that is essential for system operation, there will always be exactly one *active* image. Other images might, or might not, be present in the firmware store.

The |API| uses a state model for the firmware store that requires storage for a minimum of two images. This is possible because the store does not need to hold more than one *staged*, *backup*, or *dirty* image concurrently. An implementation of the |API| can have storage for more than two images, and selects the appropriate storage area for a requested operation. For example, providing additional image storage locations can reduce the need to carry out expensive erase operations on the storage during normal device operation.

This document uses the following names to identify the two required locations:

.. csv-table::
   :header-rows: 1
   :widths: 1 1 6

   Location, Present, Description
   *Active*, Always, The image that is actively in use by the system
   *Second*, Sometimes, "An image that is being prepared, or is kept for recovery, or needs to be erased"

Depending on the system and memory design, the *active* and *second* locations can be fixed physical storage locations, or can refer to different physical storage locations over time as an update progresses. The implementation of the |API| is responsible for mapping the logical storage locations to the stored firmware images.

During the course of an update, a specific firmware image can change from being *active* to *second*, or from *second* to *active*. For example:

*  An image will switch from being *second* --- while being prepared --- to *active* following installation.
*  An image will switch from being *active* to *second* when it becomes the backup image during installation of new firmware.

.. _state-model:

State model
-----------

The full set of use cases for the |API| requires a fine-grained state model to track each component through the update process. See :secref:`state-rationale` for an explanation of the relationship between state model features and use cases.

This section describes the complete state model. Some of the states and transitions in the state model are only necessary for specific use cases. In addition, the persistence of the component states following a reboot depends on the implementation capabilities.

The complete state model is applicable for components that have the following properties:

1. A reboot is required to complete installation of a new image.
2. The image must be tested prior to acceptance.
3. A candidate image is persistent across a reboot, before it is staged for installation.

For components that do not require testing of new firmware before acceptance, or components that do not require a reboot to complete installation, only a subset of the states are visible to the update client. For components with :term:`volatile staging`, almost all component states will transition when the system restarts. Some common examples of alternative component update characteristics are described in :secref:`variations`, including the changes in the state model for such components.

.. _component-state:

Component state
^^^^^^^^^^^^^^^

:numref:`tab-states` shows the possible update states for a component. The states have corresponding elements in the API, see :secref:`component-states`.

.. list-table:: Component states
   :name: tab-states
   :class: longtable
   :header-rows: 1
   :widths: 1 6

   *  -  State
      -  Description

   *  -  READY
      -  This is the normal state for the component. There is just one image, it is *active*, and is currently in use by the system.

         The component is ready for a new firmware update to be started.

   *  -  WRITING
      -  A new firmware image is being written to the staging area, in preparation for installation.

         When writing is complete, the image becomes a CANDIDATE for installation.

         This state is always volatile for components that have :term:`volatile staging`. For other components, it is :scterm:`implementation defined` whether this state is volatile.

         When this state is volatile, the incomplete image is discarded at reboot.

   *  -  CANDIDATE
      -  Transfer of the new firmware image to the staging area is complete.

         When all components that require update are in CANDIDATE state, they can be installed.

         This state is always volatile for components that have volatile staging. For other components, it is always persistent.

         When this state is volatile, the candidate image is discarded at reboot.

   *  -  STAGED
      -  Installation of the candidate image has been requested, but the system must be restarted as the final update operation runs within the bootloader.

         This state is always volatile.

   *  -  TRIAL
      -  Installation of the staged image has succeeded, and is now the *active* image running in 'trial mode'. This state is always volatile, and requires the trial to be explicitly accepted to make the update permanent.

         In this state, the previously installed *active* image is preserved as the *second* image. If the trial is explicitly rejected, or the system restarts without accepting the trial, the previously installed image is re-installed and the trial image is rejected.

   *  -  REJECTED
      -  The *active* trial image has been rejected, but the system must be restarted so the bootloader can revert to the previous image, which was previously saved as the *second* image.

         This state is always volatile.

   *  -  FAILED
      -  An update to a new image has been attempted, but has failed, or been cancelled for some reason. The failure reason is recorded in the firmware store.

         The *second* image needs to be cleaned before another update can be attempted.

         This state is always volatile for components that have volatile staging. For other components, it is :scterm:`implementation defined` whether this state is volatile.

         When this state is volatile, the *second* image is cleaned at reboot.

   *  -  UPDATED
      -  The *active* trial image has been accepted.

         The *second* image contains the now-expired previous firmware image, which needs to be cleaned before another update can be started.

         This state is always volatile for components that have volatile staging. For other components, it is :scterm:`implementation defined` whether this state is volatile.

         When this state is volatile, the *second* image is cleaned at reboot.

.. admonition:: Implementation note

   An implementation can have additional internal states, provided that implementation-specific states are not visible to the caller of the |API|.

.. _volatile-states:

Volatile states
^^^^^^^^^^^^^^^

A component state is 'volatile', if the state is not preserved when the system reboots.

States that are volatile are not optional for an implementation of the |API|. Until a device reboots, the update service must follow the state transitions and report the resulting states as shown in the state model appropriate for the component update characteristics.

*  READY state is never volatile.
*  STAGED, TRIAL, and REJECTED states are always volatile.
*  If the component has :term:`volatile staging`, then CANDIDATE, WRITING, FAILED, and UPDATED states are volatile.
*  If the component does not have volatile staging, then CANDIDATE state is non-volatile, and it is :scterm:`implementation defined` whether WRITING, FAILED, or UPDATED states are volatile.

In most cases, at reboot the implementation effectively implements one or more transitions to a final, non-volatile state. The exception is for a component that is STAGED, and enters TRIAL state following a successful installation at reboot.

The transitions for volatile states are described as part of the appropriate state models for different types of firmware component. See :secref:`variations`.

.. _state-transitions:

State transitions
^^^^^^^^^^^^^^^^^

The state transitions occur either as a result of an function call from the update client, when the bootloader carries out an installation operation, or transitions over reboot from a volatile state. The transitions that occur within the bootloader are determined by the state of the component, and do not depend on the reason for the restart.

Table :numref:`tab-operations` shows the operations that the update client uses to trigger transitions in the state model. The operations have corresponding elements in the API, see :secref:`api-functions`.

.. csv-table:: Operations on components
   :name: tab-operations
   :widths: auto
   :align: left

   ``start``, Begin a firmware update operation
   ``write``, "Write all, or part, of a firmware image"
   ``finish``, Complete preparation of a candidate firmware image
   ``cancel``, Abandon a firmware image that is being prepared
   ``install``, Start the installation of candidate firmware images
   ``accept``, Accept an installation that is being trialed
   ``reject``, Abandon an installation
   ``clean``, Erase firmware storage before starting a new update

The ``start``, ``write``, and ``finish`` operations are used to prepare a new firmware image. The ``cancel`` and ``clean`` operations are used to clean up a component after a successful, failed, or abandoned update. It is an error to invoke these operations on a component that is not in a valid starting state for the operation.

The ``install``, ``accept``, and ``reject`` operations apply to all components in the system, affecting any component in the required starting state for the transition. This allows an update client to update multiple components atomically, if directed by the firmware image manifests. Components that are not in a valid starting state for these operations are not affected by the operation.

:numref:`fig-states` shows the typical flow through the component states.

.. figure:: /figure/states/default.*
   :name: fig-states
   :scale: 90%

   The standard component state model transitions

Note, that the READY state at the end is distinct from the starting READY state --- at the end the *active* firmware image is the updated version. The component is ready to start the process again from the beginning for the next update.

The behavior in error scenarios is not shown, except for the transitions over reboot where a failure can only be reported to the update client by changing the state of the component.

.. _behavior-on-error:

Behavior on error
^^^^^^^^^^^^^^^^^

Many of the operations in the |API| modify the firmware store. These operations are not required to have atomic operation with respect to the firmware store --- when a failure occurs during one of these operations, the firmware store can be left in a different state after the operation reports an error status.

The following behavior is required by every implementation:

*  When an operation returns the status :code:`PSA_SUCCESS`, the requested action has been carried out.

*  When a operation returns the status :code:`PSA_SUCCESS_RESTART`, or :code:`PSA_SUCCESS_REBOOT`, the requested action has been carried out, and appropriate action must be taken by the caller to continue the installation or rollback process.

*  When a operation returns the status :code:`PSA_ERROR_BAD_STATE`, :code:`PSA_ERROR_DOES_NOT_EXIST`, or :code:`PSA_ERROR_NOT_SUPPORTED`, no action has been carried out, and the affected components' states are unchanged.

*  If firmware image dependencies are verified when the component is in CANDIDATE state, a missing dependency leaves the component unchanged, in CANDIDATE state.

*  If there is a failure when verifying other manifest or firmware image properties of a component in WRITING, CANDIDATE or STAGED state, the component is transitioned to FAILED state.

*  If there is a failure when verifying or installing a new firmware image during a component restart, or system reboot, the component is transitioned to FAILED state.

*  A component always follows a transition that is shown in the appropriate state model, except for:

   -  If FAILED is a volatile state, a reboot transition that is shown to end in the FAILED state must include a ``clean`` operation to end in READY state.
   -  Other transitions to FAILED state, as described in the preceding rules.
   -  If UPDATED is a volatile state, a reboot transition that is shown to end in the UPDATED state must include a ``clean`` operation to end in READY state.

If an operation fails because of other conditions, it is :scterm:`implementation defined` whether the component state is unchanged, or is transitioned to FAILED state. In this situation, it is recommended that the update client abort the update process with a ``cancel`` operation.

If an unexpected system restart interrupts an operation, it is :sc:`implementation defined` whether the component state is unchanged, is transitioned to FAILED state, or is processed to a following state by the bootloader as described by the state model. In this situation, the update client must query the component status when it restarts, to determine the result.

.. _state-rationale:

Rationale
^^^^^^^^^

The complexity of the state model is a response to the requirements that follow from the use cases for the |API|. :numref:`tab-model-rationale` provides a rationale for the state model design.

.. list-table:: Use case implications for the state model
   :name: tab-model-rationale
   :class: longtable
   :header-rows: 1
   :widths: 1 3

   *  -  State model feature
      -  Rationale

   *  -  Optional non-volatile WRITING state
      -  Devices with slow download due to bandwidth or energy constraints can take an extended period to obtain the firmware image. When this is not a constraint, it is more efficient to not need to retain persistent state necessary to resume a download.
   *  -  Incremental image transfer in WRITING state
      -  Devices with limited RAM cannot store the entire image in the update client before writing to the firmware store.
   *  -  CANDIDATE state
      -  Enables the update client to explicitly indicate which components are part of an atomic multi-component ``install`` operation.
   *  -  FAILED state
      -  Enables the update client to detect failed installation operations that occur in the bootloader.
   *  -  TRIAL and REJECTED states
      -  Enables a new firmware image to be tested by application firmware, prior to accepting the update, without compromising a firmware rollback-prevention policy.
   *  -  UPDATED state and ``cancel`` operation
      -  Erasing non-volatile storage can be a high-latency operation. In some systems, this activity might block other memory i/o operations, including code execution. Isolating the erase activity within the ``clean`` operation enables an update client to manage when such disruptive actions take place.


Verifying an update
-------------------

A firmware update is essentially authorized remote code execution. Any security weaknesses in the update process expose that remote code execution system. Failure to secure the firmware update process will help attackers take control of devices.

Where the installation results in the loss of the previous image, verification of the image during a :term:`secure boot` process is not sufficient. If the boot time verification fails, then it is possible that the device can no longer operate, unless additional recovery mechanisms are implemented.

It is important for the update process to verify that an update is appropriate for the device, authentic, correctly authorized, and not expected to result in a non-functioning system. This is achieved by verifying various aspects of the firmware and its manifest. The various checks can take place at different points in the update process, depending on the firmware update implementation architecture --- as a result, a verification failure can cause an error response in different function calls depending on the implementation.

The following sections provide example of verification checks that can be implemented as part of the update process.

.. _manifest-verification:

Manifest verification
^^^^^^^^^^^^^^^^^^^^^

Before processing the content of the manifest, the implementation must verify that the manifest is valid, and authentic. This is typically achieved using a digital signature on the manifest, that can be verified by a trust anchor that is associated with the component.

The manifest must conform to a format that is expected by the implementation. It is recommended that the implementation treats unexpected manifest content as an error.

The manifest describes the type of device, and component, that the firmware is for. The implementation must check that this information matches the device and component being updated.

The manifest provides the version, or sequence number, of the new firmware image. For some deployments, the implementation must not install an earlier version of firmware than is currently installed. This security requirement prevents a firmware downgrade that can expose a known security vulnerability.

The manifest can provide information about dependencies on other firmware images. The implementation must only install the new firmware if its dependencies are satisfied. See :secref:`dependencies`.

.. admonition:: Implementation note

   In a trusted-client implementation of the |API|, these steps can be carried out by the update client, and then no verification is done by the implementation. See :secref:`trusted-client`.

Firmware image verification
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before installation, the firmware integrity must be verified. This can be done by checking that a hash of the firmware image matches the associated value in the manifest, or by checking that a provided image signature matches the firmware image using the trust anchor associated with the component.

In a system that implements :term:`secure boot`, the firmware verification processes that occur during firmware update do not replace the requirement for the bootloader to ensure that only correctly authorized firmware can execute on the device.

The implementation is permitted to defer all of the verification of the manifest and firmware image to the bootloader. However, it is recommended that as much verification as possible is carried out before rebooting the system. This reduces the loss of system availability during a reboot, or the cost of storing the firmware image, when it can be determined ahead of time that the update will fail at least one verification check. This recommendation is also made for systems which repeat the verification in the bootloader, prior to final installation and execution of the new firmware.

.. admonition:: Implementation note

   In a trusted-client implementation of the |API|, this verification can be carried out by the update client, and then no verification is done by the implementation. See :secref:`trusted-client`.

.. _dependencies:

Dependencies
------------

A firmware image can have a dependency on another component's firmware image. When a firmware image has a dependency it cannot be installed until all of its dependencies are satisfied.

A dependency can be satisfied by a firmware image that is already installed, or by a firmware image that is installed at the same time as the dependent image. In the latter case, both images must be prepared as candiate images before the ``install`` operation. If new firmware images for multiple components are inter-dependent, then the components must be installed at the same time. The :secref:`multi-component-example` example shows how this can be done.

Dependencies are typically described in the firmware image manifest. It is the responsibility of the update client to update components in an order that ensures that dependencies are met during the installation process. Typically, the firmware creator and update server ensure that firmware image updates are presented to the update client in an appropriate order. In more advanced systems, a manifest might provide the update client with sufficient information to determine dependencies and installation order of multiple components itself.

.. admonition:: Implementation note

   In a trusted-client implementation of the |API|, dependency verification can be carried out by the update client, and then no verification is done by the implementation. See :secref:`trusted-client`.


Update client operation
-----------------------

A typical sequence of activity relating to a firmware update within a device is as follows:

1. Query the current component status, to determine if an update is required
2. Obtain the required manifests and firmware images for the update
3. Validate the manifest
4. Store the firmware image
5. Verify the firmware image
6. Invoke the updated firmware image
7. Clean up any outdated stored firmware image

The design of the |API| offers functions for these actions.

The activity does not always follow this sequence in order. For example,

*  To support devices with constrained download bandwidth, the interface permits an implementation to retain a partially stored firmware image across a system restart. The transfer of the image to the update service can be resumed after the update client has determined the component status.
*  For components where the manifest and image are bundled together, the image will be stored prior to verification of the manifest data.
*  Some components require execution of the new image to complete verification of the update functionality, before committing to the update.

Querying installed firmware
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each component has a local component identifier. Component queries are based on the component identifier.

The update client calls `psa_fwu_query()` with each component identifier to retrieve information about the component firmware. This information is reported in a `psa_fwu_component_info_t` object, and includes the state of the component, and version of the current active firmware.

If a component state is not READY, the update client should proceed with the appropriate operations to continue or abandon the update that is in progress.

Preparing a new firmware image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To start this process, the component must be in READY state.

To prepare a new firmware image for a component, the update client calls `psa_fwu_start()`. For components with a detached manifest, the manifest data is passed as part of the call to `psa_fwu_start()`. The implementation can verify the manifest at this point, or can defer verification until later in the process.

The update client can now transfer the firmware image data to the firmware store by calling `psa_fwu_write()` one or more times. In systems with sufficient resources, the firmware image can be transferred in a single call. In systems with limited RAM, the update client can transfer the image incrementally, and specify the location of the provided data within the overall firmware image.

When all of the firmware image has been transferred to the update service, the update client calls `psa_fwu_finish()` to complete the preparation of the candidate firmware image. The implementation can verify the manifest and verify the image at this point, or can defer this until later in the process.

If preparation is successful, the component is now in CANDIDATE state.

To abandon a component update at any stage during the image preparation, the update client calls `psa_fwu_cancel()`, and the `psa_fwu_clean()` to remove the abandoned firmware image.

.. _multi-component-updates:

Multi-component updates
~~~~~~~~~~~~~~~~~~~~~~~

A system with multiple components might sometimes require that more than one component is updated atomically.

To update multiple components atomically, all of the new firmware images must be prepared as candidates before proceeding to the installation step.

Installing the candidate firmware image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once the images have been prepared as candidates, the update client calls `psa_fwu_install()` to begin the installation process. This operation will apply to all components in CANDIDATE state. The implementation will complete the verification of the manifest data at this point, and can also verify the new firmware image.

Invoking the new firmware image can require part, or all, of the system to be restarted. If this is required, the affected components will be in STAGED state, and the call to `psa_fwu_install()` returns a status code that informs the update client of the action required.

If a system restart is required, the update client can call `psa_fwu_request_reboot()`. If a component restart is required, this requires an :scterm:`implementation defined` action by the update client.

When the update requires a system reboot, the bootloader will perform additional manifest and firmware image verification, prior to invoking the new firmware. On restart, the update client must query the component status to determine the result of the installation operation within the bootloader.

If the installation succeeds, the components will be in TRIAL or UPDATED state.

Testing the new firmware image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some components need to execute the new firmware to verify the updated functionality, before accepting the new firmware. For systems that implement a rollback-prevention policy, the testing is done with the component in TRIAL state. The tests are run immediately after the update, and results used to determine whether to accept or reject the update.

The update client reports a successful test result by calling `psa_fwu_accept()`. In an atomic, multi-component update, this will apply to all of the components in the update. The components will now be in UPDATED state.

The update client reports a test failure by calling `psa_fwu_reject()`. In an atomic, multi-component update, this will apply to all of the components in the update. Rolling back to the previous firmware can require part, or all, of the system to be restarted. If this is required, the affected components will be in REJECTED state, and the call to `psa_fwu_reject()` returns a status code that informs the update client of the action required. If a restart is not required, then following the call to `psa_fwu_reject()`, the components will now be in FAILED state.

The updated firmware is automatically rejected if the system restarts while a component is in TRIAL state.

.. admonition:: Implementation note

   Where possible, it is recommended that a firmware update can be accepted by the system prior to executing the new firmware. This reduces the complexity of the firmware update process, and reduces risks related to firmware rollback. However, for complex devices that require very reliable, remote update, support for in-field testing of new firmware can be important.

Cleaning up the firmware store
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After a successful, failed, or abandoned update, the storage containing the inactive firmware image needs to be reclaimed for reuse. The update client calls to `psa_fwu_clean()` to do this.

.. rationale::

   Erasing non-volatile storage can be a high-latency operation. In some systems, this activity might block other memory i/o operations, including code execution. Isolating the erase activity within the call to `psa_fwu_clean()` enables an update client to manage when such disruptive actions take place.

.. TODO later

   Example flow
   ^^^^^^^^^^^^

   *TODO*

   .. todo:: Provide an activity/flow chart that shows typical decision logic for an update client

Bootloader operation
--------------------

When the bootloader is involved in the firmware installation process, it does more than select and verify a firmware image to execute. This section describes the responsibilities of the bootloader for the type of component depicted in :secref:`state-transitions`.

Determine firmware state
^^^^^^^^^^^^^^^^^^^^^^^^

The bootloader checks the state of each component:

*  If there are any STAGED components, proceed to install them. See :secref:`boot-install`.
*  If there are any TRIAL or REJECTED components, proceed to roll them back. See :secref:`boot-rollback`.
*  If staging is volatile, and there are any WRITING, FAILED, or UPDATED components, proceed to clean their firmware store.
*  Otherwise, proceed to boot the firmware. See :secref:`boot-execute`.

.. note::

   The design of the state model prevents the situation in which there is a STAGED component at the same time as a TRIAL or REJECTED component.

.. _boot-install:

Install components
^^^^^^^^^^^^^^^^^^

If the implementation defers verification of the updated firmware to the bootloader, or the bootloader does not trust the update service (see :secref:`untrusted-service`), the bootloader must verify all components that are in STAGED state. If verification fails, all STAGED components are set to FAILED state, and the reason for failure stored for retrieval by the update client. The bootloader proceeds to boot the existing firmware. See :secref:`boot-execute`.

The new firmware images for all STAGED components are installed as the *active* firmware. If the installation fails for any component, the previous images are restored for all components, the components are set to FAILED state, and the reason for failure stored for retrieval by the update client. The bootloader proceeds to boot the existing firmware. See :secref:`boot-execute`.

If the components require the new firmware to be tested before acceptance, the bootloader stores the previously *active* firmware images as backup, for recovery if the new firmware images fail. The components are set to TRIAL state, and the bootloader proceeds to boot the new firmware. See :secref:`boot-execute`.

Otherwise, the components are set to UPDATED state, and the bootloader proceeds to boot the new firmware. See :secref:`boot-execute`.

.. _boot-rollback:

Rollback trial components
^^^^^^^^^^^^^^^^^^^^^^^^^

If the system restarts while components are in TRIAL state, or after an update has been explicitly rejected by the update client, the bootloader restores the previous firmware images for the affected components as the *active* image. These images were stored as a backup during the installation of the firmware being tested (see :secref:`boot-install`).

The components are set to FAILED state, and the reason for failure stored for retrieval by the update client. This will result in the firmware images, that failed the trial, being erased when the update client carries out a ``clean`` operation.

The bootloader proceeds to boot the previous firmware. See :secref:`boot-execute`.

.. _boot-execute:

Authenticate and execute *active* firmware
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In a system that implements a :term:`secure boot` policy, the bootloader verifies the integrity and authenticity of the *active* firmware. If this verification fails, the result is :scterm:`implementation defined`, for example:

*  The bootloader can rollback to a previous firmware image, if one is available and policy permits.
*  The bootloader can run a special recovery firmware image, if this is provided by the system.
*  The device can become non-functional and unrecoverable.

Otherwise, the bootloader will complete initialization and transfer execution to the *active* firmware image.

.. TODO later

   Example flow
   ^^^^^^^^^^^^

   *TODO*

   .. todo:: example bootloader flow diagram.


Sample sequence during firmware update
--------------------------------------

:numref:`fig-sequence` is a detailed sequence diagram shows how the overall logic could be implemented.

.. figure:: /figure/sequence.*
   :name: fig-sequence
   :scale: 58%

   A sequence diagram showing an example flow
