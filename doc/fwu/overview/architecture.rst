.. SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _architecture:

Architecture
============

Concepts and terminology
------------------------

This section describes important concepts and terminology used in the |API| specification.

:numref:`fig-architecture` identifies the main actors and agents involved in a typical firmware update scenario.

.. figure:: /figure/arch/components.*
   :name: fig-architecture

   The |API| in context


Firmware image
^^^^^^^^^^^^^^

A firmware image, or simply the "image", is a binary that can contain the complete software of a device or a subset of it. A firmware image can consist of multiple images if the device contains more than one microcontroller. It can also be a compressed archive that contains code, configuration data, and even the entire file system. An image may consist of a differential update for performance reasons.

The terms "firmware image", "firmware", and "image" are used in this document and are interchangeable.

.. _manifest:

Manifest
^^^^^^^^

A manifest contains metadata about the firmware image. The manifest is typically protected against modification using a signed hash of its contents, see :secref:`manifest-verification`.

Metadata that can be in a manifest includes the following:

*  The intended device, which might be a specific instance or class.
*  The intended device component.
*  The version or serial-number of the firmware image.
*  A digest of the image.
*  Information relating to rollback prevention, or other security policies.
*  Dependencies on other firmware images.
*  Hints or explicit instructions on how to decrypt, decompress or install an image.
*  Information on additional steps required to apply the update.

A manifest can be bundled within the firmware image, or detached from it.

Component
^^^^^^^^^

A component is a logical part of the device which needs a firmware image. Each firmware image is designed for exactly one component.

A component can have a one to one correspondence with a physical processor in the system, other mappings are possible:

*  A single physical processor might have multiple components. For example:

   -  If the :term:`SPE` and :term:`NSPE` have separate firmware images, these are separate components.
   -  If configuration data for the system can be updated independently, this is a separate component.

*  Multiple processors, or even the whole system, can have the firmware packaged together in a single firmware image. As a whole, this forms a single component in the context of the |API|.

Component identifier
^^^^^^^^^^^^^^^^^^^^

The component identifier is a small numerical value, that precisely identifies the component within this device.

The identifier values are typically allocated by the device developer or integrator. A component identifier can be used within the manifest during the update process, or can be translated from another identification scheme via a mapping configured in the update client.

Firmware creator
^^^^^^^^^^^^^^^^

A developer or integrator of the firmware for the device being updated.

The firmware creator is responsible for constructing firmware images and manifests for the device. For devices that implement a :term:`secure boot` protocol, the firmware creator signs the manifest using a signing key associated with a trust anchor on the device. See :secref:`trust-anchor`.

In systems with multiple components, each component can have a different firmware creator.

Update server
^^^^^^^^^^^^^

A system within the operational network of the device that hosts firmware images and manages the rollout of updates to devices within that network.

Update client
^^^^^^^^^^^^^

The update client is a software component that obtains firmware images. For example, this can be downloaded from an update server, or accessed from an attached storages device. When it obtains an image, it transfers it to the update service using the interface described in this document.

The update client runs as part of the :term:`application firmware`.

It can report device identity and installation state to a remote party, such as the update server. For example, the reported installation state can include the versions of installed images and error information of images that did not install successfully.

Update service
^^^^^^^^^^^^^^

The update service is a software component that stores a firmware image in device memory, ready for installation. The update service implements the interface described in this document.

Depending on the system design, the installation process can be implemented within the update service, or it can be implemented within a bootloader or other system component.

.. _arch-firmware-store:

Firmware store
^^^^^^^^^^^^^^

The firmware store is the location where firmware images are stored. Conceptually the firmware store is shared between the update service and the bootloader. Both components share access to the firmware store to manage the firmware update process.

The |API| presents a separate firmware store for each component. Each component's firmware store can have one or more images present. The state of the firmware store determines how those images are used, and what is required to proceed with a firmware update.

The :term:`staging area` is a region within a firmware store used for a firmware image that is being transferred to the device. Once transfer is complete, the image in the staging area can be verified during installation.

Bootloader
^^^^^^^^^^

A bootloader selects a firmware image to execute when a device boots. The bootloader can also implement the verification and installation process for a firmware update.

In a system that implements :term:`secure boot`, the bootloader will always verify the authenticity of the firmware image prior to execution.

.. _trust-anchor:

Trust anchor
^^^^^^^^^^^^

A device contains one or more trust anchors. A trust anchor is used to check if an image, or its manifest, are signed by a signing authority that the device trusts.

Each trust anchor is pre-provisioned on the device. A trust anchor can be implemented in many ways, but typically takes the form of a public key or a certificate chain, depending on the complexity of the trust model.

The management and provisioning of trust anchors is not within the scope of this document.


.. _formats:

Firmware image format
---------------------

The |API| does not define the format for the firmware image and manifest. This is defined and documented by the implementation, so that a firmware creator can construct valid firmware images and manifests for the device.

The |API| assumes that manifests and firmware images passed to the update service conform to the format expected by the implementation. The implementation is responsible for verifying that data provided by the client represents a valid manifest or firmware image.

Examples of the firmware image and manifest design details that need to be provided by the implementation, include the following:

*  Whether the manifest is detached from, or bundled with, the firmware image.
*  The format and encoding of the manifest and firmware image.
*  The attributes provided by the manifest, and their impact on processing of the firmware image.
*  Support for encrypted, compressed, or delta firmware image.
*  Firmware image integrity and authentication data.

If firmware images must be signed --- for example, for devices implementing :term:`secure boot` --- the device creator must enable the firmware creator to sign new firmware images in accordance with the device policy.

For some deployments, the firmware and manifest formats used by a device can be affected by the protocols used by the update server and update client to notify and transfer firmware updates. In other deployments, the update server and update client can have independent formats for describing firmware updates, to those used by the firmware creator and update service.


.. _deployment:

Deployment scenarios
--------------------

There are different ways in which the |API| can be implemented, that apply to different system designs. The primary differences relate to the presence and location of trust boundaries within the system, in particular trust boundaries that protect a device :term:`Root of Trust`.

The implementation architecture can affect the behavior of the |API|, particularly in regard to if, and when, a firmware update is verified.

These implementation architectures provide use cases for the design of the |API|.

.. _untrusted-client:

Untrusted client
^^^^^^^^^^^^^^^^

:numref:`fig-untrusted-client` shows an implementation architecture for a system where the firmware store is fully protected by the :term:`Platform Root of Trust` (PRoT).

.. figure:: /figure/arch/untrusted-client.*
   :name: fig-untrusted-client

   Implementation architecture with an untrusted update client

In this architecture, part of the update service must run as a service within the PRoT, to query and update the firmware store. The update client accesses this service via an update service proxy library, which implements the |API|.

The |API| is designed for implementation across a security boundary, as used in this architecture. The interface between the update service proxy and the update service itself is :scterm:`implementation defined`.

This architecture enables all of the firmware verification requirements to be fulfilled by the update service within the PRoT.

As the PRoT trusts the update service, but not the update client, this architecture is referred to as an *untrusted client* implementation.

.. _untrusted-staging:

Untrusted staging
^^^^^^^^^^^^^^^^^

:numref:`fig-untrusted-staging` shows an implementation architecture for a system where the *active* image is protected by the :term:`Platform Root of Trust` (PRoT), but the staging area for a new firmware image is not protected from access by the update client.

.. figure:: /figure/arch/untrusted-staging.*
   :name: fig-untrusted-staging

   Implementation architecture with an untrusted update service and staging

The staging area is accessible to untrusted components, so the bootloader cannot trust any verification done by the update service prior to system restart. The bootloader must do all firmware verification prior to completing installation of the firmware.

In this type of implementation, it is still beneficial for the update service to perform some verification of firmware updates: this can reduce the system impact of a malicious or accidental invalid update.

As the PRoT does not trust the staging, or the update service which writes to it, this architecture is referred to as an *untrusted staging* implementation.

.. _trusted-client:

Trusted client
^^^^^^^^^^^^^^

:numref:`fig-trusted-client` shows an implementation architecture for a system where the update client application is within the system's Root of Trust.

.. figure:: /figure/arch/trusted-client.*
   :name: fig-trusted-client

   Implementation architecture with a trusted update client

In this architecture, it is permitted for verification of an update to happen in any component, including the update client itself. This approach can be suitable for highly constrained devices, and relies on the security provided by the protocol used between the update server and update client.

.. warning::

   If the implementation assumes that manifests and firmware images provided by the client are valid, and carries out the preparation and installation without further verification, then the |API| is being used purely as a hardware abstraction layer (HAL) for the firmware store.

   An implementation like this must clearly document this assumption to ensure update clients carry out sufficient verification of firmware manifests, firmware images, and firmware dependencies before calling the |API|.

This implementation architecture can also be used in a device that does not enforce a :term:`secure boot` policy. For example, this can enable code reuse by using a single API for firmware update across devices that have different security requirements and policies. Although permitted by the |API|, this usage is not a focus for this specification.
