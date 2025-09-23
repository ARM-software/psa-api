.. SPDX-FileCopyrightText: Copyright 2020-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Introduction
============

About Platform Security Architecture
------------------------------------

This document is one of a set of resources provided by Arm that can help organizations develop products that meet the security requirements of GlobalPlatform's PSA Certified evaluation scheme on Arm-based platforms. The PSA Certified scheme provides a framework and methodology that helps silicon manufacturers, system software providers and OEMs to develop more secure products. Arm resources that support PSA Certified range from threat models, standard architectures that simplify development and increase portability, and open-source partnerships that provide ready-to-use software. You can read more about PSA Certified here at :url:`www.psacertified.org` and find more Arm resources here at :url:`developer.arm.com/platform-security-resources` and :url:`www.trustedfirmware.org`.

About the |API|
---------------

The interface described in this document is a PSA Certified API, that provides a portable programming interface to firmware update and installation operations on a wide range of hardware.

The interface enables the software and systems that manage and deliver a firmware update to a device, to be developed independently from the hardware-specific mechanisms required to apply the update to the device. Reusing the deployment and delivery system for firmware updates reduces the complexity of providing firmware updates across a diverse set of managed devices.

You can find additional resources relating to the |API| here at :url:`arm-software.github.io/psa-api/fwu`, and find other PSA Certified APIs here at :url:`arm-software.github.io/psa-api`.

.. _intro:

Firmware update
---------------

Connected devices need a reliable and secure firmware update mechanism. Incorporating such an update mechanism is a fundamental requirement for fixing vulnerabilities, but it also enables other important capabilities such as updating configuration settings and adding new functionality. This can be particularly challenging for devices with resource constraints, as highlighted in :rfc-title:`8240`.

:numref:`fig-context` depicts the actors and agents involved in a typical firmware update scenario.

.. figure:: /figure/intro/context.*
   :name: fig-context

   A typical over-the-air firmware update scenario

In this example, the new firmware is uploaded by the Firmware creator to an Update server. The Update server communicates with an Update client application on the device, announcing the availability of new firmware. The client downloads the new firmware, and installs it into the device firmware storage.

In :numref:`fig-context`, the Update client has to combine the following capabilities:

* The specific protocols used by the network operator in which the device is deployed
* The specific mechanism used by the hardware platform to install firmware for execution

Devices developed for the Internet of Things (IoT) have a very diverse ecosystem of hardware and software developers, and utilize a broad set of communication protocols and technologies. This will lead to a large, fragmented set of Update clients, that are each tightly coupled to one hardware platform and one network protocol.

The |API| separates the software responsible for delivering the new firmware in the device, from the software that is responsible for storing and installing it in the device memory. :numref:`fig-api` shows how the |API| separates an Update client, which obtains the new firmware from the Firmware Server, from an Update service, which stores the firmware in the device memory.

.. figure:: /figure/intro/fwu-api.*
   :name: fig-api

   The |API|

In practice, this enables an Update client to be written independently of the firmware storage design, and the Update service to be written independently of the delivery mechanism.

The remainder of this document includes:

*   The design goals for the |API|. See :secref:`design-goals`.
*   A definition of the concepts and terminology used in this document. See :secref:`architecture`.
*   A description of the interface design. See :secref:`programming-model`.
*   A detailed definition of the API. See :secref:`api-reference`.

The appendixes provide additional information:

*  A sample header file containing all of the API elements. See :secref:`appendix-example-header`.
*  Some example code demonstrating various use cases. See :secref:`examples`.
