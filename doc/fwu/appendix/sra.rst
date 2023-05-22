.. SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _sra:

Security Risk Assessment
========================

This appendix provides a Security Risk Assessment (SRA) of the |API|. It describes the threats presented by various types of adversary against the security goals for an implementation of Firmware Update, and mitigating actions for those threats.

*  :secref:`sra-about` describes the assessment methodology.
*  :secref:`sra-definition` defines the security problem.
*  :secref:`sra-characterization` provides additional security design details.
*  :secref:`sra-threats` describes the threats and the recommended mitigating actions.
*  :secref:`sra-mitigations` summarizes the mitigations, and where these are implemented.

.. _sra-about:

About this assessment
---------------------

Subject and scope
^^^^^^^^^^^^^^^^^

Secure firmware update has been the subject of a number of recent studies and working groups. These examine the challenges faced when implementing over-the-air updates to secure devices at scale, or present architectures for addressing those challenges. For example, see :rfc-title:`8240`, :rfc-title:`9019`, and :rfc-title:`9124`.

This SRA analyses the security of the |API| itself, not of any specific implementation of the API, or any specific use of the API.

The purpose of the SRA is to identify requirements on the design of the |API|. Those requirements can arise from threats that directly affect the caller and implementation of the API, but also from threats against the whole firmware update process. As a result, the assessment considers a broad set of threats to the entire firmware update process.

This SRA does not cover the :secref:`trusted-client` deployment architecture. :secref:`sra-operation` describes the effects of the deployment model on the security analysis.

.. note::

   This document is not a substitute for performing a security risk assessment of the firmware update process for a system that incorporates the |API|. However, this SRA can be used as a foundation for such an implementation-specific assessment.

Risk assessment methodology
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Our risk ratings follow the five-level version of the Arm ATG SRA methodology, which is derived
from :cite-title:`SP800-30`: for each Threat, we determine its Likelihood and the
Impact. Each is evaluated on a 5-level scale, as defined in :numref:`tab-sra-likelihood` and :numref:`tab-sra-impact`.

.. list-table:: Likelihood levels
   :name: tab-sra-likelihood
   :class: longtable
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 6

   *  -  Level
      -  Definition

   *  -  Very Low
      -  Unlikely to ever occur in practice, or *mathematically near impossible*
   *  -  Low
      -  The event could occur, but only if the attacker employs *significant* resources; or it is *mathematically unlikely*
   *  -  Medium
      -  A motivated, and well-equipped adversary can make it happen within the lifetime of a product based on the feature (resp. of the feature itself)
   *  -  High
      -  Likely to happen within the lifetime of the product or feature
   *  -  Very High
      -  Will happen, and soon (for instance a zero-day)

.. list-table:: Impact levels
   :name: tab-sra-impact
   :class: longtable
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 3 3

   *  -  Level
      -  Definition
      -  Example Effects

   *  -  Very Low
      -  Causes virtually no damage
      -  Probably none
   *  -  Low
      -  The damage can easily be tolerated or absorbed
      -  There would be a CVE at most
   *  -  Medium
      -  The damage will have a *noticeable* effect, such as *degrading* some functionality, but won't degrade completely the use of the considered functionality
      -  There would be a CVE at most
   *  -  High
      -  The damage will have a *strong* effect, such as causing a significant reduction in its functionality or in its security guarantees
      -  Security Analysts would discuss this at length, there would be papers, blog entries. Partners would complain
   *  -  Very High
      -  The damage will have *critical* consequences --- it could kill the feature, by affecting several of its security guarantees
      -  It would be quite an event.

         Partners would complain strongly, and delay or cancel deployment of the feature

For both Likelihood and Impact, when in doubt always choose the higher value. These two values are combined using :numref:`tab-sra-overall-risk` to determine the Overall Risk of a Threat.

.. csv-table:: Overall risk calculation
   :name: tab-sra-overall-risk
   :class: longtable
   :header-rows: 2
   :stub-columns: 1
   :widths: 1 1 1 1 1 1
   :align: left

   ,Impact,,,,
   Likelihood, Very Low, Low, Medium, High, Very High
   Very Low, Very Low, Very Low, Very Low, Low, Low
   Low, Very Low, Very Low, Low, Low, Medium
   Medium, Very Low, Low, Medium, Medium, High
   High, (Very) Low, Low, Medium, High, Very High
   Very High, (Very) Low, Medium, High, Very High, Very High

Threats are handled starting from the most severe ones. Mitigations will be devised for these Threats one by one (note that a Mitigation may mitigate more Threats, and one Threat may require the deployment of more than one Mitigation in order to be addressed). Likelihood and Impact will be reassessed assuming that the Mitigations are in place, resulting in a Mitigated Likelihood (this is
the value that usually decreases), a Mitigated Impact (it is less common that this value will decrease), and finally a Mitigated Risk. The Analysis is completed when all the Mitigated Risks are at the chosen residual level or lower, which usually is Low or Very Low.

The Mitigating actions that can be taken are defined in the acronym **CAST**:

*  **Control**: Put in place steps to reduce the Likelihood and/or Impact of a Threat, thereby reducing the risk to an acceptable level.
*  **Accept**: The threat is considered to be of acceptable risk such that a mitigation is not necessary, or must be accepted because of other constraint or market needs.
*  **Suppress**: Remove the feature or process that gives rise to the threat.
*  **Transfer**: Identify a more capable or suitable party to address the risk and transfer the responsibility of providing a mitigation for the threat to them.

.. _sra-definition:

Feature definition
------------------

Introduction
^^^^^^^^^^^^

Background
~~~~~~~~~~

Using firmware updates to fix vulnerabilities in devices is important, but securing this update mechanism is equally important since security problems are exacerbated by the update mechanism. An update is essentially authorized remote code execution, so any security problems in the update process expose that remote code execution system. Failure to secure the firmware update process will help attackers take control of devices.

:secref:`intro` provides the context in which the |API| is designed. :numref:`fig-background` is a reproduction of :numref:`fig-api` that illustrates where the |API| fits in the overall firmware update process.

.. figure:: /figure/intro/fwu-api.*
   :name: fig-background

   A firmware update process

Purpose
~~~~~~~

The |API| separates the software responsible for delivering the new firmware in the device, from the software that is responsible for storing and installing it in the device memory. :numref:`fig-background` shows how the |API| separates an update client, which obtains the new firmware from the update server, from an update service, which stores the firmware in the device memory.

The API enables an update client to be written independently of the firmware storage design, and the update service to be written independently of the delivery mechanism.

Function
~~~~~~~~

The |API| provides an interface by which an update client can query the state of firmware components that are managed by the service, prepare firmware updates for those components, and initiate the installation of the updates.


Lifecycle
^^^^^^^^^

:numref:`fig-lifecycle` shows the typical lifecycle of a device that provide firmware updates.

.. figure:: /figure/sra/lifecycle.*
   :name: fig-lifecycle

   Device lifecycle of a system providing firmware updates

The software implementing the on-device firmware update functionality, and the credentials for authorizing the update process, are installed or provisioned to device prior to its operational phase.

The firmware update process, and the |API| are active during the operational phase, implemented within the boot-time and run-time software.

.. _sra-operation:

Operation and trust boundaries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following operational dataflow diagrams include all of the main components in a firmware update process. Presenting the context in which the |API| operates aids understanding of the threats and security mitigations, and provides the rationale for some elements of the API design.

The firmware creator and update server components are representative: in a real implementation of the process these roles may be distributed amongst multiple systems and stakeholders.

|API| is a C language API. Therefore, any implementation of the API must execute, at least partially, within the context of the calling application. When an implementation includes a trust boundary, the mechanism and protocol for communication across the boundary is :scterm:`implementation defined`.

The |API| supports implementation in various deployment architectures, described in :secref:`deployment`. The operation and dataflow of the firmware update process is similar across these deployments. However, the trust boundaries within the device are different.

:numref:`fig-dm-trusted-client` shows the simplest deployment --- *Trusted client* --- which has no trust boundaries within the device. This deployment is described in :secref:`trusted-client`.

However, the threat model for this deployment shares very little with the threat model for the other deployments, which include a :term:`Root of Trust`. In particular, the attack surface lies outside of the |API| and its implementation, and mitigations for relevant threats to this deployment do not result in additional security requirements for the API.

As a consequence, this SRA **does not** provide an assessment of the mitigations required for the *Trusted client* deployment architecture. See also :secref:`sra-assumptions`.

.. figure:: /figure/sra/dm-trusted-client.*
   :name: fig-dm-trusted-client

   Operational dataflow diagram for firmware update in a 'Trusted client' deployment

   The individual dataflows are described in :numref:`tab-dm-dataflow`.

.. list-table:: Dataflow descriptions for the firmware update process
   :name: tab-dm-dataflow
   :class: longtable
   :header-rows: 1
   :widths: 1 5

   *  -  Dataflow
      -  Description

   *  -  DF.A
      -  The firmware creator uploads a firmware update to the update server.
   *  -  DF.B
      -  Communication between the update server and a managed device that supports firmware update, to track firmware status and deliver updates.
   *  -  DF.C
      -  The |API|, used by the update client to query component state and prepare firmware updates for installation.
   *  -  DF.D
      -  *Active* firmware image state read by the update service.
   *  -  DF.E
      -  Update service i/o to the *second* image, to read the component state and prepare images for update.
   *  -  DF.F
      -  Bootloader i/o to the *active* image, to install a firmware image, or to authenticate it.
   *  -  DF.G
      -  Bootloader i/o to the *second* image, to verify an update and install it.


Deployment models
^^^^^^^^^^^^^^^^^

This SRA is relevant for the deployment architectures, described in :secref:`deployment`, that include a Root of Trust within the device.

:deployment-model:`UNTRUSTED_CLIENT` deployment model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This deployment model corresponds to the deployment architecture shown in :secref:`untrusted-client`. :numref:`fig-dm-untrusted-client` shows the dataflow diagram for this deployment, and :numref:`tab-dm-dataflow` describes the dataflows.

A detailed dataflow is provided in :secref:`sra-characterization`.

.. figure:: /figure/sra/dm-untrusted-client.*
   :name: fig-dm-untrusted-client

   Operational dataflow diagram for `DM.UNTRUSTED_CLIENT`

   The individual dataflows are described in :numref:`tab-dm-dataflow`.


:deployment-model:`UNTRUSTED_STAGING` deployment model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This deployment model corresponds to the deployment architecture shown in :secref:`untrusted-staging`. :numref:`fig-dm-untrusted-staging` shows the dataflow diagram for this deployment. The dataflow is described by :numref:`tab-dm-dataflow`, the same as for `DM.UNTRUSTED_CLIENT`.

A detailed dataflow is provided in :secref:`sra-characterization`.

.. figure:: /figure/sra/dm-untrusted-staging.*
   :name: fig-dm-untrusted-staging

   Operational dataflow diagram for `DM.UNTRUSTED_STAGING`

   The individual dataflows are described in :numref:`tab-dm-dataflow`.

The *second* image in the firmware store is accessible to untrusted software. The Root of Trust protects the *active* image from modification by untrusted software. In this deployment model, there is no benefit from implementing the update service within the Root of Trust:

*  The update service only communicates with the bootloader via the data in the firmware store.
*  As the *second* image can be modified by untrusted components, the content and state of the *second* image is not trusted until the bootloader has verified the update.

In this deployment model, the update service can be implemented entirely as software library that runs within the update client execution context.

.. _sra-assumptions:

Assumptions and constraints
^^^^^^^^^^^^^^^^^^^^^^^^^^^

*  This SRA assumes that the system implements a :term:`Root of Trust`, with, at least, the following capabilities:

   -  The Root of Trust implements a :term:`Secure boot` process that ensures that all firmware is authorized prior to execution when the device boots.
   -  The *active* firmware image cannot be modified by the system after the bootloader has authenticated the firmware.

   Although the |API| can be used to provide a firmware update service in a system that does not have a Root of Trust, or implement Secure boot, such a system is not considered within this SRA.

*  Within the scope of `AM.1`, the adversary is assumed to have the ability to execute software within the context of the caller of the |API|, or other untrusted components. The adversary is assumed to not have software execution capability within the Root of Trust.

   For example, this might be achieved by an adversary that initially has remote access to the device (`AM.0`), who then exploits a vulnerability in the firmware to achieved local code execution (`AM.1`).


As a result of these assumptions:

*  Threats to the interfaces outside the device (DF.A and DF.B in :numref:`tab-dm-dataflow`) are equivalent in effect to threats against the interface between the update client and update service (DF.C). This security analysis focuses on the latter dataflows.

*  Threats to the interfaces within the Root of Trust are assumed to be mitigated by the Root of Trust implementation.

.. comment:

   Interacting entities
   ^^^^^^^^^^^^^^^^^^^^


Stakeholders and assets
^^^^^^^^^^^^^^^^^^^^^^^

The following assets are considered in this assessment:

Device firmware
   The device manufacturers (SiP, OEM), and device operator are interested in the integrity and authenticity of the device software.

   The firmware developers (SiP, OEM, ISV) might also be concerned about the confidentiality of the firmware. Disclosure of the firmware can reveal confidential IP, or reduce the cost of finding and exploiting a vulnerability in the device.

Device firmware manifest
   The device manufacturers (SiP, OEM), and device operator are interested in the integrity and authenticity of the firmware metadata within the firmware manifest.

Reliability of device operation
   The device operator is concerned about the availability of the device to execute the application firmware.

All stakeholders are concerned about the integrity of their reputation with regards to device security, and liability for security failures. A scalable security flaw related to firmware update, or an inability to use firmware update to address a security issue, can have a significant impact on the stakeholders.

Security goals
^^^^^^^^^^^^^^

The following security goals are applicable for all systems which implement the |API|:

:security-goal:`AUTHENTIC`
   An adversary is unable to install, or cause to be installed, a firmware image that is not valid and authorized for the device.

:security-goal:`RELIABLE`
   An adversary is unable to use the firmware update process to render the device inoperable.

The following security goal is applicable for some systems which implement the API:

:security-goal:`CONFIDENTIAL`
   An adversary is unable to disclose the content of a firmware image.

Adversarial model
^^^^^^^^^^^^^^^^^

Adversarial models are descriptions of capabilities that adversaries of systems implementing the |API| can have, grouped into classes. The adversaries are defined in this way to assist with threat modelling an abstract API, which can have different implementations, in systems with a wide range of security sensitivity.

:adversarial-model:`0`
   The Adversary is only capable of accessing data that requires neither physical access to a system containing an implementation of the feature nor the ability to run software on it. This Adversary is intercepting or providing data or requests to the target system via a network or other remote connection.

   For instance, the Adversary can:

   *  Read any input and output to the target through external devices.
   *  Provide, forge, replay or modify such inputs and outputs.
   *  Perform timings on the observable operations being done by the target machine, either in normal operation or as a response to crafted inputs. For example, timing attacks on web servers.

:adversarial-model:`1`
   The Adversary can additionally mount attacks from software running on a target device implementing the feature. This type of Adversary can run software on the target.

   For instance, the Adversary can:

   *  Attempt software exploitation by running software on the target.
   *  Exploit access to any memory mapped configuration, monitoring, debug register.
   *  Mount any side channel analysis that relying on software-exposed built-in hardware features to perform physical unit and time measurements.
   *  Perform software-induced glitching of resources such as Rowhammer, RASpberry or crashing the CPU by running intensive tasks.

:adversarial-model:`2`
   In addition to the above, the Adversary is capable of mounting hardware attacks and fault injection that does not require breaching the physical envelope of the chips. This type of Adversary has access to a system containing an implementation of the target feature.

   For instance, the Adversary can:

   *  Conduct side-channel analysis that requires measurement devices. For example, this can utilize leakage sources such as EM emissions, power consumption, photonics emission, or acoustic channels.
   *  Plug malicious hardware into an unmodified system.
   *  Gain access to the internals of the target system and interpose the SoC or memory for the purposes of reading, blocking, replaying, and injecting transactions.
   *  Replace or add chips on the motherboard.
   *  Make simple, reversible modifications, to perform glitching.

:adversarial-model:`3`
   In addition to all the above, the Adversary is capable of performing invasive SoC attacks.

   For instance, the Adversary can:

   *  Decapsulate a chip, via laser or chemical etching, followed by microphotography to reverse engineer the chip.
   *  Use a focussed ion beam microscope to perform gate level modification.

The adversarial models that are in scope for a firmware update process depend on the product requirements. To ensure that the |API| can be used in a wide range of systems, this assessment considers adversarial models `AM.0`, `AM.1`, and `AM.2` to be in-scope.

.. _sra-characterization:

Feature characterization
------------------------

Detailed deployment dataflow
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following diagrams expand on the diagrams in :secref:`sra-operation` to show the detailed operational dataflow during the firmware update process.

:numref:`fig-dm-untrusted-client-detail` shows the detailed dataflow diagram for the `DM.UNTRUSTED_CLIENT` deployment, and :numref:`tab-dm-dataflow-detail` describes each dataflow.

.. figure:: /figure/sra/dm-untrusted-client-detail.*
   :name: fig-dm-untrusted-client-detail

   Detailed dataflow diagram for `DM.UNTRUSTED_CLIENT`

   The individual dataflows are described in :numref:`tab-dm-dataflow-detail`.

.. list-table:: Detailed dataflow descriptions for the firmware update process
   :name: tab-dm-dataflow-detail
   :class: longtable
   :header-rows: 1
   :widths: 1 5

   *  -  Dataflow
      -  Description

   *  -  DF.1
      -  The update service reads status information for the protected, *active* image, and the unprotected *second* image.
   *  -  DF.2
      -  Firmware information in response to |API| query.
   *  -  DF.3
      -  [Optional] Cient reports device firmware status to online Status Tracker.
   *  -  DF.4
      -  Firmware creator loads a firmware update containing new firmware images to the update server. Images are signed by firmware creator to authenticate their origin. See :secref:`sra-assumptions`.
   *  -  DF.5
      -  [Optional] Update server issues notification to device about the firmware update.

         Alternatively, device periodically polls server to discover update.
   *  -  DF.6, DF.7
      -  Device requests and downloads firmware update images from the update server.
   *  -  DF.8
      -  Update client uses |API| to prepare the firmware images for update.
   *  -  DF.9
      -  Update service writes new firmware images into the firmware store's staging area.
   *  -  DF.10
      -  [Optional] Device reports to the update server that the update is ready.

         Alternatively, the device immediately installs the prepared update.
   *  -  DF.11
      -  [Optional] Update server issues command to device to apply the update.
   *  -  DF.12
      -  Update client uses |API| to request installation of the update.
   *  -  DF.13
      -  Update service marks the prepare firmware update as ready for installation.
   *  -  DF.14
      -  Bootloader inspects the *second* image, to determine if an update is ready for installation.
   *  -  DF.15, DF.16
      -  Bootloader verifies the update, and installs it as the *active* image.

         [Optional] Bootloader retains the previous firmware image for rollback.
   *  -  DF.17
      -  Bootloader authenticates the firmware image, and then executes it.

:numref:`fig-dm-untrusted-staging-detail` shows the detailed dataflow diagram for the `DM.UNTRUSTED_STAGING` deployment. The dataflows are described by :numref:`tab-dm-dataflow-detail`, the same as for `DM.UNTRUSTED_CLIENT`.

.. figure:: /figure/sra/dm-untrusted-staging-detail.*
   :name: fig-dm-untrusted-staging-detail

   Detailed dataflow diagram for `DM.UNTRUSTED_STAGING`

   The individual dataflows are described in :numref:`tab-dm-dataflow-detail`.


.. _sra-api-features:

Security features of the API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following aspects of the |API| result from the mitigations identified by this assessment:

*  The behavior of memory buffer parameters is fully specified. See also :secref:`pointer-conventions`.
*  The API provides a full state model for the firmware update process. See :secref:`state-model`. Common variations are also defined in :secref:`variations`.
*  Firmware images are not automatically staged for installation after being written to the firmware store, to support atomic update of multiple images. See also :secref:`state-rationale`.
*  A TRIAL state is provided to permit a new firmware image to be tested, and then reverted to the previous image in case of a fault. See also :secref:`state-rationale`.

The different deployment models, and variability in the adversarial model in scope for a particular product, requires that the |API| provides the following features:

*  Flexibility in when a firmware update is verified: verification errors can be reported from multiple functions. See also :secref:`verifying-an-update`.

Some mitigations are required in the format of the firmware image or the firmware manifest. The |API| does not specify a firmware update format --- see :secref:`formats` --- and enables the following aspects to be included in the firmware image or manifest, as required for the implementation:

*  Compatibility information that identifies the system and component the firmware image is intended for.
*  Description and verification of dependencies between firmware images.
*  Authentication of the firmware image and manifest.
*  Encryption of the firmware image and manifest.


.. _sra-threats:

Threats
-------

Because |API| can be used in a wide range of deployment models and a wide range of threats, not all mitigating actions apply to all scenarios. As a result, various mitigations are optional to implement, depending on which threats exist in a particular domain of application, and which firmware update use cases are important for deployments.

:numref:`tab-sra-threats` summarizes the threats.

.. csv-table:: Summary of threats
   :name: tab-sra-threats
   :class: longtable
   :widths: 1 3
   :header-rows: 1

   Threat, Description
   `T.TAMPER`, Tampering with the firmware image or manifest
   `T.NON_FUNCTIONAL`, Install defective firmware
   `T.ROLLBACK`, Install old firmware
   `T.SKIP_INTERMEDIATE`, Skip intermediate update
   `T.DEGRADE_DEVICE`, Repeatedly install invalid firmware
   `T.INTERFACE_ABUSE`, Call the API with illegal inputs
   `T.TOCTOU`, Modify asset between authentication and use
   `T.PARTIAL_UPDATE`, Trigger installation of incomplete update
   `T.INCOMPATIBLE`, Install firmware for a different device
   `T.DISCLOSURE`, Unauthorized disclosure of a firmware image or manifest
   `T.SERVER`, Exploiting or spoofing the update server
   `T.CREATOR`, Spoofing the firmware creator
   `T.NETWORK`, Manipulation of network traffic outside the device


.. threat:: Tampering with the firmware image or manifest
   :id: TAMPER

   .. description::
      An attacker modifies the firmware image or firmware manifest to cause a malfunction in the installer.

      For example:

      *  If a device misinterprets the format of the firmware image, it may cause a device to install a firmware image incorrectly. An incorrectly installed firmware image would likely cause the device to stop functioning.
      *  If a device installs a firmware image to the wrong location on the device, then it is likely to break.

      This can cause device malfunction, or enable elevation of privilege.

   .. security-goal:: `SG.AUTHENTIC`, `SG.RELIABLE`
   .. adversarial-model:: `AM.0`, `AM.1`

   .. unmitigated::
      :impact: H
      :likelihood: H

   .. mitigations::
      Secure boot (see :secref:`sra-assumptions`) will prevent tampered firmware images from executing, but installation of such images can leave the device inoperable.

      :mitigation:`AUTHENTICATE`. **Transfer** to firmware creator and implementation: authenticate the content of the firmware image manifest and firmware images to prevent unauthorized modification. For detached manifests this can be achieved by including a cryptographic hash of the firmware image in the manifest, and then signing the manifest with an authorized key. The |API| design must enable authentication of firmware images and manifests.

      :mitigation:`TRIAL`. **Control** by API design: provide a firmware image state where a failure to run a new firmware image will cause a roll back to the previously installed firmware, instead of making the device inoperable, without bypassing `M.SEQUENCE`. **Transfer** to implementation and update client: use the provided TRIAL state in the firmware update process.


   .. residual::
      :impact: H
      :likelihood: VL

.. threat:: Install defective firmware
   :id: NON_FUNCTIONAL

   .. description::
      An attacker sends a firmware update to a device that is known to not function correctly. If the firmware update function is non-operational following this update, the device also cannot be recovered without a physical repair.

   .. security-goal:: `SG.RELIABLE`
   .. adversarial-model:: `AM.0`, `AM.1`

   .. unmitigated::
      :impact: H
      :likelihood: M

   .. mitigations::
      `M.TRIAL`. Ensure a device can recover if a new firmware image cannot boot.

   .. residual::
      :impact: H
      :likelihood: VL

.. threat:: Install old firmware
   :id: ROLLBACK

   .. description::
      An attacker sends an old, but otherwise valid, firmware update to a device. If there is a known vulnerability in the provided firmware image, this may allow an attacker to exploit the vulnerability and gain control of the device.

   .. security-goal:: `SG.AUTHENTIC`
   .. adversarial-model:: `AM.0`, `AM.1`

   .. unmitigated::
      :impact: H
      :likelihood: M

   .. mitigations::
      :mitigation:`SEQUENCE`. **Transfer** to the firmware creator and implementation. Firmware images, or their manifests, must be monotonically sequenced for the device, or for each component within a device. The implementation will deny an attempt to install an update with a sequence number that is lower than the currently installed firmware.

      This mitigation creates a fragility when an update is non-functional, and requires the implementation of `M.TRIAL` to maintain availability in case of a non-functional update. See also `T.NON_FUNCTIONAL`.

   .. residual::
      :impact: H
      :likelihood: VL

.. threat:: Skip intermediate update
   :id: SKIP_INTERMEDIATE

   .. description::
      An attacker sends a valid firmware update to the device, that requires an intermediate update to be installed first.

      Following update the device might operate incorrectly, or can be left completely inoperable.

   .. security-goal:: `SG.RELIABLE`
   .. adversarial-model:: `AM.0`, `AM.1`

   .. unmitigated::
      :impact: H
      :likelihood: M

   .. mitigations::
      :mitigation:`CHECK_DEPENDENCY`. **Transfer** to the implementation: dependencies between firmware images are declared in the firmware image or manifest, and verified by the implementation. The |API| design must enable verification of firmware images.

   .. residual::
      :impact: H
      :likelihood: VL

.. threat:: Repeatedly install invalid firmware
   :id: DEGRADE_DEVICE
   :deployment-models: UNTRUSTED_CLIENT, UNTRUSTED_STAGING

   An attacker repeatedly causes an attempted installation of invalid firmware, to make the installation process disrupt the application availability, or excessively degrade the firmware store non-volatile memory.

   .. security-goal:: `SG.RELIABLE`
   .. adversarial-model:: `AM.0`, `AM.1`

   .. unmitigated:: UNTRUSTED_CLIENT
      :impact: H
      :likelihood: M

   .. unmitigated:: UNTRUSTED_STAGING
      :impact: H
      :likelihood: M

   .. mitigations::
      :mitigation:`VERIFY_EARLY`. **Transfer** to the update client and the implementation: verify firmware images as early as possible in the update process, to detect and reject an invalid update. This can reduce the storage of invalid image data in the firmware store, prevent unnecessary device reboots, and eliminate installation of firmware that will be rejected by a Secure boot process. The |API| design must permit verification to occur at all appropriate firmware update operations.

      .. warning::

         Although verification outside of the Root of Trust can reduce the likelihood of this threat, it is insufficient to mitigate attackers that can bypass such a check. See also `T.TOCTOU`.

   .. residual:: UNTRUSTED_CLIENT
      :impact: H
      :likelihood: VL

   .. residual:: UNTRUSTED_STAGING
      :impact: H
      :likelihood: L

.. threat:: Illegal inputs to the API
   :id: INTERFACE_ABUSE
   :deployment-models: UNTRUSTED_CLIENT, UNTRUSTED_STAGING

   .. description::
      An attacker can abuse the |API|. For example:

      *  Passing out of range values to the interface to provoke unexpected behavior of the implementation.
      *  Passing invalid input or output buffers to the interface, that would cause the implementation to access non-existent memory, or memory that is inaccessible to the caller.
      *  Invoking the interface functions out of sequence to cause a malfunction of the implementation.

      Using the interface to install attacker-defined firmware images and manifests is covered by `T.TAMPER`, `T.NON_FUNCTIONAL`, and `T.INCOMPATIBLE`.

      Note that for `DM.UNTRUSTED_STAGING`, the attacker can bypass the API entirely as there is no security boundary between the update service and the update client.

   .. security-goal:: `SG.AUTHENTIC`
   .. adversarial-model:: `AM.1`

   .. unmitigated:: UNTRUSTED_CLIENT
      :impact: H
      :likelihood: M

   .. unmitigated:: UNTRUSTED_STAGING
      :impact: H
      :likelihood: L

   .. mitigations::
      :mitigation:`STATE_MODEL`. **Control** by API design: the valid operation sequence for the API is fully specified by the API, to prevent unexpected firmware update states. Responsibility for enforcing the state model is **transferred** to the implementation.

      :mitigation:`MEMORY_BUFFER`. **Control** by API design: input buffers are fully consumed by the implementation before returning from a function. An implementation must not access the caller's memory after a function has returned.

      :mitigation:`VALIDATE_PARAMETER`. **Transfer** to the implementation: check all API parameters to lie within valid ranges, including memory access permissions.

   .. residual:: UNTRUSTED_CLIENT
      :impact: H
      :likelihood: VL

   .. residual:: UNTRUSTED_STAGING
      :impact: H
      :likelihood: VL

.. threat:: Modify asset between authentication and use
   :id: TOCTOU
   :deployment-models: UNTRUSTED_CLIENT, UNTRUSTED_STAGING

   .. description::
      An attacker modifies a manifest, or a firmware image, after it is authenticated (time of check) but before it is used (time of use). The attacker can place any content whatsoever in the affected asset.

   .. security-goal:: `SG.AUTHENTIC`
   .. adversarial-model:: `AM.1`, `AM.2`

   .. unmitigated:: UNTRUSTED_CLIENT
      :impact: H
      :likelihood: L

   .. unmitigated:: UNTRUSTED_STAGING
      :impact: H
      :likelihood: M

   .. mitigations::
      :mitigation:`PROTECT_THEN_VERIFY`. **Transfer** to the implementation: verification of firmware images and manifests must be done on a copy of the asset that is protected from tampering by untrusted components.

      *  For a `DM.UNTRUSTED_STAGING` deployment, this requires that everything must be verified by the bootloader.
      *  For a `DM.UNTRUSTED_CLIENT` deployment, the verification can be implemented within the update service, or the bootloader.

      This SRA assumes that Secure boot is implemented, which is the final mitigation to detect unauthorized modification of firmware. See :secref:`sra-assumptions`.

      See also `T.DEGRADE_DEVICE`.

   .. residual:: UNTRUSTED_CLIENT
      :impact: H
      :likelihood: VL

   .. residual:: UNTRUSTED_STAGING
      :impact: H
      :likelihood: VL

.. threat:: Trigger installation of incomplete update
   :id: PARTIAL_UPDATE

   .. description::
      An attacker triggers the installation of an update before all of the firmware images have been prepared.

      For example, where an update requires multiple images to be installed concurrently, the attacker might attempt to trigger the installation by forcing the device to restart. A partial installation might render the device inoperable.

   .. security-goal:: `SG.RELIABLE`
   .. adversarial-model:: `AM.0`, `AM.1`, `AM.2`

   .. unmitigated::
      :impact: H
      :likelihood: M

   .. mitigations::
      :mitigation:`EXPLICIT_STAGING`. **Control** by |API| design: firmware images that have been prepared are not automatically staged for installation. An explicit API call is used to stage all prepared images.

      `M.CHECK_DEPENDENCY`. Verify that all dependencies are satisfied before installation.

   .. residual::
      :impact: H
      :likelihood: VL

.. threat:: Mismatched Firmware
   :id: INCOMPATIBLE

   .. description::
      An attacker sends a valid firmware image, for the wrong type of device, signed by a key with firmware installation permission on both device types. This could have wide-ranging consequences. For devices that are similar, it could cause minor breakage or expose security vulnerabilities. For devices that are very different, it is likely to render devices inoperable.

   .. security-goal:: `SG.AUTHENTIC`, `SG.RELIABLE`
   .. adversarial-model:: `AM.0`, `AM.1`

   .. unmitigated::
      :impact: H
      :likelihood: M

   .. mitigations::
     :mitigation:`COMPATIBILITY`. **Transfer** to the firmware creator and implementation: include authenticated device type information in the manifest, and verify it prior to installation. The |API| design must enable authentication of firmware manifests, and validation of device type.

   .. residual::
      :impact: H
      :likelihood: VL

.. threat:: Disclosure of protected firmware
   :id: DISCLOSURE

   .. Description::
      An attacker wants to mount an attack on the device. To prepare the attack, the provided firmware image is reverse engineered and analyzed for vulnerabilities.

      The firmware image might be obtained while in transit from the firmware creator to the device, or while stored in the update server, or on the device prior to installation.

   .. security-goal:: `SG.CONFIDENTIAL`
   .. adversarial-model:: `AM.0`, `AM.1`, `AM.2`

   .. unmitigated::
      :impact: M
      :likelihood: H

   .. mitigations::
      :mitigation:`ENCRYPT`. **Transfer** to the firmware creator and implementation: use encryption to protect the firmware image. The |API| design must enable the use of encrypted firmware images.

      .. note::

         There are challenges when implementing encryption of firmware in a manner that is secure *at scale*. For example, the problems and some solutions are described in :cite-title:`SUIT-ENC`.

      Protection of installed firmware images is outside the scope of the firmware update process.

   .. residual::
      :impact: M
      :likelihood: VL

.. threat:: Attack from exploited update server
   :id: SERVER

   .. description::
      An attacker can impersonate, or exploit the update server to provide attacker-controlled commands and data to the update client.

      For the deployment models that are in scope for this SRA, this threat is indistinguishable from `T.TAMPER`.

.. threat:: Attack from spoof firmware creator
   :id: CREATOR

   .. description::
      An attacker can impersonate the firmware creator to upload attacker-controlled firmware images.

      For the deployment models that are in scope for this SRA, this threat is indistinguishable from `T.TAMPER`.

.. threat:: Manipulate network traffic
   :id: NETWORK

   .. description::
      An attacker intercepts all traffic to and from a device. The attacker can monitor or modify any data sent to or received from the device.

      For the deployment models that are in scope for this SRA, this threat is indistinguishable from `T.TAMPER`.

.. _sra-mitigations:

Mitigation summary
------------------

This section provides a summary of the mitigations described in the threat analysis, organized by the entity responsible for providing the mitigation. :secref:`sra-api-features` lists the API impacts that result from the security assessment.

Architectural mitigations
^^^^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-api-mitigations` lists mitigations that must be included in the design of the |API|.

:numref:`tab-sra-format-mitigations` lists mitigations that need to be included in the design of the firmware image and firmware manifest formats used by the selected firmware update process. An example of a firmware manifest format that provides these features is described in :rfc:`9124`.

.. list-table:: Mitigations **controlled** by the |API|
   :name: tab-sra-api-mitigations
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable

   *  -  Mitigation
      -  Description
      -  Mitigated threats

   *  -  `M.MEMORY_BUFFER`
      -  The implementation use of memory buffers in the API is fully specified.
      -  `T.INTERFACE_ABUSE`

   *  -  `M.STATE_MODEL`
      -  The valid operation sequence for the API is fully specified by the API.
      -  `T.INTERFACE_ABUSE`

   *  -  `M.EXPLICIT_STAGING`
      -  Firmware images that have been prepared require an explicit API call to stage for installation.
      -  `T.PARTIAL_UPDATE`

   *  -  `M.TRIAL`
      -  Provide a firmware image state where a failure to run a new firmware image will cause a roll back to the previously installed firmware.
      -  `T.TAMPER`, `T.NON_FUNCTIONAL`, `T.ROLLBACK`

.. list-table:: Mitigations **transferred** to the firmware image and manifest formats
   :name: tab-sra-format-mitigations
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable

   *  -  Mitigation
      -  Description
      -  Mitigated threats

   *  -  `M.COMPATIBILITY`
      -  Include authenticated device type information in the manifest.
      -  `T.INCOMPATIBLE`

   *  -  `M.CHECK_DEPENDENCY`
      -  Dependencies between firmware images are declared in the firmware image or manifest.
      -  `T.SKIP_INTERMEDIATE`, `T.PARTIAL_UPDATE`

   *  -  `M.AUTHENTICATE`
      -  Authenticate the content of the firmware image manifest and firmware images to prevent unauthorized modification. For detached manifests this can be achieved by including a cryptographic hash of the firmware image in the manifest, and then signing the manifest with an authorized key.
      -  `T.TAMPER`

   *  -  `M.SEQUENCE`
      -  Firmware images, or their manifests, must be monotonically sequenced for the device, or for each component within a device.
      -  `T.ROLLBACK`

   *  -  `M.ENCRYPT`
      -  Use encryption to protect the firmware image.
      -  `T.DISCLOSURE`


Implementation-level mitigations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-remediations` lists the mitigations that are transferred to the implementation. These are also known as 'remediations'.

.. list-table:: Mitigations that are **transferred** to the implementation
   :name: tab-sra-remediations
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable

   *  -  Mitigation
      -  Description
      -  Mitigated threats

   *  -  `M.VALIDATE_PARAMETER`
      -  Check all API parameters to lie within valid ranges, including memory access permissions.
      -  `T.INTERFACE_ABUSE`

   *  -  `M.COMPATIBILITY`
      -  Verify firmware image compatibility prior to installation.
      -  `T.INCOMPATIBLE`

   *  -  `M.CHECK_DEPENDENCY`
      -  Dependencies between firmware images are verified by the implementation prior to installation.
      -  `T.SKIP_INTERMEDIATE`, `T.PARTIAL_UPDATE`

   *  -  `M.AUTHENTICATE`
      -  Verify the authenticity of the firmware image manifest and firmware images against a trust anchor within the implementation, prior to installation.
      -  `T.TAMPER`

   *  -  `M.SEQUENCE`
      -  Deny an attempt to install an update with a sequence number that is lower than the currently installed firmware.
      -  `T.ROLLBACK`

   *  -  `M.ENCRYPT`
      -  Use cryptographic encryption to protect the firmware image.
      -  `T.DISCLOSURE`

   *  -  `M.STATE_MODEL`
      -  Enforce the state model defined by the API.
      -  `T.INTERFACE_ABUSE`

   *  -  `M.TRIAL`
      -  Use the provided TRIAL state in the firmware update process, to enable recovery of a failed update
      -  `T.TAMPER`, `T.NON_FUNCTIONAL`, `T.ROLLBACK`

   *  -  `M.PROTECT_THEN_VERIFY`
      -  Verification of firmware images and manifests must be done on a copy of the asset that is protected from tampering by untrusted components.
      -  `T.TOCTOU`

   *  -  `M.VERIFY_EARLY`
      -  Verify firmware images as early as possible in the update process, to detect and reject an invalid update.
      -  `T.DEGRADE_DEVICE`

User-level mitigations
^^^^^^^^^^^^^^^^^^^^^^

:numref:`tab-sra-residual-risk` lists mitigations that are transferred to the application or other external components. These are also known as 'residual risks'.

.. list-table:: Mitigations that are **transferred** to the application
   :name: tab-sra-residual-risk
   :widths: 1 2 1
   :header-rows: 1
   :class: longtable

   *  -  Mitigation
      -  Description
      -  Mitigated threats

   *  -  `M.VERIFY_EARLY`
      -  Verify firmware images as early as possible in the update process, to detect and reject an invalid update.
      -  `T.DEGRADE_DEVICE`
