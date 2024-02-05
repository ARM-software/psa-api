.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Support for SUIT in the Firmware Update API
===========================================

SUIT is a suite of emerging specifications from the Software Updates for Internet of Things IETF working group.

SUIT defines a 'manifest' to describe the meta-data about a firmware update, and an 'envelope' that contains a signed manifest, and optionally some additional attached 'payloads'. SUIT supports Secure update and Secure boot policies. A SUIT manifest contains instructions to determine the validity of the update for the device, the exact set of firmware payloads that are required, and to verify and install the update. Processing the instructions requires a small interpreter in the target device.

Further information about SUIT:

*  SUIT architecture (RFC 9019): https://datatracker.ietf.org/doc/rfc9019/
*  Manifest information model (RFC 9124): https://datatracker.ietf.org/doc/rfc9124/
*  SUIT paper: https://hal.inria.fr/hal-02351794/document
*  IETF working group: https://datatracker.ietf.org/wg/suit/about/

In the Firmware Update API v1.0 specification, `§2.7 Firmware format independence <https://arm-software.github.io/psa-api/fwu/1.0/overview/goals.html#firmware-format-independence>`_ states:

   New standards for firmware update within IoT are being developed, such as A Firmware Update Architecture for Internet of Things (RFC9019).

   This version of the Firmware Update API is suitable for some of the use cases that are defined by A Manifest Information Model for Firmware Updates in Internet of Things (IoT) Devices (RFC9124) and A Concise Binary Object Representation (CBOR)-based Serialization Format for the Software Updates for Internet of Things (SUIT) Manifest (SUIT-MFST). For example, where the payloads are integrated in the manifest envelope, or there is just one external payload to the envelope.

   Support for the more complex use cases from (RFC9124), with multiple external payloads, is not considered in version 1.0 of the Firmware Update API, but might be in scope for future versions of the interface.

Analysis
--------

The v1.0 API is designed to support update processes where an entity on the Update client side of the API makes the decisions about which firmware images need to be downloaded and transferred to the Update service, prior to the Update service checking that the update is valid, and verifying and installing the images.

In SUIT, the decisions regarding which images to install is based on the instructions in the manifest. For a Secure firmware update, the instruction processing ideally takes place within the trusted execution environment - typically this would be part of the Update service.

If the payloads (firmware images) in a SUIT update are 'detached', then the SUIT processor is expected to fetch these from a URI specified within the SUIT envelope. However, the v1.0 API does not provide a mechanism for the Update service to request additional payloads (firmware images) that need to be downloaded.

One solution would be to process the SUIT manifest initially in the Update client, in order to identify, download, and transfer any additional payloads. Then, the manifest is processed a second time in the Update service to validate the decisions made by an untrusted Update client, and verify the payloads. This approach would require additions to the API to provide attributes relating to the currently installed firmware, that are required by the SUIT processing in the Update client.

An alternative solution is to process the SUIT manifest in the Update service, and add functionality to the API that allows the Update service to request that the Update client download and transfer additional payloads.

In either case, further processing of the SUIT manifest will occur a boot time when authenticating, loading and executing the firmware.

One of the design objectives for the Firmware Update API is to separate the concerns for the Update client and Update service:

*  In the first solution, the Update client is required to know the manifest format, and be able to process it.
*  In the second solution, the Update client is only required to know how to handle a firmware component that is a manifest, and might request additional firmware images to be provided.

Proposal
--------

This proposal is based around the second approach in the analysis: the initial processing of the SUIT manifest is performed by the Update service, and the Update client does not require any knowledge of the encoding or format of the data that it transfers to the Update service. This approach enables the API design, and Update client implementation, to work with other SUIT-like architectures, or with alternative encodings of the SUIT information (for example, encrypted manifests).

Reuse of the v1.0 API
~~~~~~~~~~~~~~~~~~~~~

Handling the SUIT envelope
^^^^^^^^^^^^^^^^^^^^^^^^^^

The Firmware Update API 1.0 includes a ``manifest`` parameter in the ``psa_fwu_start()`` function, which allows an Update client to provide detached metadata for the firmware image. However, this is not suitable for use with SUIT:

*  The SUIT manifest is embedded within the SUIT 'envelope', and each envelope can contain any number of embedded and detached 'payloads'.
*  The SUIT envelope can be very large, containing multiple embedded payloads. The ``manifest`` parameter must be passed in the single call to ``psa_fwu_start()``.

Instead, a SUIT envelope can be treated as a 'firmware component'. The Update service developer can allocate a component identifier for each top-level SUIT envelope. This allows the envelope to be transferred in multiple calls, if required, and allows it to be associated with any number of additional payload images.

Triggering SUIT processing
^^^^^^^^^^^^^^^^^^^^^^^^^^

The SUIT envelope can only be processed once it has been transferred in its entirety - this enables integrity verification and authentication of the envelope.

This fits naturally as part of the ``psa_fwu_finish()`` functionality, when the envelope component has been fully transferred.

Later SUIT processing that occurs within an Installer or Bootloader component, would only happen following a reboot, after the Update client has called ``psa_fwu_install()``.

Transferring payloads
^^^^^^^^^^^^^^^^^^^^^

The existing functions for transferring firmware images can be used for each additional payload that is requested during SUIT manifest processing. Some consideration is needed for allocating component identifiers for the additional payloads.

Initiating installation
^^^^^^^^^^^^^^^^^^^^^^^

The current API already waits until the Update client calls ``psa_fwu_install()`` before staging any CANDIDATE components for update. This fits very well with the need to complete the transfer and processing of the SUIT envelope, and transfer all requested payloads, prior to initiating their installation.


State-based design
~~~~~~~~~~~~~~~~~~

A high level flow for the overall update process is shown in `Figure 1 <fig-flow_>`_.

.. figure:: suit-update.svg
   :name: fig-flow

   **Figure 1** *The overall flow in a SUIT update*

This proposal is focussed on the changes required to the Firmware Update API - both the programming model and the C interfaces - that are required to enable this update flow. The aim is to make the API independent of the choices made in the implementation of the API, e.g. with regards to firmware storage, or subsequent SUIT processing steps.

The overall process in `Figure 1 <fig-flow_>`_ will be managed as follows:

*  Extending the v1.0 state model within the Firmware Update API to include a state for envelope processing.
*  Providing an interface to report that an additional payload is required.
*  Providing an interface for the Update client to query the payload information, so it can be downloaded and transferred.
*  Defining the behavior when a partially complete SUIT update fails, is aborted by the client, or an unexpected restart occurs in one of the new states.

.. list-table::
   :widths: auto

   *  -  **Note**
      -  Although it looks tempting to use callbacks in the API to implement the payload fetching operation, this has a number of challenges:

         *  The Update client thread/task would have to block while obtaining the requested payload (which can be split into multiple data transfers), and only return from the callback when complete.
         *  It requires the Update service to be re-entrant, when transferring the requested payload to the service.
         *  On deployments where the Update service is isolated from the Update client, the callback mechanism will only operate in the client, and still require a state-based approach within the service.

Draft API design
~~~~~~~~~~~~~~~~

*Note that this is a draft proposal, and selects one from a number of similar options. Some alternates are briefly described later, but no detailed analysis of their relative merits has been done yet. The naming of any new API identifiers is also subject to discussion and revision.*

`Figure 2 <fig-fetch_>`_ shows the detailed call sequence for the Update client when processing a SUIT envelope

.. figure:: fetch-as-state.svg
   :name: fig-fetch

   **Figure 2** *The call sequence when fetching a payload*

The detailed steps of the flow are as follows:

1. The process is started by transferring the SUIT envelope as a firmware image using a component identifier allocated to the SUIT envelope component.

2. The call to ``psa_fwu_finish()`` behaves differently for an Envelope component, and the Update service will verify and begin processing the manifest commands related to validation of the device, the suitability of the update, and to identify any required payloads.

3. If a payload is encountered that is detached from the Envelope, the call to `psa_fwu_finish()` returns with a new status code: ``PSA_FWU_PAYLOAD_REQUIRED``. At this point, the Envelope component will be in a new state, ``PSA_FWU_PROCESSING``. In this state, the Update client can either call ``psa_fwu_cancel()`` to abandon the update, or provide the payload requested.

4. To determine the details of the required payload, the Update client calls a new function ``psa_fwu_payload()`` passing the Envelope's component identifier. This fills in a data structure that provides details of the payload, such as a URI, the size, the payload component identifier, and possibly a checksum or hash to validate the downloaded data.

5. The Update client must now fetch the payload, using the URI to locate it, and transfer it to the Update service using the standard ``psa_fwu_start()``, ``psa_fwu_write()`` and ``psa_fwu_finish()`` calls, providing the component identifier returned in the payload information.

6. When ``psa_fwu_finish()`` is called, the payload is verified by the Update service, and the payload component enters CANDIDATE state (as is normal for components when ``psa_fwu_finish()`` is called). However, before returning, the Update service now continues processing the SUIT manifest commands. If another payload is required, then ``PSA_FWU_PAYLOAD_REQUIRED`` is returned from the call to ``psa_fwu_finish()``, and processing continues from step (4) above.

7. When the Update service completes the processing of the SUIT manifest commands, the Envelope component is moved to the CANDIDATE state, and the last call to ``psa_fwu_finish()`` will return ``PSA_SUCCESS``.

8. To proceed with the installation, the Update client now calls ``psa_fwu_install()``, and the behavior follows the standard flows for the Firmware Update API.

If at any stage during SUIT processing, the Update service encounters an error, the relevant component or components will be put into the FAILED state, and the Update client will need to use ``psa_fwu_clean()`` as usual to restore the initial firmware state.

When the Update service encounters a valid payload that is a nested SUIT envelope, the implementation can do one of the following:

*  Start processing the nested SUIT envelope immediately, and request any of its detached payloads. Once complete, resume processing of the outer SUIT envelope. Note that this will require the Update service to maintain the state of two (or more) manifest processors concurrently.
*  Make note of the nested SUIT envelope for deferred processing, and resume processing of the current SUIT envelope. Once the current envelope processing is complete, begin processing any deferred Envelope and request its payloads as described in the flow above.

Alternate API designs
~~~~~~~~~~~~~~~~~~~~~

Handling a SUIT, or SUIT-like, update is something the Update client will be designed for. Therefore, the client can use some alternative APIs that reduce the number of calls required to identify and fetch payloads.

Extended finish function
^^^^^^^^^^^^^^^^^^^^^^^^

Obtaining the payload information could be combined with the call to ``psa_fwu_finish()``, so that the Update client already knows the payload details when it is informed that a payload is required. This also removes the slightly awkward use of the ``envelope_id`` in the call to ``psa_fwu_payload()`` (which is removed).

The extended finish function would also be used when completing every payload transfer, in order to identify the next payload that is required.

Extended start function
^^^^^^^^^^^^^^^^^^^^^^^

Starting the payload transfer could be combined with obtaining the payload information. E.g., this might be a ``psa_fwu_start_payload()`` function, which takes the envelope component identifier and returns the payload information, while starting the payload component for transfer.

Combined function
^^^^^^^^^^^^^^^^^

Apply both of the above ideas at once. E.g. this could be a ``psa_fwu_process_envelope()`` function that combines the behavior of ``psa_fwu_finish()``, ``psa_fwu_payload()``, and ``psa_fwu_start()``.

Detailed API definition
~~~~~~~~~~~~~~~~~~~~~~~

*TBD*

Open Issues
-----------

*  Overall API design, and optimisation of call sequences.
*  Naming of API elements.
*  Flexibility vs strict specification (e.g. handling of nested envelopes)
*  The current ``psa_fwu_component_id_t`` is typed as a 8-bit integer. Is that sufficient for this API, or should we allocate a larger size for this type?
*  Are there additional attributes for components that need to be included in the ``psa_fwu_component_info_t``?
