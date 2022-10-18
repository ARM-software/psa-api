.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _report:

Initial Attestation report
==========================

This section begins with a description of the information model for the report and then describes the expected format.

Information model
-----------------

The following table describes the mandatory and optional claims in the report:

..  list-table::
   :header-rows: 1
   :widths: 20 15 50

   *  -  Claim
      -  Mandatory
      -  Description
   *  -  Auth challenge
      -  Yes
      -  Input object from the caller. For example, this can be a cryptographic nonce or a hash of locally attested data. The length must be 32, 48, or 64 bytes.

         This is the :code:`auth_challenge` parameter to `psa_initial_attest_get_token()`.
   *  -  Instance ID
      -  Yes
      -  Represents the unique identifier of the instance:

         *  When using an asymmetric key-pair for the :term:`Initial Attestation Key` (IAK), Arm recommends the Instance ID be a hash of the corresponding public key.
         *  When using a symmetric key for the IAK, Arm recommends that the Instance ID is always a double hash of the key, hence ``InstanceID = H(H(IAK))``. This eliminates risks when exposing the key to different HMAC block size. For further information, read RFC2104.

         The use of the IAK is also discussed in `[PSM]`.
   *  -  Verification service indicator
      -  No
      -  A hint used by a relying party to locate a validation service for the token. The value is a text string that can be used to locate the service or a URL specifying the address of the service.

         A verifier may choose to ignore this claim in favor of other information.
   *  -  Profile definition
      -  No
      -  Contains the name of a document that describes the 'profile' of the report. The document name may include versioning. The value for this specification is **PSA_IOT_PROFILE_1**.
   *  -  Implementation ID
      -  Yes
      -  Uniquely identifies the underlying :term:`Immutable Platform Root of Trust`. A verification service can use this claim to locate the details of the verification process. Such details include the implementation's origin and associated certification state. The full definition is in `[PSM]`.
   *  -  Client ID
      -  Yes
      -  Represents the Partition ID of the caller. It is a signed integer whereby negative values represent callers from the :term:`NSPE` and where positive IDs represent callers from the :term:`SPE`. The value ``0`` is not permitted. The full definition of a Partition ID is provided by :cite-title:`PSA-FF-M`.

         It is essential that this claim is checked in the verification process to ensure that a security domain cannot spoof a report from another security domain.
   *  -  Security Lifecycle
      -  Yes
      -  Represents the current lifecycle state of the :term:`Platform Root of Trust` (PRoT). The state is represented by an integer that is partitioned to convey a major state and a minor state. The major state is mandatory and defined by `[PSM]`. The minor state is optional and |impdef|. The PRoT security lifecycle state and implementation state are encoded as follows:

         -  version[15:8] --- PRoT security lifecycle state
         -  version[7:0] --- |impdef| state.

         The PRoT security lifecycle states consist of the following values:

         -  PSA_LIFECYCLE_UNKNOWN (``0x0000u``)
         -  PSA_LIFECYCLE_ASSEMBLY_AND_TEST (``0x1000u``)
         -  PSA_LIFECYCLE_PSA_ROT_PROVISIONING (``0x2000u``)
         -  PSA_LIFECYCLE_SECURED (``0x3000u``)
         -  PSA_LIFECYCLE_NON_PSA_ROT_DEBUG (``0x4000u``)
         -  PSA_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG (``0x5000u``)
         -  PSA_LIFECYCLE_DECOMMISSIONED (``0x6000u``)

         For PSA Certified, a remote verifier can only trust reports from the PRoT when it has a major state that is SECURED or NON_PSA_ROT_DEBUG.
   *  -  Hardware version
      -  No
      -  Provides metadata linking the token to the GDSII that went to fabrication for this instance. It can be used to link the class of chip and PRoT to the data on a certification website. It must be represented as a thirteen-digit `[EAN-13]`.
   *  -  Boot seed
      -  Yes
      -  Represents a random value created at system boot time that can allow differentiation of reports from different boot sessions.
   *  -  Software components
      -  Yes (unless the No Software Measurements claim is specified)
      -  A list of software components that represent all the software loaded by the PRoT. This claim is needed for the rules outlined in `[PSM]`. Each entry has the following fields:
         1. Measurement type
         2. Measurement value
         3. Version
         4. Signer ID
         5. Measurement description
         The full definition of the software component is described in :secref:`software-components`. This claim is required to be compliant with `[PSM]`.
   *  -  No Software Measurements
      -  Yes (if no software components specified)
      -  In the event that the implementation does not contain any software measurements then the Software Components claim above can be omitted but instead it is mandatory to include this claim to indicate this is a deliberate state.

         This claim is intended for devices that are not compliant with `[PSM]`.


.. _software-components:

Software components
~~~~~~~~~~~~~~~~~~~~

Each software component in the Software Components claim must include the required properties of the following table:

..  list-table::
   :header-rows: 1
   :widths: 10 25 10 50
   :align: left
   :class: longtable

   *  -  Key ID
      -  Type
      -  Required
      -  Description

   *  -  1
      -  Measurement type
      -  No
      -  A short string representing the role of this software component (e.g. 'BL' for boot loader).

         Expected types may include:

         -  BL (a bootloader)
         -  PRoT (a component of the Platform Root of Trust)
         -  ARoT (a component of the Application Root of Trust)
         -  App (a component of the NSPE application)
         -  TS (a component of a trusted subsystem)

   *  -  2
      -  Measurement value
      -  Yes
      -  Represents a hash of the invariant software component in memory at startup time. The value must be a cryptographic hash of 256 bits or stronger.

   *  -  3
      -  Reserved
      -  No
      -  Reserved

   *  -  4
      -  Version
      -  No
      -  The issued software version in the form of a text string. The value of this claim corresponds to the entry in the original signed manifest of the component.

         This field must be present to be compliant with `[PSM]`.

   *  -  5
      -  Signer ID
      -  No
      -  The hash of a signing authority public key for the software component. The value of this claim corresponds to the entry in the original manifest for the component.

         This can be used by a verifier to ensure the components were signed by an expected trusted source.

         This field must be present to be compliant with `[PSM]`.

   *  -  6
      -  Measurement description
      -  No
      -  Description of the software component, which represents the way in which the measurement value of the software component is computed. The value is a text string containing an abbreviated description (or name) of the measurement method which can be used to lookup the details of the method in a profile document. This claim may normally be excluded, unless there is an exception to the default measurement described in the profile for a specific component.

Report format and signing
-------------------------

This section describes the specific representation, encoding and signing of the information described in the Information Model.

Token encoding
~~~~~~~~~~~~~~

The report is represented as a token, which must be formatted in accordance to :cite-title:`EAT` draft specification. The token consists of a series of claims declaring evidence as to the nature of the instance of hardware and software. The claims are encoded with the :term:`CBOR` format, defined in :cite-title:`STD94`.

Signing
~~~~~~~

The token is signed following the structure defined in :cite-title:`STD96` specification:

*  For asymmetric key algorithms, the signature structure must be COSE-Sign1. An asymmetric key algorithm is needed to achieve all the use cases defined in :secref:`use cases`.
*  For symmetric key algorithms, the structure must be COSE-Mac0.

   .. warning::

      A symmetric key is **strongly discouraged** due to the associated infrastructure costs for key management and operational complexities. It may also restrict the ability to interoperate with scenarios that involve third parties (see :secref:`use cases`).


EAT standard claims
~~~~~~~~~~~~~~~~~~~

The token is modelled to include custom values that correspond to the following EAT standard claims (as expressed in the draft EAT proposal):

-  **nonce** (mandatory); arm_psa_nonce is used instead
-  **UEID** (mandatory); arm_psa_UEID is used instead

A future version of the profile, corresponding to an issued standard, might declare support for both custom and standard claims as a transitionary state towards exclusive use of standard claims.

.. _custom-claims:

EAT custom claims
~~~~~~~~~~~~~~~~~

The token can include the following EAT custom claims. Custom claims for the |API| have a root identity of -75000.

Some fields must be at least 32 bytes to provide sufficient cryptographic strength.

.. list-table::
   :header-rows: 1
   :widths: 10 25 27 30
   :class: longtable
   :align: left

   *  -  Key ID
      -  Type
      -  Name
      -  CBOR type

   *  -  -75000
      -  Profile Definition
      -  ``arm_psa_profile_id``
      -  Text string

   *  -  -75001
      -  Client ID
      -  ``arm_psa_partition_id``
      -  Unsigned integer or Negative integer

   *  -  -75002
      -  Security Lifecycle
      -  ``arm_psa_security_lifecycle``
      -  Unsigned integer

   *  -  -75003
      -  Implementation ID
      -  ``arm_psa_implementation_id``
      -  Byte string (>=32 bytes)

   *  -  -75004
      -  Boot seed
      -  ``arm_psa_boot_seed``
      -  Byte string (>=32 bytes)

   *  -  -75005
      -  Hardware version
      -  ``arm_psa_hw_version``
      -  Text string

   *  -  -75006
      -  Software components (compound map claim)
      -  ``arm_psa_sw_components``
      -  Array of map entries. The map entries have the following types:

         1. Text string (type)
         2. Byte string (measurement, >=32 bytes)
         3. Reserved
         4. Text string (version)
         5. Byte string (signer ID, >=32 bytes)
         6. Text string (measurement description)

         See :secref:`software-components` for details.

   *  -  -75007
      -  No software measurements
      -  ``arm_psa_no_sw_measurements``
      -  Unsigned integer (the recommended value is ``1``)

   *  -  -75008
      -  Auth challenge
      -  ``arm_psa_nonce``
      -  Byte string

   *  -  -75009
      -  Instance ID
      -  ``arm_psa_UEID``
      -  Byte string (the type byte should be set to ``0x01``. The type byte is described in the `[EAT]` draft.)

   *  -  -75010
      -  Verification service indicator
      -  ``arm_psa_origination``
      -  Text string

An example report can be found in :secref:`example-report`.
