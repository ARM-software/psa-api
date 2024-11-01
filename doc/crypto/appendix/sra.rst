.. SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _sra:

Security Risk Assessment
========================

This Security Risk Assessment (SRA) analyses the security of the |API| itself, not of any specific implementation of the API, or any specific use of the API. However, the security of an implementation of the |API| depends on the implementation design, the capabilities of the system in which it is deployed, and the need to address some of the threats identified in this assessment.

To enable the |API| to be suitable for a wider range of security use cases, this SRA considers a broad range of adversarial models and threats to the application and the implementation, as well as to the API.

This approach allows the assessment to identify API design requirements that affect the ability for an implementation to mitigate threats that do not directly attack the API.

The scope is described in :secref:`adversarial-models`.

Architecture
------------

System definition
~~~~~~~~~~~~~~~~~

:numref:`fig-system-entities` shows the |API| as the defined interface that an Application uses to interact with the Cryptoprocessor.

..  figure:: /figure/sra/system-entities.*
    :name: fig-system-entities

    |API|

Assumptions, constraints, and interacting entities
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This SRA makes the following assumptions about the |API| design:

*   The API does not provide arguments that identify the caller, because they can be spoofed easily, and cannot be relied upon. It is assumed that the implementation of the API can determine the caller identity, where this is required. See :secref:`isolation`.

*   The API does not prevent the use of mitigations that are required by an implementation of the API. See :secref:`remediation`.

*   The API follows best-practices for C interface design, reducing the risk of exploitable errors in the application and implementation code. See :secref:`usability`.


.. _dfd:

Trust boundaries and information flow
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The |API| is the interface available to the programmer, and is the main attack surface that is analyzed here. However, to ensure that the API enables the mitigation of other threats to an implementation, we also consider the system context in which the |API| is used.

:numref:`fig-dfd-no-isolation` shows the data flow for a typical application usage of the |API|, for example, to exchange ciphertext with an external system, or for at rest protection in system non-volatile storage. The Application uses the |API| to interact with the Cryptoprocessor. The Cryptoprocessor stores persistent keys in a Key Store.

..  figure:: /figure/sra/dfd_no_isolation.*
    :name: fig-dfd-no-isolation

    |API| dataflow diagram for an implementation with no isolation

For some adversarial models, :term:`Cryptoprocessor isolation` or :term:`Caller isolation` is required in the implementation to achieve the security goals. See :secref:`security-goals`, and remediations R.1 and R.2 in :secref:`remediation`.

The Cryptoprocessor can optionally include a trust boundary within its implementation of the API. The trust boundary shown in :numref:`fig-dfd-crypto-isolation` corresponds to Cryptoprocessor isolation. The Cryptoprocessor boundary protects the confidentiality and integrity of the Cryptoprocessor and Key Store state from system components that are outside of the boundary.

..  figure:: /figure/sra/dfd_crypto_isolation.*
    :name: fig-dfd-crypto-isolation

    |API| dataflow diagram for an implementation with cryptoprocessor isolation

If the implementation supports multiple, independent client Applications within the system, each Application has its own view of the Cryptoprocessor and key store. The additional trust boundaries required for a caller isolated implementation are shown in :numref:`fig-dfd-caller-isolation`. The Application boundary restricts the capabilities of the Application, and protects the confidentiality and integrity of system state from the Application.

..  figure:: /figure/sra/dfd_caller_isolation.*
    :name: fig-dfd-caller-isolation

    |API| dataflow diagram for an implementation with caller isolation

Assets and stakeholders
~~~~~~~~~~~~~~~~~~~~~~~

1.  Cryptographic keys and key-related assets. This includes the key properties, such as the key type, identity and policies.

    Stakeholders can include the SiP, the OEM, the system or application owner. Owners of a key need to be able to use the key for cryptographic operations, such as encryption or signature, and where permitted, delete, copy or extract the key.

    Disclosure of the cryptographic key material to an attacker defeats the protection that the use of cryptography provides. Modification of cryptographic key material or key properties by an attacker has the same end result. These allow an attacker access to the assets that are protected by the key.

#.  Other cryptographic assets, for example, intermediate calculation values and RNG state.

    Disclosure or modification of these assets can enable recovery of cryptographic keys, and loss of cryptographic protection.

#.  Application input/output data and cryptographic operation state.

    Application data is only provided to the Cryptoprocessor for cryptographic operations, and its stakeholder is the application owner.

    Disclosure of this data --- whether it is plaintext, or other data or state --- to an attacker defeats the protection that the use of cryptography provides. Modification of this data can have the same effect.

.. _security-goals:

Security goals
~~~~~~~~~~~~~~

Cryptography is used as a mitigation to the risk of disclosure or tampering with data assets that require protection, where isolation of the attacker from the data asset is unavailable or inadequate. Using cryptography introduces new threats related to the incorrect use of cryptography and mismanagement of cryptographic keys. :numref:`table-sg` lists the security goals for the |API| to address these threats.

.. list-table:: Security goals
    :name: table-sg
    :class: longtable
    :header-rows: 1
    :widths: 1,9

    *   -   Id
        -   Description

    *   -   G.1
        -   An attacker shall not be able to disclose the plaintext corresponding to a ciphertext for which they do not own the correct key.
    *   -   G.2
        -   An attacker shall not be able to generate authenticated material for which they do not own the correct key.
    *   -   G.3
        -   An attacker shall not be able to exfiltrate keys or other private information stored by the |API|.
    *   -   G.4
        -   An attacker shall not be able to alter any state held by the implementation of the |API|, such as internal keys or other private information (for example, certificates, signatures, etc.).


Threat Model
------------

.. _adversarial-models:

Adversarial models
~~~~~~~~~~~~~~~~~~

The API itself has limited ability to mitigate threats. However, mitigation of some of the threats within the cryptoprocessor can place requirements on the API design. This analysis considers a broad attack surface, to also identify requirements that enable the mitigation of specific threats within a cryptoprocessor implementation.

:numref:`table-adversaries` describes the adversarial models that are considered in this assessment.

A specific implementation of the |API| might not include all of these adversarial models within its own threat model. In this case, the related threats, risks, and mitigations might not be required for that implementation.

.. list-table:: Adversarial models
    :name: table-adversaries
    :class: longtable
    :header-rows: 1
    :widths: 1,9

    *   -   Id
        -   Description

    *   -   M.0
        -   The Adversary is capable of accessing data that is outside the Security Perimeter of the system and on commonly accessible channels, such as messages in transit or data in storage.

            This includes, but is not limited to:

            *   Read any input and output.
            *   Provide, forge, replay or modify input.
            *   Attempt to gain read/write access to external storage devices.
            *   Perform timings on the operations being done by the target machine, either in normal operation or as a response to crafted inputs. For example, timing attacks on web servers.

            Once access to data is obtained, we do not make a further case distinction of the Adversarial Model depending on other capabilities. For example, the ability to perform cryptanalysis on intercepted ciphertext.
    *   -   M.1
        -   The Adversary is capable of mounting attacks from software.

            This includes, but is not limited to:

            *   Software exploitation.
            *   Side channel analysis that that relies on software-exposed, built-in hardware features to perform physical unit and time measurements.
            *   Attacks that exploit access to any memory mapped configuration, monitoring, debug register.
            *   Software-induced glitching of resources, for example Row hammer, or crashing the CPU by running intensive tasks.
    *   -   M.2
        -   The Adversary is capable of mounting simple, passive hardware attacks. This Adversary has physical access to the hardware.

            This includes, but is not limited to:

            *   Side channel analyses that require external measurement devices. For example, this can utilize leakage sources such as EM emissions, power consumption, photonic emission, or acoustic channels.
            *   Plugging malicious hardware into an unmodified system.
            *   Passive SoC or memory interposition.

Adversarial models that are outside the scope of this assessment are shown in :numref:`table-out-of-scope-adversaries`.

.. list-table:: Adversarial models that are outside the scope of this SRA
    :name: table-out-of-scope-adversaries
    :class: longtable
    :header-rows: 1
    :widths: 1,9

    *   -   Id
        -   Description

    *   -   M.3
        -   The Adversary is capable of mounting sophisticated and active physical attacks.

            This includes, but is not limited to:

            *   Interposing memory and blocking, replaying, and injecting transactions, this requires a much more precise timing than passive eavesdropping.
            *   Replacing or adding chips on the motherboard.
    *   -   M.4
        -   The Adversary is capable of performing invasive silicon microsurgery.


Threats and attacks
~~~~~~~~~~~~~~~~~~~

:numref:`table-threats` describes threats to the Security Goals, and provides examples of corresponding attacks. This table identifies which Security goals are affected by the attacks, and which Adversarial model or models are required to execute the attack.

See :secref:`risk-assessment` for an evaluation of the risks posed by these threats, :secref:`mitigations` for mitigation requirements in the API design, and :secref:`remediation` for mitigation recommendations in the cryptoprocessor implementation.

.. list-table:: Threats and attacks
    :name: table-threats
    :class: longtable
    :header-rows: 2
    :widths: 2,5,2,2,14

    *   -   Threat
        -
        -
        -
        -   Attack (Examples)
    *   -   Id
        -   Description
        -   Goals
        -   Models
        -   Id: Description

            .. TI against Application<->External dataflow, and NVM datastore
    *   -   T.1
        -   Use of insecure or incorrectly implemented cryptography
        -   G.1 G.2
        -   M.0
        -   **A.C1**: Using a cryptographic algorithm that is not adequately secure for the application use case can permit an attacker to recover the application plaintext from attacker-accessible data.

            **A.C2**: Using a cryptographic algorithm that is not adequately secure for the application use case can permit an attacker to inject forged authenticated material into application data in transit or in storage.

            **A.C3**: Using an insecure cryptographic algorithm, or one that is incorrectly implemented can permit an attacker to recover the cryptographic key. Key recovery enables the attacker to reveal encrypted plaintexts, and inject forged authenticated data.

            .. TI against Application<->External dataflow, and NVM datastore
    *   -   T.2
        -   Misuse of cryptographic algorithms
        -   G.1 G.2
        -   M.0
        -   **A.C4**: Reusing a cryptographic key with different algorithms can result in cryptanalysis attacks on the ciphertexts or signatures which enable an attacker to recover the plaintext, or the key itself.

            .. IE against Cryptoprocessor
    *   -   T.3
        -   Recover non-extractable key through the API
        -   G.3
        -   M.1
        -   **A.C5**: The attacker uses an indirect mechanism provided by the API to extract a key that is not intended to be extractable.

            **A.C6**: The attacker uses a mechanism provided by the API to enable brute-force recovery of a non-extractable key. For example, :cite-title:`CLULOW` describes various flaws in the design of the PKCS #11 interface standard that enable an attacker to recover secret and non-extractable keys.

            .. TIE against Cryptoprocessor
    *   -   T.4
        -   Illegal inputs to the API
        -   G.3 G.4
        -   M.1
        -   **A.60**: Using a pointer to memory that does not belong to the application, in an attempt to make the cryptoprocessor read or write memory that is inaccessible to the application.

            **A.70**: Passing out-of-range values, or incorrectly formatted data, to provoke incorrect behavior in the cryptoprocessor.

            **A.61**: Providing invalid buffer lengths to cause out-of-bounds read or write access within the cryptoprocessor.

            **A.62**: Call API functions in an invalid sequence to provoke incorrect operation of the cryptoprocessor.

            .. TIE against Application/Cryptoprocessor
    *   -   T.5
        -   Direct access to cryptoprocessor state
        -   G.3 G.4
        -   M.1
        -   **A.C7**: Without a cryptoprocessor boundary, an attacker can directly access the cryptoprocessor state from an application. See :numref:`fig-dfd-no-isolation`.

            **A.C8**: A misconfigured cryptoprocessor boundary can allow an attacker to directly access the cryptoprocessor state from an Application.

            .. SE against Application/Cryptoprocessor
    *   -   T.6
        -   Access and use another application's assets
        -   G.1 G.2
        -   M.1
        -   **A.C9**: Without application boundaries, the cryptoprocessor provides a unified view of the application assets. All keys are accessible to all callers of the |API|. See :numref:`fig-dfd-caller-isolation`.

            **A.C10**: The attacker can spoof the application identity within a caller-isolated implementation to gain access to another application's assets.

            .. I against Cryptoprocessor
    *   -   T.7
        -   Data-dependent timing
        -   G.1 G.3
        -   M.1
        -   **A.C11** Measuring the time for operations in the cryptoprocessor or the application, and using the differential in results to assist in recovery of the key or plaintext.

            .. TE against Cryptoprocessor
    *   -   T.8
        -   Memory manipulation
        -   G.4
        -   M.2
        -   **A.19**: Corrupt application or cryptoprocessor state via a fault, causing incorrect operation of the cryptoprocessor.
    *   -
        -
        -
        -   M.1
        -   **A.59**: Modifying function parameters in memory, while the cryptoprocessor is accessing the parameter memory, to cause incorrect operation of the cryptoprocessor.

            .. I against Cryptoprocessor
    *   -   T.9
        -   Side channels
        -   G.1 G.3
        -   M.2
        -   **A.C12** Taking measurements from physical side-channels during cryptoprocessor operation, and using this data to recover keys or plaintext. For example, using power or EM measurements.
    *   -
        -
        -
        -   M.1
        -   **A.C13** Taking measurements from shared-resource side-channels during cryptoprocessor operation, and using this data to recover keys or plaintext. For example, attacks using a shared cache.

.. _risk-assessment:

Risk assessment
~~~~~~~~~~~~~~~

The risk ratings in :numref:`table-risks` follow a version of the risk assessment scheme in :cite-title:`SP800-30`. Likelihood of an attack and its impact are evaluated independently, and then they are combined to obtain the overall risk of the attack.

The risk assessment is used to prioritize the threats that require mitigation. This helps to identify the mitigations that have the highest priority for implementation. Mitigations are described in :secref:`mitigations` and :secref:`remediation`.

It is recommended that this assessment is repeated for a specific implementation or product, taking into consideration the Adversarial models that are within scope, and re-evaluating the impact based on the assets at risk. :numref:`table-risks` repeats the association in :numref:`table-threats` between an Adversarial model and the Threats that it enables. This aids filtering of the assessment based on the models that are in scope for a specific implementation.

.. list-table:: Risk assessment
    :name: table-risks
    :class: longtable
    :header-rows: 1
    :widths: 1,1,1,1,1

    *   -   Adversarial Model
        -   Threat/Attack
        -   Likelihood
        -   Impact :sup:`a`
        -   Risk

    *   -   M.0
        -   T.1
        -   High
        -   Medium
        -   Medium
    *   -   M.0
        -   T.2
        -   High
        -   Medium
        -   Medium
    *   -   M.1
        -   T.3
        -   Medium
        -   High
        -   Medium
    *   -   M.1
        -   T.4
        -   High
        -   Medium
        -   Medium
    *   -   M.1
        -   T.5
        -   High
        -   Very high
        -   Very high
    *   -   M.1
        -   T.6
        -   High
        -   High
        -   High
    *   -   M.1
        -   T.7
        -   Medium
        -   Medium
        -   Medium
    *   -   M.1
        -   T.8/A.59
        -   Medium
        -   Medium
        -   Medium
    *   -   M.2
        -   T.8/A.19
        -   Low
        -   Medium
        -   Low
    *   -   M.2
        -   T.9/A.C12
        -   Low
        -   High
        -   Medium
    *   -   M.1
        -   T.9/A.C13
        -   Medium
        -   High
        -   Medium

a.  The impact of an attack is dependent on the impact of the disclosure or modification of the application data that is cryptographically protected. This is ultimately determined by the requirements and risk assessment for the product which is using the |API|. :numref:`table-risks` allocates the impact as follows:

    * 'Medium' if unspecified cryptoprocessor state or application data assets are affected.
    * 'High' if an application's cryptographic assets are affected.
    * 'Very High' if all cryptoprocessor assets are affected.

.. _mitigations:

Mitigations
-----------

Objectives
~~~~~~~~~~

The objectives in :numref:`table-objectives` are a high-level description of what the design must achieve in order to mitigate the threats. Detailed requirements that describe how the API or cryptoprocessor implementation can deliver the objectives are provided in :secref:`mitigation-requirements` and :secref:`remediation`.

.. list-table:: Mitigation objectives
    :name: table-objectives
    :class: longtable
    :header-rows: 1
    :widths: 1,7,5

    *   -   Id
        -   Description
        -   Threats addressed

    *   -   O.1
        -   Hide keys from the application
        -
    *   -
        -   Keys are never directly manipulated by application software. Instead keys are referred to by handle, removing the need to deal with sensitive key material inside applications. This form of API is also suitable for secure elements, based on tamper-resistant hardware, that never reveal cryptographic keys.
        -   T.1 T.2 T.3 --- see :secref:`keystore`.

            T.5 T.6 --- to mitigate T.5 and T.6, the implementation must provide some form of isolation. See :secref:`isolation`.

    *   -   O.2
        -   Limit key usage
        -
    *   -
        -   Associate each key with a policy that limits the use of the key. The policy is defined by the application when the key is created, after which it is immutable.

        -   T.2 T.3 --- see :secref:`key-policy`.

    *   -   O.3
        -   Best-practice cryptography
        -
    *   -
        -   An application developer-oriented API to achieve practical cryptography: the |API| offers services that are oriented towards the application of cryptographic methods like encrypt, sign, verify. This enables the implementation to focus on best-practice implementation of the cryptographic primitive, and the application developer on correct selection and use of those primitives.

        -   T.1 T.2 T.7 T.8 --- see :secref:`usability`.

    *   -   O.4
        -   Algorithm agility
        -
    *   -
        -   Cryptographic functions are not tied to a specific cryptographic algorithm. Primitives are designated at run-time. This simplifies updating an application to use a more secure algorithm, and makes it easier to implement dynamic selection of cryptographic algorithms within an application.

        -   T.1 --- see :secref:`algorithm-agility`.


.. _mitigation-requirements:

Requirements
~~~~~~~~~~~~

The design of the API can mitigate, or enable a cryptoprocessor to mitigate, some of the identified attacks. :numref:`tab-security-requirements` describes these mitigations. Mitigations that are delegated to the cryptoprocessor or application are described in :secref:`remediation`.

.. list-table:: Security requirements
    :name: tab-security-requirements
    :class: longtable
    :header-rows: 1
    :widths: 1,4,4,4

    *   -   Id
        -   Description
        -   API impact
        -   Threats/attacks addressed

    *   -   SR.1 (O.1)
        -   Key values are not exposed by the API, except when importing or exporting a key.
        -   The full key policy must be provided at the time a key is created. See :secref:`key-overview`.
        -   T.3/A.C5 --- key values are hidden by the API.

    *   -   SR.2 (O.2)
        -   The policy for a key must be set when the key is created, and be immutable afterward.
        -   The full key policy must be provided at the time a key is created. See `psa_key_attributes_t`.
        -   T.3/A.C5 --- once created, the key usage permissions cannot be changed to permit export.

            T.2/A.C4--- once created, a key cannot be repurposed by changing its policy.

    *   -   SR.3 (O.2)
        -   The key policy must control the algorithms that the key can be used with, and the functions of the API that the key can be used with.
        -   The key policy must include usage permissions, and permitted-algorithm attributes. See :secref:`key-policy`.
        -   T.2/A.C4 --- a key cannot be reused with different algorithms.

    *   -   SR.4 (O.1)
        -   Key export must be controlled by the key policy.
        -   See `PSA_KEY_USAGE_EXPORT`.
        -   T.3/A.C5 --- a key can only be extracted from the cryptoprocessor if explicitly permitted by the key creator.

    *   -   SR.5 (O.1)
        -   The policy of a copied key must not provide rights that are not permitted by the original key policy.
        -   See `psa_copy_key()`.
        -   T.3/A.C5 --- a copy of a key cannot be exported if the original could not be exported.

            T.3/A.C4 --- a copy of a key cannot be used in different algorithm to the original.

    *   -   SR.6 (O.3)
        -   Unless explicitly required by the use case, the API must not define cryptographic algorithms with known security weaknesses. If possible, deprecated algorithms should not be included.
        -   Algorithm inclusion is based on use cases. Warnings are provided for algorithms and operations with known security weaknesses, and recommendations made to use alternative algorithms.
        -   T.1/A.C1 A.C2 A.C3

    *   -   SR.7 (O.4)
        -   The API design must make it easy to change to a different algorithm of the same type.
        -   Cryptographic operation functions select the specific algorithm based on parameters passed at runtime. See :secref:`key-types` and :secref:`algorithms`.
        -   T.1/A.C1 A.C2 A.C3

    *   -   SR.8 (O.1)
        -   Key-derivation functions that expose part of the key value, or make part of the key value easily recoverable, must not be provided in the API.
        -
        -   T.3/A.C6

    *   -   SR.9 (O.3)
        -   Constant values defined by the API must be designed to resist bit faults.
        -   Key type values explicitly consider single-bit faults, see :secref:`key-type-encoding`. :sup:`a`

            Success and error status codes differ by multiple bits, see :secref:`status-codes`. :sup:`b`
        -   T.8/A.19 --- enablement only, mitigation is delegated to the implementation.

    *   -   SR.10 (O.3)
        -   The API design must permit the implementation of operations with data-independent timing.
        -   Provision of comparison functions for MAC, hash and key-derivation operations.
        -   T.7/A.C11 --- enablement only, mitigation is delegated to the implementation.

    *   -   SR.11 (O.3)
        -   Specify behavior for memory shared between the application and cryptoprocessor, including where multiple parameters overlap.
        -   Standardize the result when parameters overlap, see :secref:`buffer-overlap`.
        -   T.8/A.59 --- enablement only, mitigation is delegated to the implementation.

    *   -   SR.12 (O.1) (O.2)
        -   The API must permit the implementation to isolate the cryptoprocessor, to prevent access to keys without using the API.
        -   No use of shared memory between application and cryptoprocessor, except as function parameters.
        -   T.5/A.C7 --- enablement only, mitigation is delegated to the implementation.

    *   -   SR.13 (O.3)
        -   The API design must permit the implementation of operations using mitigation techniques that resist side-channel attacks.
        -   Operations that use random blinding to resist side-channel attacks, can return RNG-specific error codes.

            See also SR.12, which enables the cryptoprocessor to be fully isolated, and implemented within a separate security processor.
        -   T.9 --- enablement only, mitigation is delegated to the implementation.


a. Limited resistance to bit faults is still valuable in systems where memory may be susceptible to single-bit flip attacks, for example, Rowhammer on some types of DRAM.
b. Unlike key type values, algorithm identifiers used in cryptographic operations are verified against a the permitted-algorithm in the key policy. This provides a mitigation for a bit fault in an algorithm identifier value, without requiring error detection within the algorithm identifier itself.


Remediation & residual risk
---------------------------

.. _remediation:

Implementation remediations
~~~~~~~~~~~~~~~~~~~~~~~~~~~

:numref:`tab-remediation` includes all recommended remediations for an implementation, assuming the full adversarial model described in :secref:`adversarial-models`. When an implementation has a subset of the adversarial models, then individual remediations can be excluded from an implementation, if the associated threat is not relevant for that implementation.

.. list-table:: Implementation remediations
    :name: tab-remediation
    :class: longtable
    :header-rows: 1
    :widths: 1,4,8

    *   -   Id
        -   Identified gap
        -   Suggested remediation

    *   -   R.1 (O.1) (O.3)
        -   T.5 --- direct access to cryptoprocessor state.
        -   The cryptoprocessor implementation provides :term:`cryptoprocessor isolation` or :term:`caller isolation`, to isolate the application from the cryptoprocessor state, and from volatile and persistent key material.

    *   -   R.2 (O.1) (O.3)
        -   T.6 --- access and use another application's assets.
        -   The cryptoprocessor implementation provides :term:`caller isolation`, and maintains separate cryptoprocessor state for each application. Each application must only be able to access its own keys and ongoing operations.

            Caller isolation requires that the implementation can securely identify the caller of the |API|.

    *   -   R.3 (O.3)
        -   T.4/A.60 A.61 --- using illegal memory inputs.
        -   The cryptoprocessor implementation validates that memory buffers provided by the application are accessible by the application.

    *   -   R.4 (O.3)
        -   T.4/A.70 --- providing invalid formatted data.
        -   The cryptoprocessor implementation checks that imported key data is valid before use.

    *   -   R.5 (O.3)
        -   T.4/A.62 --- call the API in an invalid operation sequence.
        -   The cryptoprocessor implementation enforces the correct sequencing of calls in multi-part operations. See :secref:`multi-part-operations`.

    *   -   R.6 (O.1) (O.3)
        -   T.3/A.C5 A.C6 --- indirect key disclosure via the API.
        -   Cryptoprocessor implementation-specific extensions to the API must avoid providing mechanisms that can extract or recover key values, such as trivial key-derivation algorithms.

    *   -   R.8 (O.3)
        -   T.8/A.59 --- concurrent modification of parameter memory.
        -   The cryptoprocessor implementation treats application memory as untrusted and volatile, typically by not reading the same memory location twice. See :secref:`stability-of-parameters`.

    *   -   R.9 (O.3)
        -   T.2/A.C4 --- incorrect cryptographic parameters.
        -   The cryptoprocessor implementation validates the key attributes and other parameters used for a cryptographic operation, to ensure these conform to the API specification and to the specification of the algorithm itself.

    *   -   R.10 (O.3)
        -   T.1/A.C1 A.C2 A.C3 --- insecure cryptographic algorithms.
        -   The cryptoprocessor does not support deprecated cryptographic algorithms, unless justified by specific use case requirements.

    *   -   R.11 (O.3)
        -   T.7/A.C11 --- data-independent timing.
        -   The cryptoprocessor implements cryptographic operations with data-independent timing.

    *   -   R.12 (O.3)
        -   T.9 --- side-channels.
        -   The cryptoprocessor implements resistance to side-channels.


Residual risk
~~~~~~~~~~~~~

Threats T.2-T.4, and T.7-T.9 are fully mitigated in the API design, as described in :secref:`mitigations`, or the cryptoprocessor implementation, as described in :secref:`remediation`.

:numref:`tab-residual-risk` describes the remaining risks related to T.1, T.5, and T.6 that cannot be mitigated fully by the API or cryptoprocessor implementation. Responsibility for managing these risks lies with the application developers and system integrators.

.. list-table:: Residual risk
    :name: tab-residual-risk
    :class: longtable
    :header-rows: 1
    :widths: 1,4,8

    *   -   Id
        -   Threat/attack
        -   Suggested remediations

    *   -   RR.1
        -   T.1
        -   Selection of appropriately secure protocols, algorithms and key sizes is the responsibility of the application developer.
    *   -   RR.2
        -   T.5
        -   Correct isolation of the cryptoprocessor is the responsibility of the cryptoprocessor and system implementation.
    *   -   RR.3
        -   T.6
        -   Correct identification of the application client is the responsibility of the cryptoprocessor and system implementation.
