.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _use cases:

Use cases and rationale
=======================

The following subsections describe the primary use cases that this version of |API| aims to support. Other use cases are also possible.

The :term:`Platform Root of Trust` (PRoT) reports information, known as claims, that can be used to determine the exact implementation of the PRoT and its security state. If the PRoT loads other components then it also includes information about what it has loaded. Other components outside of the PRoT can add additional information to the report by calling the provided API, which will include and sign the additional information. The PRoT signs attestation reports using the :term:`Initial Attestation Key` (IAK).

Device enrolment
----------------

Enrolment is the ability for an online service to enlist a device. For example, a generic connected sensor that becomes part of a company's deployment. As part of the enrolment process, credentials need to be created for each device. However, the devices themselves need to be trustworthy to ensure that credentials are not leaked.

A common solution to this problem is to certify security hardware using third-party labs, who are trusted to deliver worthwhile certifications. By placing trust in evaluation reports (such as Common Criteria or PSA Certified), one can ascertain whether a Root of Trust exhibits important security properties. For example, one important property is the ability to generate a key pair of good quality (using a non-predictable random number generator) and store it in an isolated and  tamper-proof area, which provides strong assurance that a device private key is only ever known by that device. Each device instance contains a protected attestation key that can be used to prove that they are a particular certified implementation.

During such an enrolment process, a device might generate a new key pair and create a Certificate Signing Request (CSR) or equivalent, containing:

-  The public key of the generated key-pair.
-  A proof of possession of the corresponding private key (in general this is the public key signed by the private key). This protects against man-in-the-middle attacks where an attacker can hijack the enrolment to insert their own public key into the device request.
-  An initial attestation, in order for the recipient to assess how that particular combination of hardware and firmware can be trusted.

The CSR is then passed to a Certification Authority who can assign it an identity with the new service and then return an identity certificate signed using the private key of the Certification Authority. The Certification Authority may be operated by the company who owns the devices or operated by a trusted third party. Creating extra identities on devices is expected to be a routine operation.

If a device enforces a high level of isolation, where all applications execute within their own Secure Partition, then it allows several mutually-distrustful providers to install their applications side-by-side without having to worry about leaking assets from one application to another.

The attestation identity can be verified in an attestation process and checked against certification information. At the end of the process the credential manager can establish a secure connection to the attested endpoint, and deliver credentials. For example, these may be service access credentials.

Identifying certification
-------------------------

The combination of a hardware entity and the software installed on that entity can be certified to conform to some published security level.

Manufacturers of devices can advertise a security certification as an incentive to purchase their devices, or because it is a requirement from a regulator. To gain the certification a manufacturer can engage a test lab to verify the hardware and software combination of a device conforms to specific standards. Certification should not be declared by the device, instead it is a dynamic situation where the hardware and software state can be checked against the current known certification status for that combination.

The initial attestation report declares the state of the device to a verification service. The verification service can then:

-  Verify the production status of the device identity. For example, to identify whether the device is in an inventory, and whether it is a secured production device or a development device.
-  Verify the certification status of a device. This involves checking that all components are up to date, correctly signed, and certified to work together.

Integrity reporting
-------------------

A party may want to check the received list of claims against a database of known measurements for each component in order to decide which level of trust should be applied. Additional information can be included, such as the version numbers for all software running on the device. As a minimum, the device provides a hash for each loaded component. Boot measurements are included in order to assess if there are obvious signs of tampering with the device firmware.

Initial attestation requires three services:

-  Enrolment verification service enforcing policy as part of service enrolment of the device.
-  Production verification service (OEM), providing the production state of an attestation identity
-  Certification verification service (third party), verifying that all attested components are up to date, signed correctly, and certified to work together.

It is possible to further separate these roles. For example, there may be a separate software verification service.

These services can be hosted by different parties in online or offline settings:

-  The first service requires generating a challenge, reading back the device's token, and validating the signature of the token.
-  The second service may periodically log the current security state for all addressable devices and make that information available upon request. It does not require the knowledge of any pre-shared secret or a prior trust exchange with a device vendor. The various databases required for the full verification process may be local, replicated, or centralized, depending on the particular market.

Further information about using existing attestation protocols can be found in `[PSM]`.
