.. SPDX-FileCopyrightText: Copyright 2018-2020, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

CDDL
====

The :rfc-title:`8610` definition of the PSA token is included here for reference:

.. code:: none

	psa-token = {
	    psa-nonce-claim,
	    psa-client-id,
	    psa-instance-id,
	    psa-implementation-id,
	    psa-hardware-version,
	    psa-lifecycle,
	    psa-boot-seed,
	    ( psa-software-components // psa-no-sw-measurement ),
	    psa-profile,
	    psa-verification-service-indicator,
	}

	arm_psa_profile_id = -75000
	arm_psa_partition_id = -75001
	arm_psa_security_lifecycle = -75002
	arm_psa_implementation_id = -75003
	arm_psa_boot_seed = -75004
	arm_psa_hw_version = -75005
	arm_psa_sw_components = -75006
	arm_psa_no_sw_measurements = -75007
	arm_psa_nonce = -75008
	arm_psa_UEID = -75009
	arm_psa_origination = -75010

	psa-boot-seed-type = bytes .size 32

	psa-hash-type = bytes .size 32 / bytes .size 48 / bytes .size 64


	psa-boot-seed = (
	    arm_psa_boot_seed => psa-boot-seed-type
	)

	psa-client-id-nspe-type = -2147483648...0
	psa-client-id-spe-type = 1..2147483647

	psa-client-id-type = psa-client-id-nspe-type / psa-client-id-spe-type

	psa-client-id = (
	    arm_psa_partition_id => psa-client-id-type
	)

	psa-hardware-version-type = text .regexp "[0-9]{13}"

	psa-hardware-version = (
	    ? arm_psa_hw_version => psa-hardware-version-type
	)

	psa-implementation-id-type = bytes .size 32

	psa-implementation-id = (
	    arm_psa_implementation_id => psa-implementation-id-type
	)

	psa-instance-id-type = bytes .size 33

	psa-instance-id = (
	    arm_psa_UEID => psa-instance-id-type
	)

	psa-no-sw-measurements-type = 1

	psa-no-sw-measurement = (
	    arm_psa_no_sw_measurements => psa-no-sw-measurements-type
	)

	psa-nonce-claim = (
	    arm_psa_nonce => psa-hash-type
	)

	psa-profile-type = "PSA_IOT_PROFILE_1"

	psa-profile = (
	    ? arm_psa_profile_id => psa-profile-type
	)

	psa-lifecycle-unknown-type = 0x0000..0x00ff
	psa-lifecycle-assembly-and-test-type = 0x1000..0x10ff
	psa-lifecycle-psa-rot-provisioning-type = 0x2000..0x20ff
	psa-lifecycle-secured-type = 0x3000..0x30ff
	psa-lifecycle-non-psa-rot-debug-type = 0x4000..0x40ff
	psa-lifecycle-recoverable-psa-rot-debug-type = 0x5000..0x50ff
	psa-lifecycle-decommissioned-type = 0x6000..0x60ff

	psa-lifecycle-type =
	    psa-lifecycle-unknown-type /
	    psa-lifecycle-assembly-and-test-type /
	    psa-lifecycle-psa-rot-provisioning-type /
	    psa-lifecycle-secured-type /
	    psa-lifecycle-non-psa-rot-debug-type /
	    psa-lifecycle-recoverable-psa-rot-debug-type /
	    psa-lifecycle-decommissioned-type

	psa-lifecycle = (
	    arm_psa_security_lifecycle => psa-lifecycle-type
	)

	psa-software-component = {
	    ? 1 => text,         ; measurement type
	    2 => psa-hash-type, ; measurement value
	    ? 4  => text,        ; version
	    5 => psa-hash-type, ; signer id
	    ? 6 => text,         ; measurement description
	}

	psa-software-components = (
	    arm_psa_sw_components => [ + psa-software-component ]
	)

	psa-verification-service-indicator-type = text

	psa-verification-service-indicator = (
	    ? arm_psa_origination => psa-verification-service-indicator-type
	)
