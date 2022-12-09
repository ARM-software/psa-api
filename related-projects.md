<!--
SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Known implementations and projects related to the PSA Certified APIs

Updated Dec 2022.
 
## Software implementations

- The reference implementation for PSA Crypto API can be found inside Mbed TLS.
  [mbed-tls.readthedocs.io/en/latest](https://mbed-tls.readthedocs.io/en/latest/)

- Other PSA Certified APIs are included in the TF-M project.
  [https://www.trustedfirmware.org/projects/tf-m/](https://www.trustedfirmware.org/projects/tf-m/)

- Trusted Services implements those services in a Trusted Execution Environment on Cortex A processors.
  [https://www.trustedfirmware.org/projects/trusted-services/](https://www.trustedfirmware.org/projects/trusted-services/)

- PARSEC is a Rust-based Linux microservice based on the Crypto API.
  [https://parsec.community](https://parsec.community)

- Oberon PSA Crypto offers a way to support both hardware and optimized software crypto routines under the PSA Crypto API.
  [https://www.oberon-psa-crypto.ch/](https://www.oberon-psa-crypto.ch/)

- RIOT OS is integrating the Crypto API at a system-level for all crypto needs.
  [https://www.riot-os.org/](https://www.riot-os.org/) and the associated paper at [https://arxiv.org/abs/2208.09281](https://arxiv.org/abs/2208.09281). The RIOT OS uses the Crypto Driver Interface to integrate secure elements.


## Crypto driver implementations

Mbed TLS is developing a hardware driver interface that complements the Crypto API. The aim is to simplify the integration of cryptographic peripherals and secure elements into implementations of the Crypto API. See [https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md).

- The Silicon Labs SDK uses PSA driver API conventions.
  [https://www.silabs.com/developers/gecko-software-development-kit](https://www.silabs.com/developers/gecko-software-development-kit)

- The Nordic SDK uses PSA driver API conventions.
  [https://github.com/nrfconnect/sdk-nrf/tree/main/samples/crypto/psa_tls](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/crypto/psa_tls)
 
 
## API usage

- Mbed TLS implements TLS stack for embedded usage, based on Crypto API. Mbed TLS also uses the Secure Storage API for the Crypto implementation of key storage.
  [https://mbed-tls.readthedocs.io/en/latest/](https://mbed-tls.readthedocs.io/en/latest/)

- WolfSSL can consume PSA-compliant crypto backends.
  [https://www.wolfssl.com/platform-security-architecture-psa-crypto-api-support-wolfssl/](https://www.wolfssl.com/platform-security-architecture-psa-crypto-api-support-wolfssl/)

- t_cose uses PSA Crypto APIs for portability.
  [t_cose](https://github.com/laurencelundblade/t_cose)

- The EEMBC Securemark-TLS Benchmark uses PSA Crypto APIs.
  [https://github.com/eembc/securemark-tls](https://github.com/eembc/securemark-tls)

- The Matter project offers a PSA-compliant crypto adapter.
  [https://github.com/project-chip/connectedhomeip/tree/master/src/crypto](https://github.com/project-chip/connectedhomeip/tree/master/src/crypto)

- Zephyr OS integrates PSA Crypto APIs.
  [https://docs.zephyrproject.org/latest/samples/tfm_integration/psa_crypto/README.html](https://docs.zephyrproject.org/latest/samples/tfm_integration/psa_crypto/README.html)

----

*Copyright 2022, Arm Limited and/or its affiliates*

