# Change Log of Oberon PSA Crypto Core (Sandbox)

This is the initial version of the Oberon sandbox.
It contains the same Crypto Core as in the commercial Oberon PSA Crypto 2.1
release (2026-06-03).

## Compatibility

The sandbox Oberon PSA Crypto Core has been successfully tested for compatibility
with the following specifications / software:

- [PSA Certified Crypto API 1.4.1](https://arm-software.github.io/psa-api/crypto/1.4/IHI0086-PSA_Certified_Crypto_API-1.4.1.pdf)
- [PSA Crypto API 1.4 Final 1 PQC Extension](https://arm-software.github.io/psa-api/crypto/1.4/ext-pqc/AES0119-PSA_Certified_Crypto_API-1.4_PQC_Extension.1.pdf)
- [PSA Crypto Driver Interface 1.0 alpha 1](https://arm-software.github.io/psa-api/crypto-driver/1.0/111106-PSA_Certified_Crypto_Driver_Interface-1.0-alp.1.pdf)
  - Compatible to this version of the new draft standard.
    For KDF, PAKE and RNG the sandbox is ahead.
- [PSA API Test Suite v1.9](https://github.com/ARM-software/psa-arch-tests/releases/tag/v25.08_API1.9_ADAC_1.0.2)
  - Compatibility has been tested with the commercial Oberon software drivers.

## Features

- Common PSA Certified Crypto API features
  - Hashing, key agreement, signatures, encryption, DRBG
- Recent PSA Certified Crypto API features
  - Ascon-AEAD, Ascon-Hash, Ascon-XOF
  - Password-authenticated key exchange (PAKE)
    - EC-JPAKE, SPAKE2+, WPA3-SAE
    - PAKE is compatible with the driver interface proposal
  - Key Wrap
  - PQC support
    - LMS, HSS, XMSS, XMSS^MT
    - ML-KEM, ML-DSA
  - Extendable-output functions (XOF)
- PSA Driver Interface 1.0 alpha 1 support
  - With KDF proposal with buffering to enable opaque drivers
- Driver wrapper example for dispatch
- Example drivers (proof-of-concept only, not intended for production)
  - SHA, AES, HMAC, HKDF, RNG
  - Driver chaining: KDF chains to HMAC, which in turn chains to SHA
