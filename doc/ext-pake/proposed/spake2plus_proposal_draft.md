Introduction
------------

This document proposes protocol flow and high-level API changes required in PSA Cryptography API 1.1 PAKE Extension, to support the SPAKE2+ protocol.

SPAKE2+ Version
---------------

SPAKE2+, an Augmented PAKE Draft 02, 10 December 2020 is considered for proposal.

Link : [https://tools.ietf.org/pdf/draft-bar-cfrg-spake2plus-02.pdf](https://tools.ietf.org/pdf/draft-bar-cfrg-spake2plus-02.pdf)

Remarks

*   SPAKE2+, an Augmented PAKE Draft 08, 5 May 2022 is the latest draft version. Link : [https://datatracker.ietf.org/doc/pdf/draft-bar-cfrg-spake2plus-08](https://datatracker.ietf.org/doc/pdf/draft-bar-cfrg-spake2plus-08)
*   Shared Secret Key generation is not compatible between Draft 02 and 08.
*   As most SPAKE2+ implementations e.g. Matter Specification Version 1.0 are based on Draft 02, this version is being considered for better interoperability.

Expected PAKE API Flow :
------------------------------------
![](SPAKE2PLUS.svg)


### Ciphersuite

The current PAKE ciphersuite does not have encoding for MAC. The SPAKE2+ draft recommends HMAC and CMAC for the MAC operation, therefore MAC field should be added to the ciphersuite.

### Key types

Define a new asymmetric key type for SPAKE2+ with `w0 || w1` as private key and `w0 || L` as public key.

**Shared Information** : ProverID, VerifierID and Context.

**Input methods** :

*   Existing API's (when user is Prover)
    *   `psa_pake_set_user()` to input ProverID
    *   `psa_pake_set_peer()` to input VerifierID
    *   `psa_pake_set_role()` to set role as client/server
*   Additional proposed API
    *   `psa_pake_set_context()` to input context (additional data)

### Registration

Propose a new API `psa_pake_registration()` which will take as input:
* PAKE operation with user and peer IDs
* PBKDF operation which is initialized with the key attributes, PBKDF parameters and password received OOB
* key attributes for the output

The function will compute `w0 || w1` if role is set as prover or `w0 || L` if role is set as verifier and store the result as a key.

```
psa_status_t psa_pake_registration(psa_pake_operation_t *pake, psa_key_derivation_operation_t *pbkdf, psa_key_attributes_t *attributes);
```

### Key confirmation

Key confirmation is part of the SPAKE2+ protocol. Current PSA Cryptography API 1.1 PAKE Extension only supports implicit key confirmation.

*   New API `psa_pake_get_explicit_key()`  which will take as input the current PAKE operation and the attributes for the explicit key and return the key id of the explicit key.
  ```
  psa_pake_get_explicit_key(psa_pake_operation_t *pake, psa_key_attributes_t *attributes, psa_key_id_t *explicit_key);
  ```

