<!--
SPDX-FileCopyrightText: Copyright 2022-2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# PSA Certified APIs

This is the official place for the latest published documents of the PSA Certified APIs.

Specification source files, updates, and discussions, as well as reference headers and example code, can be found in the associated [PSA Certified APIs GitHub project][psa-api-gh].

Test suites to verify a correct implementation can be found in the [PSA Certified APIs Test suites][psa-api-ats].

[psa-api-gh]:       https://github.com/arm-software/psa-api
[psa-api-ats]:      https://github.com/ARM-software/psa-arch-tests/tree/main/api-tests/dev_apis


## Specifications

The following specifications are part of the PSA Certified APIs:

Specification | | | | |
-|-|-|-|-
Crypto API | 1.1 | [HTML][crypto-html] | [&darr; PDF][crypto-pdf] | [All versions](crypto/)
Secure Storage API | 1.0 | [HTML][storage-html] | [&darr; PDF][storage-pdf] | [All versions](storage/)
Attestation API | 1.0 | [HTML][attestation-html] | [&darr; PDF][attestation-pdf] | [All versions](attestation/)
Firmware Update API | 1.0 | [HTML][fwu-html] | [&darr; PDF][fwu-pdf] | [All versions](fwu/)
Status code API | 1.0 | [HTML][status-code-html] | [&darr; PDF][status-code-pdf] | [All versions](status-code/)

## Extensions

Extension specifications introduce new functionality that is not yet stable enough for inclusion in the main specification.

Specification | Extension | | | | |
-|-|-|-|-|-
Crypto API | PAKE | 1.1 Beta | [HTML][pake-html] | [&darr; PDF][pake-pdf] | [All versions](crypto/)

[status-code-html]:  status-code/1.0/
[status-code-pdf]:   status-code/1.0/IHI0097-PSA_Certified_Status_code_API-1.0.3.pdf
[crypto-html]:       crypto/1.1/
[crypto-pdf]:        crypto/1.1/IHI0086-PSA_Certified_Crypto_API-1.1.2.pdf
[storage-html]:      storage/1.0/
[storage-pdf]:       storage/1.0/IHI0087-PSA_Certified_Secure_Storage_API-1.0.3.pdf
[attestation-html]:  attestation/1.0/
[attestation-pdf]:   attestation/1.0/IHI0085-PSA_Certified_Attestation_API-1.0.3.pdf
[fwu-html]:          fwu/1.0/
[fwu-pdf]:           fwu/1.0/IHI0093-PSA_Certified_Firmware_Update_API-1.0.0.pdf
[pake-html]:         crypto/1.1/ext-pake/
[pake-pdf]:          crypto/1.1/ext-pake/AES0058-PSA_Certified_Crypto_API-1.1_PAKE_Extension-bet.1.pdf

## Feedback

If you have questions or comments on any of the specifications, or suggestions for enhancements, please [raise a new issue][psa-api-issue] in the PSA Certified APIs GitHub project.

Please indicate which specification the issue applies to. This can be done by:

* Providing a link to the section of the specification on this website.
* Providing the document name, full version, and section or page number in the PDF.

[psa-api-issue]:    https://github.com/arm-software/psa-api/issues/new

## License

The latest versions of the PSA Certified APIs that are hosted on this website are licensed under the Creative Commons [Attribution–Share Alike 4.0 International license][CC-BY-SA-4.0] and [Apache License, Version 2.0][APACHE-2.0]. Some earlier versions of the specifications are licensed under a non-confidential license from Arm.

Refer to individual documents for license details.

[CC-BY-SA-4.0]:     https://creativecommons.org/licenses/by/4.0
[APACHE-2.0]:       https://www.apache.org/licenses/LICENSE-2.0

----

*Copyright 2022-2024, Arm Limited and/or its affiliates*
