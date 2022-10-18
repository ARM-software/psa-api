<!--
SPDX-FileCopyrightText: Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# PSA Certified API Specifications

This is the official place for the latest documents of the PSA Certified API.

This GitHub repository contains:
*  Specification source files
*  Reference copies of the PSA Certified API header files
*  Examples of usage and implementation of the PSA Certified APIs
*  Discussions of updates to the specifications
*  Proposed changes to the specifications

Officially released documents and sample code can be found in the associated [PSA Certified API website](https://arm-software.github.io/psa-api/).

## Specifications

The following specifications are part of the PSA API.

Specification | Published | Source | Status | Dashboard
-|-|-|-|-
Crypto API | [1.1.1][crypto-specs] | [`/doc/crypto`](doc/crypto) | Active | [Project board][crypto-dash]
Secure Storage API | [1.0.1][storage-specs] | [`/doc/storage`](doc/storage) | Pending |
Attestation API | [1.0.3][attestation-specs] | [`/doc/attestation`](doc/attestation) | Pending |
Firmware Update API | [1.0 Beta][fwu-specs] | [`/doc/fwu`](doc/fwu) | Active | [Working group][fwu-dash]
Status code API | [1.0.1][status-specs] | [`/doc/status-code`](doc/status-code) | Pending |

[crypto-specs]:         https://arm-software.github.io/psa-api/crypto/
[storage-specs]:        https://arm-software.github.io/psa-api/storage/
[attestation-specs]:    https://arm-software.github.io/psa-api/attestation/
[fwu-specs]:            https://arm-software.github.io/psa-api/fwu/
[status-specs]:         https://arm-software.github.io/psa-api/status-code/

[crypto-dash]:          https://github.com/orgs/ARM-software/projects/5
[fwu-dash]:             https://github.com/ARM-software/psa-firmware-update-spec/projects/1


## Extensions

Extension specifications introduce new functionality that is not yet stable enough for inclusion in the main specification.

Extension | Published | Source | Status | Dashboard
-|-|-|-|-
PAKE | [1.1 Beta 1][crypto-specs] | [`/doc/ext-pake`](doc/ext-pake) | Active | [Project board][crypto-dash]

## Reference header files

Reference header files for each minor version of each API are provided in the [`/headers`](headers) folder.

## Example source code

Source code examples of both usage, and implementation, of the PSA Certified APIs are provided in the [`examples`](/examples) folder.

## License

### Text and illustrations

Text and illustrations in this project are licensed under Creative Commons [Attribution–Share Alike 4.0 International license][CC-BY-SA-4.0] (CC BY-SA 4.0).

**Grant of patent license**. Subject to the terms and conditions of this license (both the CC BY-SA 4.0 Public License and this Patent License), each Licensor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as stated in this section) patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Licensed Material, where such license applies only to those patent claims licensable by such Licensor that are necessarily infringed by their contribution(s) alone or by combination of their contribution(s) with the Licensed Material to which such contribution(s) was submitted. If You institute patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Licensed Material or a contribution incorporated within the Licensed Material constitutes direct or contributory patent infringement, then any licenses granted to You under this license for that Licensed Material shall terminate as of the date such litigation is filed.

The Arm trademarks featured here are registered trademarks or trademarks of Arm Limited (or its subsidiaries) in the US and/or elsewhere. All rights reserved. Please visit [arm.com/company/policies/trademarks][trademarks] for more information about Arm's trademarks.

### About the license

The language in the additional patent license is largely identical to that in section 3 of [Apache License, Version 2.0][APACHE-2.0] (Apache 2.0) with two exceptions:

1. Changes are made related to the defined terms, to align those defined terms with the terminology in CC BY-SA 4.0 rather than Apache 2.0 (for example, changing "Work" to "Licensed Material").

2. The scope of the defensive termination clause is changed from "any patent licenses granted to You" to "any licenses granted to You". This change is intended to help maintain a healthy ecosystem by providing additional protection to the community against patent litigation claims.

[CC-BY-SA-4.0]:     https://creativecommons.org/licenses/by/4.0
[APACHE-2.0]:       https://www.apache.org/licenses/LICENSE-2.0
[trademarks]:       https://www.arm.com/company/policies/trademarks

### Source code

Source code samples in this project are licensed under the [Apache License, Version 2.0][APACHE-2.0] (the "License"); you may not use such samples except in compliance with the License. You may obtain a copy of the License at [apache.org/licenses/LICENSE-2.0][APACHE-2.0].

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and limitations under the License.

## Feedback

If you have questions or comments on any of the PSA Certified API specifications, or suggestions for enhancements, please [raise a new issue][psa-api-issue].

Please indicate which specification the issue applies to. This can be done by:

* Providing a link to the section of the specification on this website.
* Providing the document name, full version, and section or page number in the PDF.

[psa-api-issue]:    https://github.com/arm-software/psa-api/issues/new

## Contributing

Anyone may contribute to the PSA Certified API. Discussion of changes and enhancement happens in this repository's [Issues][issues] and [Pull requests][pulls]. See [CONTRIBUTING](CONTRIBUTING.md) for details.

[issues]:           https://github.com/arm-software/psa-api/issues
[pulls]:            https://github.com/arm-software/psa-api/pulls

----

*Copyright 2022, Arm Limited and/or its affiliates*
