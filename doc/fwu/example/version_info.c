// SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

#include <psa/update.h>

/* Assume that the components in this system have sequential identifiers
 * starting at zero.
 */
#define NUM_COMPONENTS 3

void example_get_installation_info() {

    psa_status_t rc;
    psa_fwu_component_t id;
    psa_fwu_component_info_t info;

    for (id = 0; id < NUM_COMPONENTS; ++id) {
        rc = psa_fwu_query(id, &info);

        if (rc == PSA_SUCCESS) {
            specific_protocol_report(id, info.version);
        }
    }
}
