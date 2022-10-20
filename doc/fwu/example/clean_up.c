// SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

#include <psa/update.h>

/* Assume that the components in this system have sequential identifiers
 * starting at zero.
 */
#define NUM_COMPONENTS 3

/* Forcibly cancel and clean up all components to return to READY state */

void example_clean_all_components() {

    psa_status_t rc;
    psa_fwu_component_t id;
    psa_fwu_component_info_t info;

    rc = psa_fwu_reject();
    if (rc == PSA_SUCCESS_REBOOT) {
        psa_fwu_request_reboot();
        // After reboot, run this function again to finish clean up
        return;
    }

    for (id = 0; id < NUM_COMPONENTS; ++id) {
        rc = psa_fwu_query(id, &info);

        if (rc == PSA_SUCCESS) {
            switch (info.state) {
               case PSA_FWU_WRITING:
               case PSA_FWU_CANDIDATE:
                  psa_fwu_cancel(id);
                  psa_fwu_clean(id);
                  break;
               case PSA_FWU_FAILED:
               case PSA_FWU_UPDATED:
                  psa_fwu_clean(id);
                  break;
            }
        }
    }
}
