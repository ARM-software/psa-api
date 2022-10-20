// SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

#include <psa/update.h>

/* Simple, single image update with a bundled manifest.
 * Component requires reboot
 */

void example_install_single_image(psa_fwu_component_t id,
                                  const void *image, size_t image_size) {
    psa_status_t rc;

    // Assume the component state is READY
    rc = psa_fwu_start(id, NULL, 0);

    if (rc == PSA_SUCCESS) {
        rc = psa_fwu_write(id, 0, image, image_size);

        if (rc == PSA_SUCCESS) {
            rc = psa_fwu_finish(id);

            if (rc == PSA_SUCCESS) {
                rc = psa_fwu_install();

                if (rc == PSA_SUCCESS_REBOOT) {
                    // do other things and then eventually...
                    psa_fwu_request_reboot();
                    return;     // or wait for reboot to happen
                }
            }
        }
        // an error occurred during image preparation: clean up
        psa_fwu_cancel(id);
        psa_fwu_clean(id);
    }
    // report failure...
}
