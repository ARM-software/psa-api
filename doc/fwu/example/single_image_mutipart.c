// SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

#include <psa/update.h>
#include <stdlib.h>
#include <stddef.h>

/* Single image update with a bundled manifest.
 * Image data is fetched and written incrementally in blocks
 */

void example_install_single_image_multipart(psa_fwu_component_t id,
                                            size_t total_image_size) {
    psa_status_t rc;
    size_t offset;
    size_t to_send;
    void *image;

    // Assume the component state is READY
    rc = psa_fwu_start(id, NULL, 0);

    if (rc == PSA_SUCCESS) {
        // Using dynamically allocated memory for this example

        image = malloc(PSA_FWU_MAX_WRITE_SIZE);
        if (image == NULL) {
            rc == PSA_ERROR_INSUFFICIENT_MEMORY;
        } else {
            for (offset = 0;
                offset < total_image_size,
                offset += PSA_FWU_MAX_WRITE_SIZE) {
                to_send = min(PSA_FWU_MAX_WRITE_SIZE, total_image_size - offset);
                if (fetch_next_part_of_image(id, image, to_send)) {
                    // failed to obtain next block of image
                    rc == PSA_ERROR_GENERIC_ERROR;
                    break;
                } else {
                    rc = psa_fwu_write(id, offset, image, to_send);
                    if (rc != PSA_SUCCESS) {
                        break;
                    }
                }
            }
            free(image);
        }

        if (rc == PSA_SUCCESS) {
            rc = psa_fwu_finish(id);

            if (rc == PSA_SUCCESS) {
                rc = psa_fwu_install();

                if (rc == PSA_SUCCESS) {
                    // installation completed, now clean up
                    psa_fwu_clean(id);
                    // report success ...
                    return;
                } else if (rc == PSA_SUCCESS_REBOOT) {
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
