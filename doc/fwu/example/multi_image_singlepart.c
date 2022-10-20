// SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

#include <psa/update.h>

/* Atomic, multiple image update, with bundled manifests.
 * Installation requires reboot
 */

// Prepare a single image for update
static psa_status_t prepare_image(psa_fwu_component_t id,
                           const void *image, size_t image_size) {
    psa_status_t rc;

    // Assume the component state is READY
    rc = psa_fwu_start(id, NULL, 0);

    if (rc == PSA_SUCCESS) {
        rc = psa_fwu_write(id, 0, image, image_size);

        if (rc == PSA_SUCCESS) {
            rc = psa_fwu_finish(id);

        if (rc != PSA_SUCCESS) {
            // an error occurred during image preparation: clean up
            psa_fwu_cancel(id);
            psa_fwu_clean(id);
        }
    }
    return rc;
}

// Fetch and prepare a single image for update
static psa_status_t fetch_and_prepare_image(psa_fwu_component_t id) {
    psa_status_t rc;
    void *image;
    size_t image_size;

    // Get image data.
    // Assume this is dynamically allocated memory in this example
    image = fetch_image_data(id, &image_size);
    if (image == NULL)
        return PSA_ERROR_INSUFFICIENT_MEMORY;

    rc = prepare_image(id, image, image_size);
    free(image);
    return rc;
}

// Update a set of components atomically
// Prepare all the images before installing
// Clean up all preparation on error
void example_install_multiple_images(psa_fwu_component_id ids[],
                                     size_t num_ids) {
    psa_status_t rc;
    int ix;

    for (ix = 0, ix < num_ids; ++ix) {
        rc = fetch_and_prepare_image(ids[ix]);
        if (rc != PSA_SUCCESS)
            break;
    }

    if (rc == PSA_SUCCESS) {
        // All images are prepared, so now install them
        rc = psa_fwu_install();

        if (rc == PSA_SUCCESS_REBOOT) {
            // do other things and then eventually...
            psa_fwu_request_reboot();
            return;     // or wait for reboot to happen
        }
    }
    // an error occurred during image preparation: clean up.
    // All of the components prior to element ix have been prepared
    // Update of these needs to be aborted and erased.
    while (--ix >= 0) {
        psa_fwu_cancel(ids[ix]);
        psa_fwu_clean(ids[ix]);
    }
    // Report the failure ...
}
