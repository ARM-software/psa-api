// SPDX-FileCopyrightText: Copyright 2020-2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
// SPDX-License-Identifier: Apache-2.0

typedef uint8_t psa_fwu_component_t;
typedef struct { /* implementation-defined type */ } psa_fwu_impl_info_t;
typedef struct psa_fwu_component_info_t {
    uint8_t state;
    psa_status_t error;
    psa_fwu_image_version_t version;
    uint32_t max_size;
    uint32_t flags;
    uint32_t location;
    psa_fwu_impl_info_t impl;
} psa_fwu_component_info_t;
typedef struct psa_fwu_image_version_t {
    uint8_t major;
    uint8_t minor;
    uint16_t patch;
    uint32_t build;
} psa_fwu_image_version_t;
#define PSA_ERROR_DEPENDENCY_NEEDED ((psa_status_t)-156)
#define PSA_ERROR_FLASH_ABUSE ((psa_status_t)-160)
#define PSA_ERROR_INSUFFICIENT_POWER ((psa_status_t)-161)
#define PSA_FWU_API_VERSION_MAJOR 1
#define PSA_FWU_API_VERSION_MINOR 0
#define PSA_FWU_CANDIDATE 2u
#define PSA_FWU_FAILED 4u
#define PSA_FWU_FLAG_ENCRYPTION 0x00000002u
#define PSA_FWU_FLAG_VOLATILE_STAGING 0x00000001u
#define PSA_FWU_MAX_WRITE_SIZE /* implementation-defined value */
#define PSA_FWU_READY 0u
#define PSA_FWU_REJECTED 6u
#define PSA_FWU_STAGED 3u
#define PSA_FWU_TRIAL 5u
#define PSA_FWU_UPDATED 7u
#define PSA_FWU_WRITING 1u
#define PSA_SUCCESS_REBOOT ((psa_status_t)+1)
#define PSA_SUCCESS_RESTART ((psa_status_t)+2)
psa_status_t psa_fwu_accept(void);
psa_status_t psa_fwu_cancel(psa_fwu_component_t component);
psa_status_t psa_fwu_clean(psa_fwu_component_t component);
psa_status_t psa_fwu_finish(psa_fwu_component_t component);
psa_status_t psa_fwu_install(void);
psa_status_t psa_fwu_query(psa_fwu_component_t component,
                           psa_fwu_component_info_t *info);
psa_status_t psa_fwu_reject(psa_status_t error);
psa_status_t psa_fwu_request_reboot(void);
psa_status_t psa_fwu_start(psa_fwu_component_t component,
                           const void *manifest,
                           size_t manifest_size);
psa_status_t psa_fwu_write(psa_fwu_component_t component,
                           size_t image_offset,
                           const void *block,
                           size_t block_size);
