cmake_minimum_required(VERSION 3.13)
# Note: operator precedence for AND/OR differs in CMake 3.13.4 release, explicit bracketing required

# top level project for the PSA Core object libraries
project(oberon-psa-crypto-core LANGUAGES C)

# Prevent implicit installation to system default directory.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE "${CMAKE_SOURCE_DIR}/export")
endif()

# toolchain specific settings 
if(MSVC)
    add_compile_options(/std:c11)
elseif(CMAKE_C_COMPILER_ID MATCHES Clang)
    add_compile_options(-Wno-logical-op-parentheses)
    add_compile_options(-Wno-bitwise-op-parentheses)
    add_compile_options(-Wno-tautological-constant-out-of-range-compare)
    add_compile_options(-Wno-gnu-folding-constant)
elseif(UNIX)
    add_compile_options(-O2 -Wall -Wextra -Werror)
endif()

# build options
option(CONFIG_PSA_BASIC_TESTS        "Build basic PSA Crypto API tests"                  ON)
option(CONFIG_MBEDTLS_THREADING      "Build for multi-threading"                        OFF)

message(STATUS " - CONFIG_MBEDTLS_THREADING:      ${CONFIG_MBEDTLS_THREADING}")
message(STATUS " - CONFIG_PSA_BASIC_TESTS:        ${CONFIG_PSA_BASIC_TESTS}")
if(DEFINED PSA_ARCH_TESTS)
    get_filename_component(PSA_ARCH_TESTS "${PSA_ARCH_TESTS}" REALPATH)
    message(STATUS " - PSA_ARCH_TESTS-PATH:           ${PSA_ARCH_TESTS}")
endif()

# oberon-psa-crypto core library
add_library(${PROJECT_NAME} OBJECT)

# define sources originating from TF-PSA-Crypto
set(TF_PSA_CRYPTO_SOURCES
        ${CMAKE_SOURCE_DIR}/core/check_crypto_config.h
        ${CMAKE_SOURCE_DIR}/core/tf_psa_crypto_common.h
        ${CMAKE_SOURCE_DIR}/core/psa_crypto.c
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_client.c
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_core.h
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_invasive.h
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_its.h
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_slot_management.h
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_slot_management.c
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_storage.h
        ${CMAKE_SOURCE_DIR}/core/psa_crypto_storage.c
        ${CMAKE_SOURCE_DIR}/core/psa_its_file.c
        ${CMAKE_SOURCE_DIR}/platform/platform.c
        ${CMAKE_SOURCE_DIR}/platform/platform_util.c
        ${CMAKE_SOURCE_DIR}/platform/threading.c
        ${CMAKE_SOURCE_DIR}/utilities/constant_time.c
)

# common sources and includes
target_sources(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_SOURCES})

if(CONFIG_MBEDTLS_THREADING)
    target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
    target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/platform/threading.c")
endif()

# default TF-PSA-Crypto includes
target_include_directories(${PROJECT_NAME} PRIVATE include)
target_include_directories(${PROJECT_NAME} PRIVATE core)
target_include_directories(${PROJECT_NAME} PRIVATE dispatch)
target_include_directories(${PROJECT_NAME} PRIVATE platform)

# poc dispatch, acme driver, and driver config includes
target_include_directories(${PROJECT_NAME} PRIVATE targets/acme/poc/dispatch)
target_include_directories(${PROJECT_NAME} PRIVATE drivers/acme)

# poc psa-crypto library with config and other headers from default locations
project(psa-crypto-poc LANGUAGES C)

# create poc library for host platform
add_library(${PROJECT_NAME} STATIC $<TARGET_OBJECTS:oberon-psa-crypto-core>)

# add acme drivers
add_subdirectory(drivers/acme)

# driver wrapper dispatching to acme drivers
target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/poc/dispatch/psa_crypto_driver_wrappers.c)

# includes psa/crypto_config.h
target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:include>)
target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/targets/acme/poc/dispatch>
        $<INSTALL_INTERFACE:include>)

target_include_directories(${PROJECT_NAME} PRIVATE core)
target_include_directories(${PROJECT_NAME} PRIVATE dispatch)
target_include_directories(${PROJECT_NAME} PRIVATE platform)
target_include_directories(${PROJECT_NAME} PRIVATE drivers/acme)
target_include_directories(${PROJECT_NAME} PRIVATE targets/acme/poc/drivers)

# add threading
if(CONFIG_MBEDTLS_THREADING)
    target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
    target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/platform/threading.c")
endif()

if (CONFIG_PSA_BASIC_TESTS)
    include(CTest)
    add_subdirectory(tests/basic)
endif()

# PSA API Test Suite; uses demo drivers for entropy and opaque
if (DEFINED PSA_ARCH_TESTS)
    include(CTest)

    set(PSA_INCLUDE_PATHS_RELATIVE
        include
        targets/acme/poc/dispatch # use psa/crypto_config.h from poc
        drivers/acme
    )  
    set(PSA_CRYPTO_POC psa-crypto-poc)

    # cmake ../ -G"Unix Makefiles" -DTARGET=tgt_dev_apis_linux \
    #           -DTOOLCHAIN=INHERIT -DSUITE=CRYPTO -DPSA_INCLUDE_PATHS="..."

    set(TARGET tgt_dev_apis_linux)
    set(TOOLCHAIN INHERIT)
    set(SUITE CRYPTO)
    set(PSA_INCLUDE_PATHS "")
    foreach(PSA_INCLUDE_PATH ${PSA_INCLUDE_PATHS_RELATIVE})
        get_filename_component(PSA_INCLUDE_PATH "${PSA_INCLUDE_PATH}" REALPATH)
        list(APPEND PSA_INCLUDE_PATHS ${PSA_INCLUDE_PATH})
    endforeach()
    
    project("${TARGET}" LANGUAGES C ASM)

    add_subdirectory(${PSA_ARCH_TESTS}/api-tests api-tests)
    add_executable(${PROJECT_NAME} ${PSA_ARCH_TESTS}/api-tests/platform/targets/${PROJECT_NAME}/nspe/main.c)

    target_link_libraries(${TARGET} PRIVATE val_nspe)
    target_link_libraries(${TARGET} PRIVATE pal_nspe)
    target_link_libraries(${TARGET} PRIVATE test_combine)

    target_link_libraries(${TARGET} PUBLIC ${PSA_CRYPTO_POC})

    set_target_properties(${PROJECT_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}")

    add_test(NAME ${PROJECT_NAME} COMMAND "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}")
    set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_PSA_API_TESTS)
endif()
