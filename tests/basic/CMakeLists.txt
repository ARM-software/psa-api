cmake_minimum_required(VERSION 3.13)

# Testing
set(TESTS test_sha test_mac test_kdf test_aes)

foreach(test ${TESTS})
    set(TARGET "psa_basic_${test}")
    message(STATUS "Add ${TARGET}")
    add_executable(${TARGET})
    target_link_libraries(${TARGET} PRIVATE psa-crypto-poc)
    target_sources(${TARGET} PRIVATE "${test}.c")
    target_include_directories(${TARGET} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_include_directories(${TARGET} PRIVATE ${CMAKE_SOURCE_DIR}/dispatch)
    target_include_directories(${TARGET} PRIVATE ${CMAKE_SOURCE_DIR}/drivers/acme)
    target_include_directories(${TARGET} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/poc/drivers)
    add_test(NAME ${TARGET} COMMAND ${TARGET})
endforeach()
