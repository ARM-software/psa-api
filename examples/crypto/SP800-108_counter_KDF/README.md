<!--
SPDX-FileCopyrightText: Copyright (c) 2023-2024 Nordic Semiconductor ASA
SPDX-License-Identifier: Apache-2.0
-->

NIST SP 800-108 counter-mode KDF
================================

This example shows a reference implementation for a key based key derivation function for counter mode that conforms to the [NIST SP 800-108r1 recommendation](https://csrc.nist.gov/pubs/sp/800/108/r1/final).

It includes a HMAC and a CMAC variant.
The CMAC variant implements the suggested addition to prevent a key control attack that is listed in Appendix B of [SP 800-108](https://csrc.nist.gov/pubs/sp/800/108/r1/final).



Building the example
********************
To build the example CMake 3.10.2 or later is required.
Also [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) is required.
You can either provide a Mbed TLS installation that exists or the build script will clone it into the build folder.
Check the [requirements for building Mbed TLS](https://github.com/Mbed-TLS/mbedtls#compiling) to make sure all required dependencies are installed.


To build the example then use CMake

        [optional] export MBEDTLS_ROOT_PATH="/path/to/your/mbedtls"
        mkdir build && cd build
        cmake -G "Unix Makefiles" ..
        cmake --build .


Then run the sample

        ./kbkdf
        Deriving a key using SP800-108 HMAC(SHA256) counter mode...Done
        Key:
        ------------------- len: 32 -------------------
        01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0d 0f
        01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0d 0f
        --------------------- end ---------------------
        Label:
        ------------------- len: 32 -------------------
        50 53 41 5f 41 4c 47 5f 53 50 38 30 30 5f 31 30
        38 5f 43 4f 55 4e 54 45 52 20 53 61 6d 70 6c 65
        --------------------- end ---------------------
        Context:
        ------------------- len: 49 -------------------
        53 61 6d 70 6c 65 20 6b 65 79 20 63 72 65 61 74
        69 6f 6e 20 76 69 61 20 53 50 20 38 30 30 2d 31
        30 38 72 31 20 43 6f 75 6e 74 65 72 20 6d 6f 64
        65
        --------------------- end ---------------------
        Capacity: 0x2a

        HMAC derived key:
        ------------------- len: 42 -------------------
        81 58 cd 6a e7 50 69 0c 20 54 be 10 66 d2 d8 f3
        4a b0 14 d0 7f 81 4c bc 7d 3e 3d ca 78 a9 3f 5d
        66 29 b1 14 b4 2a 04 64 a4 89
        --------------------- end ---------------------


        Deriving a key using SP800-108 HMAC(SHA256) counter mode...Done
        Key:
        ------------------- len: 32 -------------------
        01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0d 0f
        01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0d 0f
        --------------------- end ---------------------
        Label:
        ------------------- len: 32 -------------------
        50 53 41 5f 41 4c 47 5f 53 50 38 30 30 5f 31 30
        38 5f 43 4f 55 4e 54 45 52 20 53 61 6d 70 6c 65
        --------------------- end ---------------------
        Capacity: 0x2a

        HMAC without context derived key:
        ------------------- len: 42 -------------------
        2f e0 5b d4 22 00 4f a1 9a 48 cd 8c 9b d2 ca 8d
        39 87 ea 6c 5a bc d5 54 3a ed eb 04 e2 b7 00 0c
        b6 eb 18 c3 3a 3d 89 67 a7 d6
        --------------------- end ---------------------


        Deriving a key using SP800-108 CMAC counter mode...Done
        Key:
        ------------------- len: 16 -------------------
        01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0d 0f
        --------------------- end ---------------------
        Label:
        ------------------- len: 32 -------------------
        50 53 41 5f 41 4c 47 5f 53 50 38 30 30 5f 31 30
        38 5f 43 4f 55 4e 54 45 52 20 53 61 6d 70 6c 65
        --------------------- end ---------------------
        Context:
        ------------------- len: 49 -------------------
        53 61 6d 70 6c 65 20 6b 65 79 20 63 72 65 61 74
        69 6f 6e 20 76 69 61 20 53 50 20 38 30 30 2d 31
        30 38 72 31 20 43 6f 75 6e 74 65 72 20 6d 6f 64
        65
        --------------------- end ---------------------
        Capacity: 0x2a

        CMAC derived key:
        ------------------- len: 42 -------------------
        3c 50 b5 5a 13 b9 49 ad 25 b4 b4 0f c3 7f 55 38
        36 b5 9f a0 d0 74 b7 3c 83 17 6d 4c 10 5f c2 17
        83 8e c4 a1 b0 7b 8a be a8 f1
        --------------------- end ---------------------


        Deriving a key using SP800-108 CMAC counter mode...Done
        Key:
        ------------------- len: 16 -------------------
        01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0d 0f
        --------------------- end ---------------------
        Label:
        ------------------- len: 32 -------------------
        50 53 41 5f 41 4c 47 5f 53 50 38 30 30 5f 31 30
        38 5f 43 4f 55 4e 54 45 52 20 53 61 6d 70 6c 65
        --------------------- end ---------------------
        Capacity: 0x2a

        CMAC without context derived key:
        ------------------- len: 42 -------------------
        e1 ec fc 00 1e 2e 9a db d0 16 b3 b4 f3 23 ce 00
        c1 05 82 ec 81 e1 fc 19 40 47 4c a6 84 f9 e5 07
        b5 8a bd 03 bc e5 23 82 05 11
        --------------------- end ---------------------