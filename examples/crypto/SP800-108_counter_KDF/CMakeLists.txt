#
# SPDX-FileCopyrightText: Copyright (c) 2023 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.27.0)

project("SP800-108-counter-KDF")
add_executable(kbkdf)
target_sources(kbkdf PRIVATE main.c)


include(ExternalProject)


if(NOT DEFINED ${MBEDTLS_ROOT_PATH})
# Clone the library through using CMAKE
ExternalProject_Add(mbedcrypto
   GIT_REPOSITORY "https://github.com/Mbed-TLS/mbedtls"
   GIT_TAG "v3.5.1"
   GIT_SHALLOW ON
   BUILD_ALWAYS OFF
   SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/source_mbedtls"
   INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/install_mbedtls"
   CMAKE_CACHE_ARGS
       -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
       -DENABLE_TESTING:BOOL=OFF
       -DENABLE_PROGRAMS:BOOL=OFF
   )

else()
# Add the library using the a local folder
ExternalProject_Add(mbedcrypto
    SOURCE_DIR "${MBEDTLS_ROOT_PATH}"
    INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/install_mbedtls"
    CMAKE_CACHE_ARGS
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DENABLE_TESTING:BOOL=OFF
        -DENABLE_PROGRAMS:BOOL=OFF
    )

endif()

add_dependencies(kbkdf mbedcrypto)

target_include_directories(kbkdf PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/install_mbedtls/include)
target_link_libraries(kbkdf ${CMAKE_CURRENT_BINARY_DIR}/install_mbedtls/lib/libmbedcrypto.a)
