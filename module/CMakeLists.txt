cmake_minimum_required(VERSION 3.22.1)
project(titan-module LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

# Zygisk-Modul: libtitan.so für arm64-v8a (Legacy)
add_library(titan SHARED main.cpp)
target_include_directories(titan PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_compile_options(titan PRIVATE -fvisibility=hidden -Wall -Wextra)
target_link_libraries(titan android log)
set_target_properties(titan PROPERTIES
    OUTPUT_NAME "titan"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
)

# Titan Zygisk: Hook + TitanHardwareState (alle nötigen Funktionen)
add_library(titan_zygisk SHARED
    zygisk_module.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/titan_hardware.cpp
)

target_include_directories(titan_zygisk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_compile_options(titan_zygisk PRIVATE -fvisibility=hidden -Wall -Wextra)
target_link_libraries(titan_zygisk android log)

set_target_properties(titan_zygisk PROPERTIES
    OUTPUT_NAME "titan_zygisk"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
)
