cmake_minimum_required(VERSION 3.22.1)
project(titan-module LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

# Zygisk-Modul: libtitan.so für arm64-v8a
add_library(titan SHARED main.cpp)

target_include_directories(titan PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_compile_options(titan PRIVATE -fvisibility=hidden -Wall -Wextra)
target_link_libraries(titan android log)

# Nur arm64-v8a (Zygisk auf Pixel 6)
set_target_properties(titan PROPERTIES
    OUTPUT_NAME "titan"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
)
