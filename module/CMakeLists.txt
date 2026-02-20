# ==============================================================================
# Hardware Overlay – Native Module Build Configuration
# Target: libcompat.so for Zygisk Next (arm64-v8a)
# ==============================================================================

cmake_minimum_required(VERSION 3.22.1)
project(hw-overlay-module LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

# ==============================================================================
# Build Configuration
# ==============================================================================

option(HW_STEALTH_MODE "Disable all logging for stealth" ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(HW_DEBUG ON)
else()
    set(HW_DEBUG OFF)
endif()

# Dobby removed (v8.0)
# LSPlant v6.4 (pre-module commit 386200f) — pre-built static library
# Built with NDK r27d (Clang 18) targeting arm64-v8a, Android API 31, c++_static

# ==============================================================================
# Compiler Flags (Stealth + Performance)
# ==============================================================================

set(HW_COMMON_FLAGS
    -Wall
    -Wextra
    -Werror=return-type
    -fno-exceptions
    -fno-rtti
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -ffunction-sections
    -fdata-sections
)

set(HW_RELEASE_FLAGS
    -O3
    -DNDEBUG
    -fomit-frame-pointer
    -flto
)

set(HW_DEBUG_FLAGS
    -O0
    -g
    -DDEBUG
)

set(HW_LINKER_FLAGS
    -Wl,--gc-sections
    -Wl,--exclude-libs,ALL
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,--hash-style=gnu
    -Wl,--allow-shlib-undefined
)

if(NOT HW_DEBUG)
    list(APPEND HW_LINKER_FLAGS
        -Wl,--strip-all
        -flto
    )
endif()

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

# ==============================================================================
# Target: libcompat.so (Main Module)
# ==============================================================================

add_library(compat SHARED
    zygisk_module.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/hw_compat.cpp
)

# LSPlant pre-built static libraries
add_library(lsplant_static STATIC IMPORTED)
set_target_properties(lsplant_static PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/liblsplant_static.a
)

add_library(dex_builder_static STATIC IMPORTED)
set_target_properties(dex_builder_static PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ANDROID_ABI}/libdex_builder_static.a
)

target_include_directories(compat PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/lsplant
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_compile_options(compat PRIVATE
    ${HW_COMMON_FLAGS}
    $<$<CONFIG:Release>:${HW_RELEASE_FLAGS}>
    $<$<CONFIG:Debug>:${HW_DEBUG_FLAGS}>
)

target_link_options(compat PRIVATE
    ${HW_LINKER_FLAGS}
)

if(HW_STEALTH_MODE)
    target_compile_definitions(compat PRIVATE STEALTH_MODE)
endif()

target_link_libraries(compat PRIVATE
    android
    log
    lsplant_static
    dex_builder_static
)


set_target_properties(compat PROPERTIES
    OUTPUT_NAME "compat"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
)

# ==============================================================================
# Target: libhw_compat.so (Legacy)
# ==============================================================================

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")
    add_library(hw_compat_legacy SHARED main.cpp)
    
    target_include_directories(hw_compat_legacy PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
    
    target_compile_options(hw_compat_legacy PRIVATE
        ${HW_COMMON_FLAGS}
        $<$<CONFIG:Release>:${HW_RELEASE_FLAGS}>
        $<$<CONFIG:Debug>:${HW_DEBUG_FLAGS}>
    )
    
    target_link_libraries(hw_compat_legacy PRIVATE android log)
    
    set_target_properties(hw_compat_legacy PROPERTIES
        OUTPUT_NAME "hw_compat"
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
    )
endif()

# ==============================================================================
# Install Rules
# ==============================================================================

install(TARGETS compat
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/zygisk/${ANDROID_ABI}
)

# ==============================================================================
# Custom Targets
# ==============================================================================


# ==============================================================================
# Build-Info
# ==============================================================================

message(STATUS "===============================================")
message(STATUS "HW Overlay - Native Module Configuration")
message(STATUS "===============================================")
message(STATUS "Build Type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "Android ABI:    ${ANDROID_ABI}")
message(STATUS "Android API:    ${ANDROID_NATIVE_API_LEVEL}")
message(STATUS "Stealth Mode:   ${HW_STEALTH_MODE}")
message(STATUS "Hook Engine:    LSPlant (ART) + Inline (Native)")
message(STATUS "Output:         ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}/")
message(STATUS "===============================================")
