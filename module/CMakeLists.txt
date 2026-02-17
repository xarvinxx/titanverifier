# ==============================================================================
# Hardware Overlay – Native Module Build Configuration
# Target: libhw_overlay.so for Zygisk Next (arm64-v8a)
# ==============================================================================

cmake_minimum_required(VERSION 3.22.1)
project(hw-overlay-module LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

# ==============================================================================
# Build Configuration
# ==============================================================================

option(HW_STEALTH_MODE "Disable all logging for stealth" OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(HW_DEBUG ON)
else()
    set(HW_DEBUG OFF)
endif()

# ==============================================================================
# Dobby Integration (Inline-Hooking Engine)
# ==============================================================================

set(DOBBY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../libs/dobby)
set(DOBBY_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(DOBBY_LIB_DIR ${DOBBY_ROOT}/${ANDROID_ABI})

if(EXISTS "${DOBBY_LIB_DIR}/libdobby.a")
    set(DOBBY_AVAILABLE ON)
    message(STATUS "Dobby found at: ${DOBBY_LIB_DIR}/libdobby.a")
else()
    set(DOBBY_AVAILABLE OFF)
    message(WARNING "Dobby not found at ${DOBBY_LIB_DIR}/libdobby.a")
    message(WARNING "Build Dobby first or download prebuilt:")
    message(WARNING "  mkdir -p libs/dobby/${ANDROID_ABI}")
    message(WARNING "  # Copy libdobby.a to that directory")
endif()

if(DOBBY_AVAILABLE)
    add_library(dobby STATIC IMPORTED)
    set_target_properties(dobby PROPERTIES
        IMPORTED_LOCATION ${DOBBY_LIB_DIR}/libdobby.a
        INTERFACE_INCLUDE_DIRECTORIES ${DOBBY_INCLUDE}
    )
endif()

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
    )
endif()

# ==============================================================================
# Target: libhw_overlay.so (Main Module)
# ==============================================================================

add_library(hw_overlay SHARED
    zygisk_module.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/hw_compat.cpp
)

target_include_directories(hw_overlay PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_compile_options(hw_overlay PRIVATE
    ${HW_COMMON_FLAGS}
    $<$<CONFIG:Release>:${HW_RELEASE_FLAGS}>
    $<$<CONFIG:Debug>:${HW_DEBUG_FLAGS}>
)

target_link_options(hw_overlay PRIVATE
    ${HW_LINKER_FLAGS}
)

if(HW_STEALTH_MODE)
    target_compile_definitions(hw_overlay PRIVATE STEALTH_MODE)
endif()

target_link_libraries(hw_overlay PRIVATE
    android
    log
)

if(DOBBY_AVAILABLE)
    target_link_libraries(hw_overlay PRIVATE dobby)
    target_compile_definitions(hw_overlay PRIVATE USE_DOBBY=1)
else()
    target_compile_definitions(hw_overlay PRIVATE USE_DOBBY=0)
    message(WARNING "Building without Dobby - hooks will not work!")
endif()

set_target_properties(hw_overlay PROPERTIES
    OUTPUT_NAME "hw_overlay"
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

install(TARGETS hw_overlay
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/zygisk/${ANDROID_ABI}
)

# ==============================================================================
# Custom Targets
# ==============================================================================

add_custom_target(build_dobby
    COMMAND ${CMAKE_COMMAND} -E echo "Building Dobby..."
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DOBBY_ROOT}
    COMMAND ${CMAKE_COMMAND} -E echo "Please build Dobby manually:"
    COMMAND ${CMAKE_COMMAND} -E echo "  git clone https://github.com/jmpews/Dobby.git /tmp/Dobby"
    COMMAND ${CMAKE_COMMAND} -E echo "  cd /tmp/Dobby && mkdir build && cd build"
    COMMAND ${CMAKE_COMMAND} -E echo "  cmake .. -DCMAKE_TOOLCHAIN_FILE=\$ANDROID_NDK/build/cmake/android.toolchain.cmake \\\\"
    COMMAND ${CMAKE_COMMAND} -E echo "    -DANDROID_ABI=${ANDROID_ABI} -DANDROID_PLATFORM=android-30 \\\\"
    COMMAND ${CMAKE_COMMAND} -E echo "    -DCMAKE_BUILD_TYPE=Release -DDOBBY_DEBUG=OFF"
    COMMAND ${CMAKE_COMMAND} -E echo "  make -j\$(nproc)"
    COMMAND ${CMAKE_COMMAND} -E echo "  cp libdobby.a ${DOBBY_LIB_DIR}/"
    COMMENT "Instructions for building Dobby"
)

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
message(STATUS "Dobby:          ${DOBBY_AVAILABLE}")
message(STATUS "Output:         ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}/")
message(STATUS "===============================================")
