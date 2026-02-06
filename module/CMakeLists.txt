# ==============================================================================
# Project Titan – Native Module Build Configuration
# Phase 3.3 Convergence: Dobby Integration + Stealth Optimization
#
# Target: libtitan_zygisk.so für Zygisk Next (arm64-v8a)
# Hardware: Google Pixel 6 (Oriole), Tensor G1
# Environment: Android 14 (API 34), KernelSU
# ==============================================================================

cmake_minimum_required(VERSION 3.22.1)
project(titan-module LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

# ==============================================================================
# Build Configuration
# ==============================================================================

# Stealth-Mode: Deaktiviert Logging in Release-Builds
option(TITAN_STEALTH_MODE "Disable all logging for stealth" OFF)

# Debug-Build erkennen
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(TITAN_DEBUG ON)
else()
    set(TITAN_DEBUG OFF)
    # Stealth-Mode bleibt wie vom User gewählt (nicht erzwungen)
endif()

# ==============================================================================
# Dobby Integration (Inline-Hooking Engine)
# ==============================================================================

# Pfad zur Dobby prebuilt library
set(DOBBY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../libs/dobby)
set(DOBBY_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../include)  # Header in include/dobby.h
set(DOBBY_LIB_DIR ${DOBBY_ROOT}/${ANDROID_ABI})

# Prüfe ob Dobby vorhanden ist
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

# Importiere Dobby als statische Library
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

# Basis-Flags für alle Targets
set(TITAN_COMMON_FLAGS
    -Wall
    -Wextra
    -Werror=return-type
    -fno-exceptions        # Keine C++ Exceptions (Footprint reduzieren)
    -fno-rtti              # Keine RTTI (Footprint + Anti-Forensics)
    -fvisibility=hidden    # Alle Symbole hidden by default
    -fvisibility-inlines-hidden
    -ffunction-sections    # Ermöglicht --gc-sections
    -fdata-sections
)

# Release/Stealth-Flags
set(TITAN_RELEASE_FLAGS
    -O3                    # Maximale Optimierung
    -DNDEBUG
    # LTO deaktiviert - verursacht Probleme mit Zygisk-Runtime-Symbolen
    # -flto=thin
    -fomit-frame-pointer   # Spart Instruktionen
)

# Debug-Flags
set(TITAN_DEBUG_FLAGS
    -O0
    -g
    -DDEBUG
)

# Linker-Flags
set(TITAN_LINKER_FLAGS
    -Wl,--gc-sections           # Entferne unbenutzte Sections
    -Wl,--exclude-libs,ALL      # Exportiere keine Symbole aus statischen Libs
    -Wl,-z,relro                # Relocation Read-Only (Security)
    -Wl,-z,now                  # Full RELRO
    -Wl,--hash-style=gnu        # Schnellere Symbol-Lookups
    -Wl,--allow-shlib-undefined # Erlaube unaufgelöste Symbole (Zygisk-Runtime)
)

# Strip-Flags für Release
if(NOT TITAN_DEBUG)
    list(APPEND TITAN_LINKER_FLAGS
        -Wl,--strip-all    # Entferne alle Symbole
    )
endif()

# ==============================================================================
# Target: libtitan_zygisk.so (Hauptmodul)
# ==============================================================================

add_library(titan_zygisk SHARED
    zygisk_module.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/titan_hardware.cpp
)

target_include_directories(titan_zygisk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_compile_options(titan_zygisk PRIVATE
    ${TITAN_COMMON_FLAGS}
    $<$<CONFIG:Release>:${TITAN_RELEASE_FLAGS}>
    $<$<CONFIG:Debug>:${TITAN_DEBUG_FLAGS}>
)

target_link_options(titan_zygisk PRIVATE
    ${TITAN_LINKER_FLAGS}
)

# Stealth-Modus definieren
if(TITAN_STEALTH_MODE)
    target_compile_definitions(titan_zygisk PRIVATE TITAN_STEALTH)
endif()

# Link gegen Android Libraries
target_link_libraries(titan_zygisk PRIVATE
    android
    log
)

# Link gegen Dobby (wenn verfügbar)
if(DOBBY_AVAILABLE)
    target_link_libraries(titan_zygisk PRIVATE dobby)
    target_compile_definitions(titan_zygisk PRIVATE USE_DOBBY=1)
else()
    target_compile_definitions(titan_zygisk PRIVATE USE_DOBBY=0)
    message(WARNING "Building without Dobby - hooks will not work!")
endif()

# Output-Konfiguration
set_target_properties(titan_zygisk PROPERTIES
    OUTPUT_NAME "titan_zygisk"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
    # Entferne lib-Prefix für Zygisk-Kompatibilität (optional)
    # PREFIX ""
)

# ==============================================================================
# Target: libtitan.so (Legacy-Kompatibilität)
# ==============================================================================

# Prüfe ob main.cpp existiert
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")
    add_library(titan SHARED main.cpp)
    
    target_include_directories(titan PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
    
    target_compile_options(titan PRIVATE
        ${TITAN_COMMON_FLAGS}
        $<$<CONFIG:Release>:${TITAN_RELEASE_FLAGS}>
        $<$<CONFIG:Debug>:${TITAN_DEBUG_FLAGS}>
    )
    
    target_link_libraries(titan PRIVATE android log)
    
    set_target_properties(titan PROPERTIES
        OUTPUT_NAME "titan"
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}
    )
endif()

# ==============================================================================
# Install Rules (für Deployment-Script)
# ==============================================================================

# Installiere SO in standardmäßiges Output-Verzeichnis
install(TARGETS titan_zygisk
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/zygisk/${ANDROID_ABI}
)

# ==============================================================================
# Custom Targets
# ==============================================================================

# Target zum Bauen von Dobby (optional)
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
message(STATUS "Project Titan - Native Module Configuration")
message(STATUS "===============================================")
message(STATUS "Build Type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "Android ABI:    ${ANDROID_ABI}")
message(STATUS "Android API:    ${ANDROID_NATIVE_API_LEVEL}")
message(STATUS "Stealth Mode:   ${TITAN_STEALTH_MODE}")
message(STATUS "Dobby:          ${DOBBY_AVAILABLE}")
message(STATUS "Output:         ${CMAKE_BINARY_DIR}/lib/${ANDROID_ABI}/")
message(STATUS "===============================================")
