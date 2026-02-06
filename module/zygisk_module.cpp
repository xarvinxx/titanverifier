/**
 * Project Titan - Zygisk Module (Phase 3.4 - Fixed)
 * 
 * Zygisk API v4 kompatibles Modul für Hardware-Identity-Spoofing.
 * Verwendet die offizielle Magisk Zygisk API.
 * 
 * Features:
 * - Dobby Inline-Hooks für __system_property_get
 * - Bridge-basiertes State-Management mit Fallback-Pfaden
 * - Kill-Switch für sichere Deaktivierung
 * 
 * Target: Google Pixel 6 (Oriole), Android 14, KernelSU + Zygisk Next
 */

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <atomic>

#include "../include/zygisk.hpp"
#include "../include/dobby.h"
#include "../common/titan_hardware.h"

// ==============================================================================
// Logging
// ==============================================================================

#define LOG_TAG "TitanZygisk"

#ifdef TITAN_STEALTH
    #define LOGI(...) ((void)0)
    #define LOGW(...) ((void)0)
    #define LOGE(...) ((void)0)
#else
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
    #define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

// ==============================================================================
// Konfiguration
// ==============================================================================

// Kill-Switch Pfad - wenn diese Datei existiert, werden keine Hooks installiert
#define TITAN_KILL_SWITCH "/data/local/tmp/titan_stop"

// Bridge-Pfade (primär und fallback)
#define TITAN_BRIDGE_PRIMARY   "/data/local/tmp/.titan_state"
#define TITAN_BRIDGE_FALLBACK  "/data/adb/modules/titan_verifier/titan_state"

// Ziel-Package für Hooks
static const char* TARGET_PACKAGE = "com.titan.verifier";

// ==============================================================================
// Globaler State
// ==============================================================================

// Original-Funktion (Trampolin)
using SystemPropertyGetFn = int (*)(const char* name, char* value);
static SystemPropertyGetFn g_origSystemPropertyGet = nullptr;

// State-Flags
static std::atomic<bool> g_hookInstalled{false};
static std::atomic<bool> g_bridgeLoaded{false};
static std::atomic<bool> g_killSwitchActive{false};

// ==============================================================================
// Kill-Switch Check
// ==============================================================================

static bool checkKillSwitch() {
    struct stat st;
    if (stat(TITAN_KILL_SWITCH, &st) == 0) {
        LOGW("[TITAN] Kill-switch detected at %s, hooks disabled", TITAN_KILL_SWITCH);
        g_killSwitchActive = true;
        return true;
    }
    return false;
}

// ==============================================================================
// Bridge Loading (mit Fallback)
// ==============================================================================

static bool loadBridgeFromFile(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    char buffer[512] = {};
    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    
    if (bytesRead <= 0) {
        return false;
    }
    buffer[bytesRead] = '\0';
    
    // Parse: serial\nimei\nboot_serial\ngsfid
    TitanHardware& hw = TitanHardware::getInstance();
    
    char* savePtr = nullptr;
    char* bufPtr = buffer;
    int lineNum = 0;
    char* line;
    
    while ((line = strtok_r(bufPtr, "\n", &savePtr)) != nullptr && lineNum < 4) {
        bufPtr = nullptr;
        
        // Trim trailing whitespace
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\r' || line[len-1] == ' ')) {
            line[--len] = '\0';
        }
        
        switch (lineNum) {
            case 0: hw.setSerial(line); break;
            case 1: hw.setImei(line); break;
            case 2: hw.setBootSerial(line); break;
            case 3: hw.setGsfId(line); break;
        }
        lineNum++;
    }
    
    return (lineNum >= 1);  // Mindestens Serial muss vorhanden sein
}

static bool loadBridge() {
    if (g_bridgeLoaded.load()) {
        return true;
    }
    
    // Versuche primären Pfad
    if (loadBridgeFromFile(TITAN_BRIDGE_PRIMARY)) {
        LOGI("[TITAN] Bridge loaded from primary: %s", TITAN_BRIDGE_PRIMARY);
        g_bridgeLoaded = true;
        return true;
    }
    
    // Fallback-Pfad versuchen
    if (loadBridgeFromFile(TITAN_BRIDGE_FALLBACK)) {
        LOGI("[TITAN] Bridge loaded from fallback: %s", TITAN_BRIDGE_FALLBACK);
        g_bridgeLoaded = true;
        return true;
    }
    
    LOGE("[TITAN] Failed to load bridge from any path!");
    return false;
}

// ==============================================================================
// Hook Handler: __system_property_get
// ==============================================================================

static int titan_hooked_system_property_get(const char* name, char* value) {
    // Null-Guard
    if (name == nullptr || value == nullptr) {
        if (g_origSystemPropertyGet) {
            return g_origSystemPropertyGet(name, value);
        }
        return 0;
    }
    
    // Bridge-Daten laden (falls noch nicht geschehen)
    if (!g_bridgeLoaded.load()) {
        loadBridge();
    }
    
    TitanHardware& hw = TitanHardware::getInstance();
    
    // ro.serialno Hook
    if (strcmp(name, "ro.serialno") == 0) {
        char spoofed[96] = {};
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            LOGI("[TITAN] Spoofed ro.serialno -> %s", spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // ro.boot.serialno Hook
    if (strcmp(name, "ro.boot.serialno") == 0) {
        char spoofed[96] = {};
        hw.getBootSerial(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            LOGI("[TITAN] Spoofed ro.boot.serialno -> %s", spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // Fallback: Original aufrufen
    if (g_origSystemPropertyGet) {
        return g_origSystemPropertyGet(name, value);
    }
    return 0;
}

// ==============================================================================
// Hook Installation via Dobby
// ==============================================================================

static bool installPropertyHook() {
    if (g_hookInstalled.load()) {
        LOGI("[TITAN] Hooks already installed, skipping");
        return true;
    }
    
    // Symbol auflösen
    void* targetAddr = nullptr;
    
    // Methode 1: Dobby Symbol Resolver
#ifdef USE_DOBBY
    targetAddr = DobbySymbolResolver("libc.so", "__system_property_get");
#endif
    
    // Methode 2: Fallback via dlsym
    if (!targetAddr) {
        void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (libc) {
            targetAddr = dlsym(libc, "__system_property_get");
        }
    }
    
    if (!targetAddr) {
        LOGE("[TITAN] Failed to resolve __system_property_get");
        return false;
    }
    
    LOGI("[TITAN] Found __system_property_get at %p", targetAddr);
    
#ifdef USE_DOBBY
    // Installiere Inline-Hook via Dobby
    int result = DobbyHook(
        targetAddr,
        reinterpret_cast<dobby_dummy_func_t>(titan_hooked_system_property_get),
        reinterpret_cast<dobby_dummy_func_t*>(&g_origSystemPropertyGet)
    );
    
    if (result == 0) {  // RT_SUCCESS = 0
        g_hookInstalled = true;
        LOGI("[TITAN] Dobby inline hook installed successfully");
        LOGI("[TITAN] Original trampoline at %p", reinterpret_cast<void*>(g_origSystemPropertyGet));
        return true;
    } else {
        LOGE("[TITAN] DobbyHook failed with code %d", result);
        return false;
    }
#else
    LOGW("[TITAN] Dobby not available, hooks disabled");
    return false;
#endif
}

// ==============================================================================
// Titan Zygisk Module Class
// ==============================================================================

class TitanModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        m_api = api;
        m_env = env;
        
        LOGI("[TITAN] Module loaded (API v%d)", ZYGISK_API_VERSION);
        
        // Kill-Switch Check
        if (checkKillSwitch()) {
            LOGW("[TITAN] Kill-switch active, module will not hook anything");
            return;
        }
        
        // Pre-load Bridge-Daten (im Zygote-Kontext haben wir mehr Rechte)
        if (loadBridge()) {
            LOGI("[TITAN] Bridge pre-loaded in onLoad");
        } else {
            LOGW("[TITAN] Bridge not available in onLoad, will retry later");
        }
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (g_killSwitchActive.load()) {
            // Kill-Switch aktiv: Modul entladen
            if (m_api) {
                m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            }
            return;
        }
        
        // Package-Name extrahieren (args->nice_name ist eine Referenz auf jstring)
        m_packageName.clear();
        if (m_env && args->nice_name) {
            const char* pkgName = m_env->GetStringUTFChars(args->nice_name, nullptr);
            if (pkgName) {
                m_packageName = pkgName;
                m_env->ReleaseStringUTFChars(args->nice_name, pkgName);
            }
        }
        
        // Entscheide ob wir für diese App aktiv werden
        if (m_packageName != TARGET_PACKAGE) {
            // Nicht-Ziel-App: Modul entladen (Stealth)
            LOGI("[TITAN] Not target package (%s), unloading", m_packageName.c_str());
            if (m_api) {
                m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            }
            m_shouldInject = false;
        } else {
            m_shouldInject = true;
            LOGI("[TITAN] Target package detected: %s", m_packageName.c_str());
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        (void)args;
        
        if (!m_shouldInject) {
            return;
        }
        
        if (g_killSwitchActive.load()) {
            LOGW("[TITAN] Kill-switch active, skipping hooks");
            return;
        }
        
        LOGI("[TITAN] Injecting into %s", m_packageName.c_str());
        
        // Bridge-Daten laden (falls noch nicht geschehen)
        if (!g_bridgeLoaded.load()) {
            if (!loadBridge()) {
                LOGE("[TITAN] Bridge still not available!");
            }
        }
        
        // Hooks installieren
        if (!installPropertyHook()) {
            LOGE("[TITAN] Failed to install property hooks!");
        } else {
            LOGI("[TITAN] Property hooks installed successfully");
        }
    }
    
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        
        // System Server: Modul immer entladen
        LOGI("[TITAN] System server fork, unloading module");
        if (m_api) {
            m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }
    
    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        // Nichts zu tun
    }
    
private:
    zygisk::Api* m_api = nullptr;
    JNIEnv* m_env = nullptr;
    std::string m_packageName;
    bool m_shouldInject = false;
};

// ==============================================================================
// Modul-Registrierung (offizielle Magisk API)
// ==============================================================================

REGISTER_ZYGISK_MODULE(TitanModule)

// ==============================================================================
// Companion Handler (für Root-Operationen)
// ==============================================================================

static void companionHandler(int clientFd) {
    LOGI("[TITAN] Companion handler invoked (fd=%d)", clientFd);
    
    // Bridge-Daten laden und an Client senden
    TitanHardware& hw = TitanHardware::getInstance();
    
    // Versuche beide Pfade
    bool loaded = loadBridgeFromFile(TITAN_BRIDGE_PRIMARY) || 
                  loadBridgeFromFile(TITAN_BRIDGE_FALLBACK);
    
    if (loaded) {
        char serial[96] = {};
        hw.getSerial(serial, sizeof(serial));
        
        // Sende Länge + Daten
        uint32_t len = static_cast<uint32_t>(strlen(serial));
        write(clientFd, &len, sizeof(len));
        write(clientFd, serial, len);
        
        LOGI("[TITAN] Companion sent serial: %s", serial);
    } else {
        // Leere Antwort
        uint32_t len = 0;
        write(clientFd, &len, sizeof(len));
        LOGW("[TITAN] Companion: Bridge not loaded");
    }
    
    close(clientFd);
}

REGISTER_ZYGISK_COMPANION(companionHandler)
