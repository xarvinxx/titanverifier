/*
 * Project Titan - Zygisk Module (Phase 5.0 - Final Convergence)
 * 
 * Maximale Stabilitaet durch strikte App-Isolation.
 * Nur Ziel-Apps werden gehookt, niemals System-Prozesse.
 * 
 * Native Hooks via Dobby:
 * - __system_property_get: Serial, IMEI, GSF, Android ID
 * - getifaddrs: MAC-Adressen fuer wlan0 und eth0
 * 
 * Target: Google Pixel 6 Oriole, Android 14, KernelSU und Zygisk Next
 */

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <atomic>
#include <mutex>

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
    #define LOGD(...) ((void)0)
#else
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
    #define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
    #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif

// ==============================================================================
// Konfiguration - Phase 5.0
// ==============================================================================

#define TITAN_KILL_SWITCH       "/data/local/tmp/titan_stop"

// EINZIGE Bridge-Quelle (sicher waehrend Boot)
#define TITAN_BRIDGE_PATH       "/data/adb/modules/titan_verifier/titan_identity"

// Ziel-Apps (NIEMALS System-Prozesse!)
static const char* TARGET_APPS[] = {
    "com.titan.verifier",           // Unser Auditor
    "com.zhiliaoapp.musically",     // TikTok International
    "com.ss.android.ugc.trill",     // TikTok (andere Region)
    nullptr
};

// ==============================================================================
// Hardcoded Pixel 6 Defaults (Fail-Safe)
// ==============================================================================

static const char* DEFAULT_SERIAL = "28161FDF6006P8";
static const char* DEFAULT_IMEI1 = "352269111271008";
static const char* DEFAULT_IMEI2 = "358476312016587";
static const char* DEFAULT_ANDROID_ID = "d7f4b30e1b210a83";
static const char* DEFAULT_GSF_ID = "3a8c4f72d91e50b6";
static const char* DEFAULT_WIFI_MAC = "94:b9:7e:d3:a1:f4";
static const char* DEFAULT_WIDEVINE_ID = "a1b2c3d4e5f67890a1b2c3d4e5f67890";

// ==============================================================================
// Globaler State (Thread-Safe)
// ==============================================================================

using SystemPropertyGetFn = int (*)(const char* name, char* value);
using GetifaddrsFn = int (*)(struct ifaddrs** ifap);

static SystemPropertyGetFn g_origSystemPropertyGet = nullptr;
static GetifaddrsFn g_origGetifaddrs = nullptr;

static std::atomic<bool> g_propertyHookInstalled{false};
static std::atomic<bool> g_macHookInstalled{false};
static std::atomic<bool> g_bridgeLoaded{false};
static std::atomic<bool> g_killSwitchActive{false};
static std::atomic<bool> g_usingDefaults{false};

static std::mutex g_jniMutex;
static JNIEnv* g_cachedEnv = nullptr;

// ==============================================================================
// Kill-Switch Check (ERSTE Zeile in onLoad!)
// ==============================================================================

static bool checkKillSwitch() {
    struct stat st;
    if (stat(TITAN_KILL_SWITCH, &st) == 0) {
        g_killSwitchActive = true;
        return true;
    }
    return false;
}

// ==============================================================================
// Target App Check (Strikte Isolation)
// ==============================================================================

static bool isTargetApp(const char* packageName) {
    if (!packageName) return false;
    
    for (int i = 0; TARGET_APPS[i] != nullptr; i++) {
        if (strcmp(packageName, TARGET_APPS[i]) == 0) {
            return true;
        }
    }
    return false;
}

// ==============================================================================
// Bridge Loading mit Fail-Safe Defaults
// ==============================================================================

static void applyDefaults() {
    TitanHardware& hw = TitanHardware::getInstance();
    hw.setSerial(DEFAULT_SERIAL);
    hw.setBootSerial(DEFAULT_SERIAL);
    hw.setImei1(DEFAULT_IMEI1);
    hw.setImei2(DEFAULT_IMEI2);
    hw.setAndroidId(DEFAULT_ANDROID_ID);
    hw.setGsfId(DEFAULT_GSF_ID);
    hw.setWifiMac(DEFAULT_WIFI_MAC);
    hw.setWidevineId(DEFAULT_WIDEVINE_ID);
    g_usingDefaults = true;
    LOGI("[TITAN] Using hardcoded Pixel 6 defaults");
}

static bool loadBridgeFromFile(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    
    char buffer[2048] = {};
    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    
    if (bytesRead <= 0) return false;
    buffer[bytesRead] = '\0';
    
    TitanHardware& hw = TitanHardware::getInstance();
    bool foundAny = false;
    
    char* savePtr = nullptr;
    char* bufPtr = buffer;
    char* line;
    
    while ((line = strtok_r(bufPtr, "\n", &savePtr)) != nullptr) {
        bufPtr = nullptr;
        
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0' || *line == '#') continue;
        
        char* eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            char* key = line;
            char* value = eq + 1;
            
            while (*key == ' ') key++;
            char* kEnd = eq - 1;
            while (kEnd > key && *kEnd == ' ') *kEnd-- = '\0';
            while (*value == ' ') value++;
            
            if (strcmp(key, "serial") == 0) { hw.setSerial(value); foundAny = true; }
            else if (strcmp(key, "boot_serial") == 0) { hw.setBootSerial(value); foundAny = true; }
            else if (strcmp(key, "imei1") == 0 || strcmp(key, "imei") == 0) { hw.setImei1(value); foundAny = true; }
            else if (strcmp(key, "imei2") == 0) { hw.setImei2(value); foundAny = true; }
            else if (strcmp(key, "gsf_id") == 0 || strcmp(key, "gsfid") == 0) { hw.setGsfId(value); foundAny = true; }
            else if (strcmp(key, "android_id") == 0) { hw.setAndroidId(value); foundAny = true; }
            else if (strcmp(key, "wifi_mac") == 0 || strcmp(key, "mac_wlan0") == 0) { hw.setWifiMac(value); foundAny = true; }
            else if (strcmp(key, "widevine_id") == 0) { hw.setWidevineId(value); foundAny = true; }
            else if (strcmp(key, "imsi") == 0) { hw.setImsi(value); foundAny = true; }
            else if (strcmp(key, "sim_serial") == 0 || strcmp(key, "iccid") == 0) { hw.setSimSerial(value); foundAny = true; }
        }
    }
    
    return foundAny;
}

static void loadBridge() {
    if (g_bridgeLoaded.load()) return;
    
    if (loadBridgeFromFile(TITAN_BRIDGE_PATH)) {
        LOGI("[TITAN] Bridge loaded from: %s", TITAN_BRIDGE_PATH);
        g_bridgeLoaded = true;
        return;
    }
    
    // Fail-Safe: Hardcoded Defaults verwenden
    LOGW("[TITAN] Bridge not found, using defaults");
    applyDefaults();
    g_bridgeLoaded = true;
}

// ==============================================================================
// Hook: __system_property_get
// ==============================================================================

static int titan_hooked_system_property_get(const char* name, char* value) {
    if (!name || !value) {
        return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
    }
    
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofed[128] = {};
    
    // === Serial ===
    if (strcmp(name, "ro.serialno") == 0 || strcmp(name, "ro.boot.serialno") == 0) {
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            return (int)strlen(value);
        }
    }
    
    // === GSF ID ===
    if (strcmp(name, "ro.com.google.gservices.gsf.id") == 0 ||
        strcmp(name, "ro.gsf.id") == 0 || strcmp(name, "gsf.id") == 0) {
        hw.getGsfId(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            return (int)strlen(value);
        }
    }
    
    // === Android ID ===
    if (strcmp(name, "ro.build.android_id") == 0 || strcmp(name, "net.hostname") == 0) {
        hw.getAndroidId(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 63);
            value[63] = '\0';
            return (int)strlen(value);
        }
    }
    
    // === IMEI ===
    if (strcmp(name, "gsm.baseband.imei") == 0 || strcmp(name, "ro.ril.oem.imei") == 0 ||
        strcmp(name, "ril.IMEI") == 0 || strcmp(name, "gsm.imei") == 0) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            return (int)strlen(value);
        }
    }
    
    if (strstr(name, "imei1") != nullptr) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            return (int)strlen(value);
        }
    }
    
    if (strstr(name, "imei2") != nullptr) {
        hw.getImei2(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            return (int)strlen(value);
        }
    }
    
    // === WiFi MAC ===
    if (strcmp(name, "ro.boot.wifimacaddr") == 0 || strstr(name, "wlan.driver.macaddr") != nullptr) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 23);
            value[23] = '\0';
            return (int)strlen(value);
        }
    }
    
    return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
}

// ==============================================================================
// Hook: getifaddrs (MAC)
// ==============================================================================

static bool parseMacString(const char* macStr, unsigned char* out) {
    if (!macStr || !out) return false;
    int v[6];
    if (sscanf(macStr, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)v[i];
    return true;
}

static int titan_hooked_getifaddrs(struct ifaddrs** ifap) {
    if (!g_origGetifaddrs) return -1;
    
    int result = g_origGetifaddrs(ifap);
    if (result != 0 || !ifap || !*ifap) return result;
    
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofedMac[24] = {};
    hw.getWifiMac(spoofedMac, sizeof(spoofedMac));
    
    if (spoofedMac[0] == '\0') return result;
    
    unsigned char newMac[6];
    if (!parseMacString(spoofedMac, newMac)) return result;
    
    for (struct ifaddrs* ifa = *ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, "wlan0") != 0 && strcmp(ifa->ifa_name, "eth0") != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        
        struct sockaddr_ll* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen == 6) {
            memcpy(sll->sll_addr, newMac, 6);
        }
    }
    
    return result;
}

// ==============================================================================
// Hook Installation (Dobby)
// ==============================================================================

static bool installPropertyHook() {
    if (g_propertyHookInstalled.load()) return true;
    
    void* addr = nullptr;
#ifdef USE_DOBBY
    addr = DobbySymbolResolver("libc.so", "__system_property_get");
#endif
    if (!addr) {
        void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (libc) addr = dlsym(libc, "__system_property_get");
    }
    
    if (!addr) return false;
    
#ifdef USE_DOBBY
    int ret = DobbyHook(addr,
        reinterpret_cast<dobby_dummy_func_t>(titan_hooked_system_property_get),
        reinterpret_cast<dobby_dummy_func_t*>(&g_origSystemPropertyGet));
    
    if (ret == 0) {
        g_propertyHookInstalled = true;
        LOGI("[TITAN] Property hook OK");
        return true;
    }
#endif
    return false;
}

static bool installMacHook() {
    if (g_macHookInstalled.load()) return true;
    
    void* addr = nullptr;
#ifdef USE_DOBBY
    addr = DobbySymbolResolver("libc.so", "getifaddrs");
#endif
    if (!addr) {
        void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (libc) addr = dlsym(libc, "getifaddrs");
    }
    
    if (!addr) return false;
    
#ifdef USE_DOBBY
    int ret = DobbyHook(addr,
        reinterpret_cast<dobby_dummy_func_t>(titan_hooked_getifaddrs),
        reinterpret_cast<dobby_dummy_func_t*>(&g_origGetifaddrs));
    
    if (ret == 0) {
        g_macHookInstalled = true;
        LOGI("[TITAN] MAC hook OK");
        return true;
    }
#endif
    return false;
}

// ==============================================================================
// Titan Zygisk Module Class
// ==============================================================================

class TitanModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        m_api = api;
        m_env = env;
        
        // ERSTE ZEILE: Kill-Switch Check!
        if (checkKillSwitch()) {
            LOGW("[TITAN] Kill-switch active, all hooks disabled");
            return;
        }
        
        LOGI("[TITAN] Module loaded (Phase 5.0 - Final Convergence)");
        
        // Bridge laden (mit Fail-Safe)
        loadBridge();
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (g_killSwitchActive.load()) {
            if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        
        m_packageName[0] = '\0';
        if (m_env && args->nice_name) {
            const char* pkg = m_env->GetStringUTFChars(args->nice_name, nullptr);
            if (pkg) {
                strncpy(m_packageName, pkg, sizeof(m_packageName) - 1);
                m_env->ReleaseStringUTFChars(args->nice_name, pkg);
            }
        }
        
        // STRIKTE ISOLATION: Nur Ziel-Apps!
        if (!isTargetApp(m_packageName)) {
            if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            m_shouldInject = false;
        } else {
            m_shouldInject = true;
            LOGI("[TITAN] Target: %s", m_packageName);
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        (void)args;
        if (!m_shouldInject) return;
        if (g_killSwitchActive.load()) return;
        
        LOGI("[TITAN] Injecting (Phase 5.0)");
        
        bool propOk = installPropertyHook();
        bool macOk = installMacHook();
        
        LOGI("[TITAN] Hooks: prop=%d mac=%d defaults=%d", 
             propOk, macOk, g_usingDefaults.load());
    }
    
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        // NIEMALS System Server hooken!
        if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
    
    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        (void)args;
    }
    
private:
    zygisk::Api* m_api = nullptr;
    JNIEnv* m_env = nullptr;
    char m_packageName[256] = {};
    bool m_shouldInject = false;
};

// ==============================================================================
// Registrierung
// ==============================================================================

REGISTER_ZYGISK_MODULE(TitanModule)

static void companionHandler(int fd) {
    loadBridge();
    TitanHardware& hw = TitanHardware::getInstance();
    char serial[96] = {};
    hw.getSerial(serial, sizeof(serial));
    uint32_t len = (uint32_t)strlen(serial);
    write(fd, &len, sizeof(len));
    if (len > 0) write(fd, serial, len);
    close(fd);
}

REGISTER_ZYGISK_COMPANION(companionHandler)
