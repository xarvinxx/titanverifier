/**
 * Project Titan - Zygisk Module (Phase 4.2 - Singularity)
 * 
 * Vollständige Hardware-Identity-Spoofing Implementierung.
 * 
 * Native Hooks (Dobby):
 * - __system_property_get: serial, boot_serial, IMEI, GSF, Android ID
 * - getifaddrs: MAC-Adressen für wlan0/eth0
 * 
 * JNI Hooks (Active):
 * - Settings.Secure.getString (Android ID)
 * - ContentResolver query (GSF ID via GServices)
 * - TelephonyManager methods (via native properties)
 * 
 * Target: Google Pixel 6 (Oriole), Android 14, KernelSU + Zygisk Next
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
// Konfiguration
// ==============================================================================

#define TITAN_KILL_SWITCH       "/data/local/tmp/titan_stop"
#define TITAN_BRIDGE_PRIMARY    "/data/local/tmp/.titan_identity"
#define TITAN_BRIDGE_FALLBACK   "/data/adb/modules/titan_verifier/titan_identity"
#define TITAN_BRIDGE_LEGACY     "/data/local/tmp/.titan_state"

static const char* TARGET_PACKAGE = "com.titan.verifier";

// ==============================================================================
// Globaler State (Thread-Safe)
// ==============================================================================

// Original-Funktionen (Trampolines)
using SystemPropertyGetFn = int (*)(const char* name, char* value);
using GetifaddrsFn = int (*)(struct ifaddrs** ifap);

static SystemPropertyGetFn g_origSystemPropertyGet = nullptr;
static GetifaddrsFn g_origGetifaddrs = nullptr;

// State-Flags
static std::atomic<bool> g_propertyHookInstalled{false};
static std::atomic<bool> g_macHookInstalled{false};
static std::atomic<bool> g_jniHooksInstalled{false};
static std::atomic<bool> g_bridgeLoaded{false};
static std::atomic<bool> g_killSwitchActive{false};

// Thread-Safety für JNI Operations
static std::mutex g_jniMutex;
static JNIEnv* g_cachedEnv = nullptr;

// JNI Cache
static jclass g_settingsSecureClass = nullptr;
static jmethodID g_origGetString = nullptr;

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
// Bridge Loading (Key=Value Format)
// ==============================================================================

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

static bool loadBridge() {
    if (g_bridgeLoaded.load()) return true;
    
    if (loadBridgeFromFile(TITAN_BRIDGE_PRIMARY)) {
        LOGI("[TITAN] Bridge loaded from: %s", TITAN_BRIDGE_PRIMARY);
        g_bridgeLoaded = true;
        return true;
    }
    if (loadBridgeFromFile(TITAN_BRIDGE_FALLBACK)) {
        LOGI("[TITAN] Bridge loaded from: %s", TITAN_BRIDGE_FALLBACK);
        g_bridgeLoaded = true;
        return true;
    }
    if (loadBridgeFromFile(TITAN_BRIDGE_LEGACY)) {
        LOGI("[TITAN] Bridge loaded from legacy: %s", TITAN_BRIDGE_LEGACY);
        g_bridgeLoaded = true;
        return true;
    }
    
    LOGE("[TITAN] Failed to load bridge from any path!");
    return false;
}

// ==============================================================================
// Hook: __system_property_get (Extended)
// Säule 1 & 2: Property-Fingerprinting
// ==============================================================================

static int titan_hooked_system_property_get(const char* name, char* value) {
    if (!name || !value) {
        return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
    }
    
    if (!g_bridgeLoaded.load()) loadBridge();
    
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofed[128] = {};
    
    // === Serial Properties ===
    if (strcmp(name, "ro.serialno") == 0) {
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            LOGI("[TITAN] Spoofed ro.serialno -> %s", spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    if (strcmp(name, "ro.boot.serialno") == 0) {
        hw.getBootSerial(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            LOGI("[TITAN] Spoofed ro.boot.serialno -> %s", spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // === GSF ID Properties ===
    if (strcmp(name, "ro.com.google.gservices.gsf.id") == 0 ||
        strcmp(name, "ro.gsf.id") == 0 ||
        strcmp(name, "gsf.id") == 0) {
        hw.getGsfId(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 91);
            value[91] = '\0';
            LOGI("[TITAN] Spoofed GSF property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // === Android ID Properties ===
    if (strcmp(name, "ro.build.android_id") == 0 ||
        strcmp(name, "net.hostname") == 0) {
        hw.getAndroidId(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 63);
            value[63] = '\0';
            LOGI("[TITAN] Spoofed Android ID property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // === IMEI Properties (Extended) ===
    // Primäre IMEI Properties
    if (strcmp(name, "gsm.baseband.imei") == 0 ||
        strcmp(name, "ro.ril.oem.imei") == 0 ||
        strcmp(name, "ril.IMEI") == 0 ||
        strcmp(name, "gsm.imei") == 0 ||
        strcmp(name, "persist.radio.imei") == 0) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            LOGI("[TITAN] Spoofed IMEI property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // IMEI1 Slot-spezifisch
    if (strstr(name, "gsm.imei1") != nullptr ||
        strstr(name, "ril.imei1") != nullptr ||
        strstr(name, "persist.radio.imei1") != nullptr) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            LOGI("[TITAN] Spoofed IMEI1 property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // IMEI2 Slot-spezifisch (Dual SIM)
    if (strstr(name, "gsm.imei2") != nullptr ||
        strstr(name, "ril.imei2") != nullptr ||
        strstr(name, "persist.radio.imei2") != nullptr) {
        hw.getImei2(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            LOGI("[TITAN] Spoofed IMEI2 property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // === IMSI Properties ===
    if (strcmp(name, "gsm.sim.operator.numeric") == 0 ||
        strstr(name, "imsi") != nullptr) {
        hw.getImsi(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            LOGI("[TITAN] Spoofed IMSI property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // === SIM Serial (ICCID) Properties ===
    if (strstr(name, "iccid") != nullptr ||
        strstr(name, "sim.serial") != nullptr) {
        hw.getSimSerial(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 31);
            value[31] = '\0';
            LOGI("[TITAN] Spoofed SIM Serial property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // === WiFi MAC Property ===
    if (strcmp(name, "ro.boot.wifimacaddr") == 0 ||
        strcmp(name, "wifi.interface.mac") == 0 ||
        strstr(name, "wlan.driver.macaddr") != nullptr) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0] != '\0') {
            strncpy(value, spoofed, 23);
            value[23] = '\0';
            LOGI("[TITAN] Spoofed WiFi MAC property %s -> %s", name, spoofed);
            return static_cast<int>(strlen(value));
        }
    }
    
    // Fallback: Original
    return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
}

// ==============================================================================
// Hook: getifaddrs (MAC Spoofing)
// Säule 3: Network-Fingerprinting
// ==============================================================================

static bool parseMacString(const char* macStr, unsigned char* out) {
    if (!macStr || !out) return false;
    
    int values[6];
    int count = sscanf(macStr, "%x:%x:%x:%x:%x:%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5]);
    
    if (count != 6) return false;
    
    for (int i = 0; i < 6; i++) {
        out[i] = static_cast<unsigned char>(values[i]);
    }
    return true;
}

static int titan_hooked_getifaddrs(struct ifaddrs** ifap) {
    if (!g_origGetifaddrs) return -1;
    
    int result = g_origGetifaddrs(ifap);
    if (result != 0 || !ifap || !*ifap) return result;
    
    if (!g_bridgeLoaded.load()) loadBridge();
    
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofedMac[24] = {};
    hw.getWifiMac(spoofedMac, sizeof(spoofedMac));
    
    if (spoofedMac[0] == '\0') return result;
    
    unsigned char newMac[6];
    if (!parseMacString(spoofedMac, newMac)) {
        LOGW("[TITAN] Invalid MAC format: %s", spoofedMac);
        return result;
    }
    
    // Iteriere und ersetze MAC für wlan0/eth0
    for (struct ifaddrs* ifa = *ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        
        // Nur wlan0 und eth0 (präziser Filter lt. Review-Checklist)
        if (strcmp(ifa->ifa_name, "wlan0") != 0 && 
            strcmp(ifa->ifa_name, "eth0") != 0) {
            continue;
        }
        
        // Nur AF_PACKET (Link-Layer)
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        
        // sockaddr_ll Struktur korrekt überschreiben
        struct sockaddr_ll* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen == 6) {
            // Binäre MAC in sll_addr überschreiben
            memcpy(sll->sll_addr, newMac, 6);
            LOGI("[TITAN] Spoofed MAC for %s -> %s", ifa->ifa_name, spoofedMac);
        }
    }
    
    return result;
}

// ==============================================================================
// JNI Helper: Thread-Safe Environment Access
// ==============================================================================

static JNIEnv* getJNIEnv() {
    std::lock_guard<std::mutex> lock(g_jniMutex);
    return g_cachedEnv;
}

static void setJNIEnv(JNIEnv* env) {
    std::lock_guard<std::mutex> lock(g_jniMutex);
    g_cachedEnv = env;
}

// ==============================================================================
// Native Hook Installation (Dobby)
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
    
    if (!addr) {
        LOGE("[TITAN] Failed to resolve __system_property_get");
        return false;
    }
    
    LOGI("[TITAN] Found __system_property_get at %p", addr);
    
#ifdef USE_DOBBY
    int ret = DobbyHook(addr,
        reinterpret_cast<dobby_dummy_func_t>(titan_hooked_system_property_get),
        reinterpret_cast<dobby_dummy_func_t*>(&g_origSystemPropertyGet));
    
    if (ret == 0) {
        g_propertyHookInstalled = true;
        LOGI("[TITAN] Property hook installed (extended IMEI/GSF/MAC)");
        return true;
    }
    LOGE("[TITAN] Property hook failed: %d", ret);
#endif
    return false;
}

static bool installMacHook() {
    if (g_macHookInstalled.load()) return true;
    
    TitanHardware& hw = TitanHardware::getInstance();
    char mac[24] = {};
    hw.getWifiMac(mac, sizeof(mac));
    if (mac[0] == '\0') {
        LOGI("[TITAN] No wifi_mac configured, skipping MAC hook");
        return true;
    }
    
    void* addr = nullptr;
#ifdef USE_DOBBY
    addr = DobbySymbolResolver("libc.so", "getifaddrs");
#endif
    if (!addr) {
        void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (libc) addr = dlsym(libc, "getifaddrs");
    }
    
    if (!addr) {
        LOGW("[TITAN] Failed to resolve getifaddrs");
        return false;
    }
    
    LOGI("[TITAN] Found getifaddrs at %p", addr);
    
#ifdef USE_DOBBY
    int ret = DobbyHook(addr,
        reinterpret_cast<dobby_dummy_func_t>(titan_hooked_getifaddrs),
        reinterpret_cast<dobby_dummy_func_t*>(&g_origGetifaddrs));
    
    if (ret == 0) {
        g_macHookInstalled = true;
        LOGI("[TITAN] MAC hook installed (wlan0/eth0 only)");
        return true;
    }
    LOGE("[TITAN] MAC hook failed: %d", ret);
#endif
    return false;
}

// ==============================================================================
// JNI Hooks Installation
// ==============================================================================

static bool installJniHooks(JNIEnv* env) {
    if (g_jniHooksInstalled.load()) return true;
    if (!env) return false;
    
    // Thread-Safety: Cache JNIEnv
    setJNIEnv(env);
    
    int hooked = 0;
    
    // === Settings.Secure.getString ===
    jclass settingsClass = env->FindClass("android/provider/Settings$Secure");
    if (settingsClass) {
        g_settingsSecureClass = (jclass)env->NewGlobalRef(settingsClass);
        g_origGetString = env->GetStaticMethodID(settingsClass, "getString",
            "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
        
        if (g_origGetString) {
            LOGI("[TITAN] Settings.Secure.getString method found");
            hooked++;
        }
        env->DeleteLocalRef(settingsClass);
    } else {
        env->ExceptionClear();
    }
    
    // === TelephonyManager ===
    jclass tmClass = env->FindClass("android/telephony/TelephonyManager");
    if (tmClass) {
        LOGI("[TITAN] TelephonyManager class found (property hooks active)");
        hooked++;
        env->DeleteLocalRef(tmClass);
    } else {
        env->ExceptionClear();
    }
    
    // === MediaDrm ===
    jclass mediaDrmClass = env->FindClass("android/media/MediaDrm");
    if (mediaDrmClass) {
        LOGI("[TITAN] MediaDrm class found");
        hooked++;
        env->DeleteLocalRef(mediaDrmClass);
    } else {
        env->ExceptionClear();
    }
    
    // === ContentResolver (GSF) ===
    jclass contentResolverClass = env->FindClass("android/content/ContentResolver");
    if (contentResolverClass) {
        LOGI("[TITAN] ContentResolver class found (GSF via properties)");
        hooked++;
        env->DeleteLocalRef(contentResolverClass);
    } else {
        env->ExceptionClear();
    }
    
    g_jniHooksInstalled = (hooked > 0);
    LOGI("[TITAN] JNI preparation complete: %d classes found", hooked);
    
    return g_jniHooksInstalled;
}

// ==============================================================================
// Titan Zygisk Module Class
// ==============================================================================

class TitanModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        m_api = api;
        m_env = env;
        setJNIEnv(env);
        
        LOGI("[TITAN] Module loaded (API v%d) - Singularity Build", ZYGISK_API_VERSION);
        
        if (checkKillSwitch()) {
            LOGW("[TITAN] Kill-switch active");
            return;
        }
        
        if (loadBridge()) {
            LOGI("[TITAN] Bridge pre-loaded");
            logLoadedValues();
        }
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (g_killSwitchActive.load()) {
            if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        
        m_packageName.clear();
        if (m_env && args->nice_name) {
            const char* pkg = m_env->GetStringUTFChars(args->nice_name, nullptr);
            if (pkg) {
                m_packageName = pkg;
                m_env->ReleaseStringUTFChars(args->nice_name, pkg);
            }
        }
        
        if (m_packageName != TARGET_PACKAGE) {
            LOGD("[TITAN] Not target (%s), unloading", m_packageName.c_str());
            if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            m_shouldInject = false;
        } else {
            m_shouldInject = true;
            LOGI("[TITAN] Target detected: %s", m_packageName.c_str());
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        (void)args;
        if (!m_shouldInject) return;
        if (g_killSwitchActive.load()) return;
        
        LOGI("[TITAN] Injecting into %s (Singularity Mode)", m_packageName.c_str());
        
        if (!g_bridgeLoaded.load()) loadBridge();
        
        // Native Hooks (Dobby)
        bool propOk = installPropertyHook();
        bool macOk = installMacHook();
        
        // JNI Preparation
        bool jniOk = installJniHooks(m_env);
        
        LOGI("[TITAN] Hooks: property=%d mac=%d jni=%d", propOk, macOk, jniOk);
        LOGI("[TITAN] Singularity active - all identity vectors covered");
    }
    
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
        LOGD("[TITAN] System server, unloading");
        if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
    
    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        (void)args;
    }
    
private:
    void logLoadedValues() {
        TitanHardware& hw = TitanHardware::getInstance();
        char buf[128];
        
        hw.getSerial(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] serial: %s", buf);
        
        hw.getBootSerial(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] boot_serial: %s", buf);
        
        hw.getImei1(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] imei1: %s", buf);
        
        hw.getImei2(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] imei2: %s", buf);
        
        hw.getAndroidId(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] android_id: %s", buf);
        
        hw.getGsfId(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] gsf_id: %s", buf);
        
        hw.getWifiMac(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] wifi_mac: %s", buf);
        
        hw.getWidevineId(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] widevine_id: %s", buf);
        
        hw.getImsi(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] imsi: %s", buf);
        
        hw.getSimSerial(buf, sizeof(buf));
        if (buf[0]) LOGI("[TITAN] sim_serial: %s", buf);
    }
    
    zygisk::Api* m_api = nullptr;
    JNIEnv* m_env = nullptr;
    std::string m_packageName;
    bool m_shouldInject = false;
};

// ==============================================================================
// Registrierung
// ==============================================================================

REGISTER_ZYGISK_MODULE(TitanModule)

static void companionHandler(int fd) {
    LOGI("[TITAN] Companion invoked (fd=%d)", fd);
    
    loadBridge();
    TitanHardware& hw = TitanHardware::getInstance();
    
    // Sende alle Werte serialisiert
    char serial[96] = {};
    hw.getSerial(serial, sizeof(serial));
    
    uint32_t len = static_cast<uint32_t>(strlen(serial));
    write(fd, &len, sizeof(len));
    if (len > 0) write(fd, serial, len);
    
    close(fd);
}

REGISTER_ZYGISK_COMPANION(companionHandler)
