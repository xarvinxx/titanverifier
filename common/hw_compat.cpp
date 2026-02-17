/**
 * HwCompat Singleton Implementation
 * Reads hardware identifiers from bridge config file (Key=Value format).
 */
#include "hw_compat.h"
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

// String obfuscation
#define _XK 0x5A

static inline void _hw_xdec(char* out, const unsigned char* enc, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = (char)(enc[i] ^ _XK);
    out[len] = '\0';
}

// "/data/adb/modules/hw_overlay/.hw_config" (len=39)
static const unsigned char _ENC_HW_PRIMARY[] = {
    0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x3b,0x3e,0x38,0x75,0x37,0x35,
    0x3e,0x2f,0x36,0x3f,0x29,0x75,0x32,0x2d,0x05,0x35,0x2c,0x3f,
    0x28,0x36,0x3b,0x23,0x75,0x74,0x32,0x2d,0x05,0x39,0x35,0x34,
    0x3c,0x33,0x3d
};
// "/sdcard/.hw_config" (len=18)
static const unsigned char _ENC_HW_FALLBACK[] = {
    0x75,0x29,0x3e,0x39,0x3b,0x28,0x3e,0x75,0x74,0x32,0x2d,0x05,
    0x39,0x35,0x34,0x3c,0x33,0x3d
};
// "/data/local/tmp/.hw_config" (len=26)
static const unsigned char _ENC_HW_LEGACY[] = {
    0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x36,0x35,0x39,0x3b,0x36,0x75,
    0x2e,0x37,0x2a,0x75,0x74,0x32,0x2d,0x05,0x39,0x35,0x34,0x3c,
    0x33,0x3d
};

static char g_hwPath[48] = {};
static char g_hwFallback[24] = {};
static char g_hwLegacy[32] = {};
static bool g_hwPathsDecoded = false;

static void _decodeBridgePaths() {
    if (g_hwPathsDecoded) return;
    _hw_xdec(g_hwPath,     _ENC_HW_PRIMARY,  39);
    _hw_xdec(g_hwFallback, _ENC_HW_FALLBACK, 18);
    _hw_xdec(g_hwLegacy,   _ENC_HW_LEGACY,   26);
    g_hwPathsDecoded = true;
}

const char* HW_BRIDGE_PATH_DEC     = nullptr;
const char* HW_BRIDGE_FALLBACK_DEC = nullptr;
const char* HW_BRIDGE_LEGACY_DEC   = nullptr;

__attribute__((constructor))
static void _initBridgePaths() {
    _decodeBridgePaths();
    HW_BRIDGE_PATH_DEC     = g_hwPath;
    HW_BRIDGE_FALLBACK_DEC = g_hwFallback;
    HW_BRIDGE_LEGACY_DEC   = g_hwLegacy;
}

// Raw Syscall Wrappers
static inline int _hw_raw_openat(const char* path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}
static inline ssize_t _hw_raw_read(int fd, void* buf, size_t count) {
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}
static inline int _hw_raw_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

// ============================================================================
// HwCompat Singleton Implementation
// ============================================================================

HwCompat::HwCompat() {
    std::memset(m_serial, 0, sizeof(m_serial));
    std::memset(m_bootSerial, 0, sizeof(m_bootSerial));
    std::memset(m_imei1, 0, sizeof(m_imei1));
    std::memset(m_imei2, 0, sizeof(m_imei2));
    std::memset(m_gsfId, 0, sizeof(m_gsfId));
    std::memset(m_androidId, 0, sizeof(m_androidId));
    std::memset(m_wifiMac, 0, sizeof(m_wifiMac));
    std::memset(m_widevineId, 0, sizeof(m_widevineId));
    std::memset(m_imsi, 0, sizeof(m_imsi));
    std::memset(m_simSerial, 0, sizeof(m_simSerial));
}

HwCompat& HwCompat::getInstance() {
    static HwCompat instance;
    return instance;
}

void HwCompat::safeCopy(char* dest, size_t destSize, const char* src) {
    if (!dest || destSize == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    std::strncpy(dest, src, destSize - 1);
    dest[destSize - 1] = '\0';
    
    size_t len = std::strlen(dest);
    while (len > 0 && (dest[len - 1] == '\n' || dest[len - 1] == '\r' || 
                       dest[len - 1] == ' ' || dest[len - 1] == '\t')) {
        dest[--len] = '\0';
    }
}

bool HwCompat::parseKeyValue(const char* key, const char* value) {
    if (!key || !value) return false;
    
    if (std::strcmp(key, "serial") == 0) {
        safeCopy(m_serial, sizeof(m_serial), value);
        return true;
    }
    if (std::strcmp(key, "boot_serial") == 0) {
        safeCopy(m_bootSerial, sizeof(m_bootSerial), value);
        return true;
    }
    if (std::strcmp(key, "imei1") == 0 || std::strcmp(key, "imei") == 0) {
        safeCopy(m_imei1, sizeof(m_imei1), value);
        return true;
    }
    if (std::strcmp(key, "imei2") == 0) {
        safeCopy(m_imei2, sizeof(m_imei2), value);
        return true;
    }
    if (std::strcmp(key, "gsf_id") == 0 || std::strcmp(key, "gsfid") == 0) {
        safeCopy(m_gsfId, sizeof(m_gsfId), value);
        return true;
    }
    if (std::strcmp(key, "android_id") == 0) {
        safeCopy(m_androidId, sizeof(m_androidId), value);
        return true;
    }
    if (std::strcmp(key, "wifi_mac") == 0 || std::strcmp(key, "mac_wlan0") == 0) {
        safeCopy(m_wifiMac, sizeof(m_wifiMac), value);
        return true;
    }
    if (std::strcmp(key, "widevine_id") == 0) {
        safeCopy(m_widevineId, sizeof(m_widevineId), value);
        return true;
    }
    if (std::strcmp(key, "imsi") == 0) {
        safeCopy(m_imsi, sizeof(m_imsi), value);
        return true;
    }
    if (std::strcmp(key, "sim_serial") == 0 || std::strcmp(key, "iccid") == 0) {
        safeCopy(m_simSerial, sizeof(m_simSerial), value);
        return true;
    }
    
    return false;
}

bool HwCompat::loadFromFile(const char* path) {
    int fd = _hw_raw_openat(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    char buffer[2048] = {};
    ssize_t bytesRead = _hw_raw_read(fd, buffer, sizeof(buffer) - 1);
    _hw_raw_close(fd);
    
    if (bytesRead <= 0) {
        return false;
    }
    buffer[bytesRead] = '\0';
    
    bool foundAny = false;
    char* savePtr = nullptr;
    char* line;
    char* bufPtr = buffer;
    
    while ((line = strtok_r(bufPtr, "\n", &savePtr)) != nullptr) {
        bufPtr = nullptr;
        
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0' || *line == '#') continue;
        
        char* eq = std::strchr(line, '=');
        if (!eq) {
            continue;
        }
        
        *eq = '\0';
        char* key = line;
        char* value = eq + 1;
        
        while (*key == ' ' || *key == '\t') key++;
        char* keyEnd = eq - 1;
        while (keyEnd > key && (*keyEnd == ' ' || *keyEnd == '\t')) *keyEnd-- = '\0';
        
        while (*value == ' ' || *value == '\t') value++;
        
        if (parseKeyValue(key, value)) {
            foundAny = true;
        }
    }
    
    return foundAny;
}

bool HwCompat::refreshFromBridge() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (loadFromFile(HW_BRIDGE_PATH)) {
        m_loaded = true;
        return true;
    }
    
    if (loadFromFile(HW_BRIDGE_FALLBACK)) {
        m_loaded = true;
        return true;
    }
    
    if (loadFromFile(HW_BRIDGE_LEGACY)) {
        m_loaded = (m_serial[0] != '\0');
        return m_loaded;
    }
    
    m_loaded = false;
    return false;
}

bool HwCompat::isLoaded() const {
    return m_loaded.load();
}

// ============================================================================
// Getter/Setter
// ============================================================================

void HwCompat::getSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_serial);
}
void HwCompat::setSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_serial, sizeof(m_serial), value);
}

void HwCompat::getBootSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_bootSerial);
}
void HwCompat::setBootSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_bootSerial, sizeof(m_bootSerial), value);
}

void HwCompat::getImei1(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imei1);
}
void HwCompat::setImei1(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imei1, sizeof(m_imei1), value);
}

void HwCompat::getImei2(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imei2);
}
void HwCompat::setImei2(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imei2, sizeof(m_imei2), value);
}

void HwCompat::getGsfId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_gsfId);
}
void HwCompat::setGsfId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_gsfId, sizeof(m_gsfId), value);
}

void HwCompat::getAndroidId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_androidId);
}
void HwCompat::setAndroidId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_androidId, sizeof(m_androidId), value);
}

void HwCompat::getWifiMac(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_wifiMac);
}
void HwCompat::setWifiMac(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_wifiMac, sizeof(m_wifiMac), value);
}

void HwCompat::getWidevineId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_widevineId);
}
void HwCompat::setWidevineId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_widevineId, sizeof(m_widevineId), value);
}

void HwCompat::getImsi(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imsi);
}
void HwCompat::setImsi(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imsi, sizeof(m_imsi), value);
}

void HwCompat::getSimSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_simSerial);
}
void HwCompat::setSimSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_simSerial, sizeof(m_simSerial), value);
}

// ============================================================================
// C API
// ============================================================================

extern "C" {

void HwState_Init(struct HwState* s) {
    if (!s) return;
    std::memset(s, 0, sizeof(HwState));
    
    HwCompat& hw = HwCompat::getInstance();
    hw.getSerial(s->serial, sizeof(s->serial));
    hw.getBootSerial(s->boot_serial, sizeof(s->boot_serial));
    hw.getImei1(s->imei1, sizeof(s->imei1));
    hw.getImei2(s->imei2, sizeof(s->imei2));
    hw.getGsfId(s->gsf_id, sizeof(s->gsf_id));
    hw.getAndroidId(s->android_id, sizeof(s->android_id));
    hw.getWifiMac(s->wifi_mac, sizeof(s->wifi_mac));
    hw.getWidevineId(s->widevine_id, sizeof(s->widevine_id));
    hw.getImsi(s->imsi, sizeof(s->imsi));
    hw.getSimSerial(s->sim_serial, sizeof(s->sim_serial));
}

void HwState_SetSerial(struct HwState* s, const char* v) {
    HwCompat::getInstance().setSerial(v);
    if (s && v) {
        std::strncpy(s->serial, v, sizeof(s->serial) - 1);
        s->serial[sizeof(s->serial) - 1] = '\0';
    }
}

void HwState_SetBootSerial(struct HwState* s, const char* v) {
    HwCompat::getInstance().setBootSerial(v);
    if (s && v) {
        std::strncpy(s->boot_serial, v, sizeof(s->boot_serial) - 1);
        s->boot_serial[sizeof(s->boot_serial) - 1] = '\0';
    }
}

void HwState_SetImei1(struct HwState* s, const char* v) {
    HwCompat::getInstance().setImei1(v);
    if (s && v) {
        std::strncpy(s->imei1, v, sizeof(s->imei1) - 1);
        s->imei1[sizeof(s->imei1) - 1] = '\0';
    }
}

void HwState_SetImei2(struct HwState* s, const char* v) {
    HwCompat::getInstance().setImei2(v);
    if (s && v) {
        std::strncpy(s->imei2, v, sizeof(s->imei2) - 1);
        s->imei2[sizeof(s->imei2) - 1] = '\0';
    }
}

void HwState_SetImei(struct HwState* s, const char* v) {
    HwState_SetImei1(s, v);
}

void HwState_SetGsfId(struct HwState* s, const char* v) {
    HwCompat::getInstance().setGsfId(v);
    if (s && v) {
        std::strncpy(s->gsf_id, v, sizeof(s->gsf_id) - 1);
        s->gsf_id[sizeof(s->gsf_id) - 1] = '\0';
    }
}

void HwState_SetAndroidId(struct HwState* s, const char* v) {
    HwCompat::getInstance().setAndroidId(v);
    if (s && v) {
        std::strncpy(s->android_id, v, sizeof(s->android_id) - 1);
        s->android_id[sizeof(s->android_id) - 1] = '\0';
    }
}

void HwState_SetWifiMac(struct HwState* s, const char* v) {
    HwCompat::getInstance().setWifiMac(v);
    if (s && v) {
        std::strncpy(s->wifi_mac, v, sizeof(s->wifi_mac) - 1);
        s->wifi_mac[sizeof(s->wifi_mac) - 1] = '\0';
    }
}

void HwState_SetWidevineId(struct HwState* s, const char* v) {
    HwCompat::getInstance().setWidevineId(v);
    if (s && v) {
        std::strncpy(s->widevine_id, v, sizeof(s->widevine_id) - 1);
        s->widevine_id[sizeof(s->widevine_id) - 1] = '\0';
    }
}

void HwState_SetImsi(struct HwState* s, const char* v) {
    HwCompat::getInstance().setImsi(v);
    if (s && v) {
        std::strncpy(s->imsi, v, sizeof(s->imsi) - 1);
        s->imsi[sizeof(s->imsi) - 1] = '\0';
    }
}

void HwState_SetSimSerial(struct HwState* s, const char* v) {
    HwCompat::getInstance().setSimSerial(v);
    if (s && v) {
        std::strncpy(s->sim_serial, v, sizeof(s->sim_serial) - 1);
        s->sim_serial[sizeof(s->sim_serial) - 1] = '\0';
    }
}

const char* HwState_GetSerial(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().serialPtr();
}

const char* HwState_GetBootSerial(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().bootSerialPtr();
}

const char* HwState_GetImei1(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().imei1Ptr();
}

const char* HwState_GetImei2(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().imei2Ptr();
}

const char* HwState_GetImei(struct HwState* s) {
    return HwState_GetImei1(s);
}

const char* HwState_GetGsfId(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().gsfIdPtr();
}

const char* HwState_GetAndroidId(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().androidIdPtr();
}

const char* HwState_GetWifiMac(struct HwState* s) {
    (void)s;
    return HwCompat::getInstance().wifiMacPtr();
}

int HwCompat_RefreshFromBridge(void) {
    return HwCompat::getInstance().refreshFromBridge() ? 1 : 0;
}

int HwCompat_IsLoaded(void) {
    return HwCompat::getInstance().isLoaded() ? 1 : 0;
}

} // extern "C"
