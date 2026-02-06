/**
 * Project Titan – TitanHardware Singleton Implementierung (Phase 4.1)
 * 
 * Liest Hardware-Identifikatoren aus der Bridge-Datei:
 *   /data/local/tmp/.titan_identity (Key=Value Format)
 * 
 * Unterstützte Keys:
 *   serial, boot_serial, imei1, imei2, gsf_id, android_id,
 *   wifi_mac, widevine_id, imsi, sim_serial
 */
#include "titan_hardware.h"
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>

// ============================================================================
// TitanHardware Singleton Implementation
// ============================================================================

TitanHardware::TitanHardware() {
    // Zero-Initialize alle Buffer
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

TitanHardware& TitanHardware::getInstance() {
    // Meyer's Singleton - thread-safe in C++11+
    static TitanHardware instance;
    return instance;
}

void TitanHardware::safeCopy(char* dest, size_t destSize, const char* src) {
    if (!dest || destSize == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    std::strncpy(dest, src, destSize - 1);
    dest[destSize - 1] = '\0';
    
    // Strip trailing whitespace/newlines
    size_t len = std::strlen(dest);
    while (len > 0 && (dest[len - 1] == '\n' || dest[len - 1] == '\r' || 
                       dest[len - 1] == ' ' || dest[len - 1] == '\t')) {
        dest[--len] = '\0';
    }
}

bool TitanHardware::parseKeyValue(const char* key, const char* value) {
    if (!key || !value) return false;
    
    // Serial
    if (std::strcmp(key, "serial") == 0) {
        safeCopy(m_serial, sizeof(m_serial), value);
        return true;
    }
    if (std::strcmp(key, "boot_serial") == 0) {
        safeCopy(m_bootSerial, sizeof(m_bootSerial), value);
        return true;
    }
    
    // IMEI (Dual SIM)
    if (std::strcmp(key, "imei1") == 0 || std::strcmp(key, "imei") == 0) {
        safeCopy(m_imei1, sizeof(m_imei1), value);
        return true;
    }
    if (std::strcmp(key, "imei2") == 0) {
        safeCopy(m_imei2, sizeof(m_imei2), value);
        return true;
    }
    
    // IDs
    if (std::strcmp(key, "gsf_id") == 0 || std::strcmp(key, "gsfid") == 0) {
        safeCopy(m_gsfId, sizeof(m_gsfId), value);
        return true;
    }
    if (std::strcmp(key, "android_id") == 0) {
        safeCopy(m_androidId, sizeof(m_androidId), value);
        return true;
    }
    
    // Network
    if (std::strcmp(key, "wifi_mac") == 0 || std::strcmp(key, "mac_wlan0") == 0) {
        safeCopy(m_wifiMac, sizeof(m_wifiMac), value);
        return true;
    }
    
    // DRM
    if (std::strcmp(key, "widevine_id") == 0) {
        safeCopy(m_widevineId, sizeof(m_widevineId), value);
        return true;
    }
    
    // SIM
    if (std::strcmp(key, "imsi") == 0) {
        safeCopy(m_imsi, sizeof(m_imsi), value);
        return true;
    }
    if (std::strcmp(key, "sim_serial") == 0 || std::strcmp(key, "iccid") == 0) {
        safeCopy(m_simSerial, sizeof(m_simSerial), value);
        return true;
    }
    
    return false;  // Unbekannter Key
}

bool TitanHardware::loadFromFile(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    // Lese gesamte Datei (max 2KB für alle Keys)
    char buffer[2048] = {};
    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    
    if (bytesRead <= 0) {
        return false;
    }
    buffer[bytesRead] = '\0';
    
    bool foundAny = false;
    
    // Parse Key=Value Zeilen
    char* savePtr = nullptr;
    char* line;
    char* bufPtr = buffer;
    
    while ((line = strtok_r(bufPtr, "\n", &savePtr)) != nullptr) {
        bufPtr = nullptr;
        
        // Skip leere Zeilen und Kommentare
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0' || *line == '#') continue;
        
        // Finde '=' Trenner
        char* eq = std::strchr(line, '=');
        if (!eq) {
            // Legacy-Format (nur Werte, zeilenweise)
            // Fallback für alte .titan_state Dateien
            continue;
        }
        
        // Split in Key und Value
        *eq = '\0';
        char* key = line;
        char* value = eq + 1;
        
        // Trim Key
        while (*key == ' ' || *key == '\t') key++;
        char* keyEnd = eq - 1;
        while (keyEnd > key && (*keyEnd == ' ' || *keyEnd == '\t')) *keyEnd-- = '\0';
        
        // Trim Value
        while (*value == ' ' || *value == '\t') value++;
        
        if (parseKeyValue(key, value)) {
            foundAny = true;
        }
    }
    
    return foundAny;
}

bool TitanHardware::refreshFromBridge() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Versuche primären Pfad
    if (loadFromFile(TITAN_BRIDGE_PATH)) {
        m_loaded = true;
        return true;
    }
    
    // Fallback Pfad
    if (loadFromFile(TITAN_BRIDGE_FALLBACK)) {
        m_loaded = true;
        return true;
    }
    
    // Legacy-Pfad (altes Format: Zeilen ohne Keys)
    if (loadFromFile(TITAN_BRIDGE_LEGACY)) {
        m_loaded = (m_serial[0] != '\0');
        return m_loaded;
    }
    
    m_loaded = false;
    return false;
}

bool TitanHardware::isLoaded() const {
    return m_loaded.load();
}

// ============================================================================
// Getter/Setter Implementierungen
// ============================================================================

// Serial
void TitanHardware::getSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_serial);
}
void TitanHardware::setSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_serial, sizeof(m_serial), value);
}

void TitanHardware::getBootSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_bootSerial);
}
void TitanHardware::setBootSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_bootSerial, sizeof(m_bootSerial), value);
}

// IMEI
void TitanHardware::getImei1(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imei1);
}
void TitanHardware::setImei1(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imei1, sizeof(m_imei1), value);
}

void TitanHardware::getImei2(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imei2);
}
void TitanHardware::setImei2(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imei2, sizeof(m_imei2), value);
}

// IDs
void TitanHardware::getGsfId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_gsfId);
}
void TitanHardware::setGsfId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_gsfId, sizeof(m_gsfId), value);
}

void TitanHardware::getAndroidId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_androidId);
}
void TitanHardware::setAndroidId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_androidId, sizeof(m_androidId), value);
}

// Network
void TitanHardware::getWifiMac(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_wifiMac);
}
void TitanHardware::setWifiMac(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_wifiMac, sizeof(m_wifiMac), value);
}

// DRM
void TitanHardware::getWidevineId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_widevineId);
}
void TitanHardware::setWidevineId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_widevineId, sizeof(m_widevineId), value);
}

// SIM
void TitanHardware::getImsi(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imsi);
}
void TitanHardware::setImsi(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imsi, sizeof(m_imsi), value);
}

void TitanHardware::getSimSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_simSerial);
}
void TitanHardware::setSimSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_simSerial, sizeof(m_simSerial), value);
}

// ============================================================================
// C-kompatible API (delegiert an Singleton)
// ============================================================================

extern "C" {

void TitanHardwareState_Init(struct TitanHardwareState* s) {
    if (!s) return;
    std::memset(s, 0, sizeof(TitanHardwareState));
    
    // Synchronisiere mit Singleton
    TitanHardware& hw = TitanHardware::getInstance();
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

void TitanHardwareState_SetSerial(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setSerial(v);
    if (s && v) {
        std::strncpy(s->serial, v, sizeof(s->serial) - 1);
        s->serial[sizeof(s->serial) - 1] = '\0';
    }
}

void TitanHardwareState_SetBootSerial(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setBootSerial(v);
    if (s && v) {
        std::strncpy(s->boot_serial, v, sizeof(s->boot_serial) - 1);
        s->boot_serial[sizeof(s->boot_serial) - 1] = '\0';
    }
}

void TitanHardwareState_SetImei1(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setImei1(v);
    if (s && v) {
        std::strncpy(s->imei1, v, sizeof(s->imei1) - 1);
        s->imei1[sizeof(s->imei1) - 1] = '\0';
    }
}

void TitanHardwareState_SetImei2(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setImei2(v);
    if (s && v) {
        std::strncpy(s->imei2, v, sizeof(s->imei2) - 1);
        s->imei2[sizeof(s->imei2) - 1] = '\0';
    }
}

// Legacy-Kompatibilität
void TitanHardwareState_SetImei(struct TitanHardwareState* s, const char* v) {
    TitanHardwareState_SetImei1(s, v);
}

void TitanHardwareState_SetGsfId(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setGsfId(v);
    if (s && v) {
        std::strncpy(s->gsf_id, v, sizeof(s->gsf_id) - 1);
        s->gsf_id[sizeof(s->gsf_id) - 1] = '\0';
    }
}

void TitanHardwareState_SetAndroidId(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setAndroidId(v);
    if (s && v) {
        std::strncpy(s->android_id, v, sizeof(s->android_id) - 1);
        s->android_id[sizeof(s->android_id) - 1] = '\0';
    }
}

void TitanHardwareState_SetWifiMac(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setWifiMac(v);
    if (s && v) {
        std::strncpy(s->wifi_mac, v, sizeof(s->wifi_mac) - 1);
        s->wifi_mac[sizeof(s->wifi_mac) - 1] = '\0';
    }
}

void TitanHardwareState_SetWidevineId(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setWidevineId(v);
    if (s && v) {
        std::strncpy(s->widevine_id, v, sizeof(s->widevine_id) - 1);
        s->widevine_id[sizeof(s->widevine_id) - 1] = '\0';
    }
}

void TitanHardwareState_SetImsi(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setImsi(v);
    if (s && v) {
        std::strncpy(s->imsi, v, sizeof(s->imsi) - 1);
        s->imsi[sizeof(s->imsi) - 1] = '\0';
    }
}

void TitanHardwareState_SetSimSerial(struct TitanHardwareState* s, const char* v) {
    TitanHardware::getInstance().setSimSerial(v);
    if (s && v) {
        std::strncpy(s->sim_serial, v, sizeof(s->sim_serial) - 1);
        s->sim_serial[sizeof(s->sim_serial) - 1] = '\0';
    }
}

const char* TitanHardwareState_GetSerial(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().serialPtr();
}

const char* TitanHardwareState_GetBootSerial(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().bootSerialPtr();
}

const char* TitanHardwareState_GetImei1(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().imei1Ptr();
}

const char* TitanHardwareState_GetImei2(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().imei2Ptr();
}

const char* TitanHardwareState_GetImei(struct TitanHardwareState* s) {
    return TitanHardwareState_GetImei1(s);
}

const char* TitanHardwareState_GetGsfId(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().gsfIdPtr();
}

const char* TitanHardwareState_GetAndroidId(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().androidIdPtr();
}

const char* TitanHardwareState_GetWifiMac(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().wifiMacPtr();
}

int TitanHardware_RefreshFromBridge(void) {
    return TitanHardware::getInstance().refreshFromBridge() ? 1 : 0;
}

int TitanHardware_IsLoaded(void) {
    return TitanHardware::getInstance().isLoaded() ? 1 : 0;
}

} // extern "C"
