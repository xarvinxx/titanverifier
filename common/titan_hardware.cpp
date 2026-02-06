/**
 * Project Titan – TitanHardware Singleton Implementierung
 * 
 * Liest Hardware-Identifikatoren aus der Bridge-Datei:
 *   /data/local/tmp/.titan_state (chmod 666)
 * 
 * Format:
 *   Zeile 1: serial
 *   Zeile 2: imei  
 *   Zeile 3: boot_serial
 *   Zeile 4: gsfid
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
    std::memset(m_imei, 0, sizeof(m_imei));
    std::memset(m_gsfId, 0, sizeof(m_gsfId));
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
    
    // Strip trailing newlines/carriage returns
    size_t len = std::strlen(dest);
    while (len > 0 && (dest[len - 1] == '\n' || dest[len - 1] == '\r')) {
        dest[--len] = '\0';
    }
}

bool TitanHardware::refreshFromBridge() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Öffne Bridge-Datei mit low-level I/O (weniger Footprint)
    int fd = open(TITAN_BRIDGE_PATH, O_RDONLY);
    if (fd < 0) {
        // Datei existiert nicht oder kein Zugriff
        m_loaded = false;
        return false;
    }
    
    // Lese gesamte Datei (max 512 Bytes für 4 Zeilen)
    char buffer[512] = {};
    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    
    if (bytesRead <= 0) {
        m_loaded = false;
        return false;
    }
    buffer[bytesRead] = '\0';
    
    // Parse Zeilen: serial\nimei\nboot_serial\ngsfid
    char* savePtr = nullptr;
    char* line;
    int lineNum = 0;
    
    char* bufPtr = buffer;
    while ((line = strtok_r(bufPtr, "\n", &savePtr)) != nullptr && lineNum < 4) {
        bufPtr = nullptr;  // Für nachfolgende strtok_r Aufrufe
        
        switch (lineNum) {
            case 0:  // serial
                safeCopy(m_serial, sizeof(m_serial), line);
                break;
            case 1:  // imei
                safeCopy(m_imei, sizeof(m_imei), line);
                break;
            case 2:  // boot_serial
                safeCopy(m_bootSerial, sizeof(m_bootSerial), line);
                break;
            case 3:  // gsfid
                safeCopy(m_gsfId, sizeof(m_gsfId), line);
                break;
        }
        lineNum++;
    }
    
    // Validierung: mindestens serial muss gesetzt sein
    m_loaded = (m_serial[0] != '\0');
    return m_loaded;
}

bool TitanHardware::isLoaded() const {
    return m_loaded.load();
}

void TitanHardware::getSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_serial);
}

void TitanHardware::getBootSerial(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_bootSerial);
}

void TitanHardware::getImei(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_imei);
}

void TitanHardware::getGsfId(char* buf, size_t len) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(buf, len, m_gsfId);
}

void TitanHardware::setSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_serial, sizeof(m_serial), value);
}

void TitanHardware::setBootSerial(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_bootSerial, sizeof(m_bootSerial), value);
}

void TitanHardware::setImei(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_imei, sizeof(m_imei), value);
}

void TitanHardware::setGsfId(const char* value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    safeCopy(m_gsfId, sizeof(m_gsfId), value);
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
    hw.getImei(s->imei, sizeof(s->imei));
    hw.getGsfId(s->gsfid, sizeof(s->gsfid));
}

void TitanHardwareState_SetSerial(struct TitanHardwareState* s, const char* v) {
    TitanHardware& hw = TitanHardware::getInstance();
    hw.setSerial(v);
    if (s && v) {
        std::strncpy(s->serial, v, sizeof(s->serial) - 1);
        s->serial[sizeof(s->serial) - 1] = '\0';
    }
}

void TitanHardwareState_SetBootSerial(struct TitanHardwareState* s, const char* v) {
    TitanHardware& hw = TitanHardware::getInstance();
    hw.setBootSerial(v);
    if (s && v) {
        std::strncpy(s->boot_serial, v, sizeof(s->boot_serial) - 1);
        s->boot_serial[sizeof(s->boot_serial) - 1] = '\0';
    }
}

void TitanHardwareState_SetImei(struct TitanHardwareState* s, const char* v) {
    TitanHardware& hw = TitanHardware::getInstance();
    hw.setImei(v);
    if (s && v) {
        std::strncpy(s->imei, v, sizeof(s->imei) - 1);
        s->imei[sizeof(s->imei) - 1] = '\0';
    }
}

void TitanHardwareState_SetGsfId(struct TitanHardwareState* s, const char* v) {
    TitanHardware& hw = TitanHardware::getInstance();
    hw.setGsfId(v);
    if (s && v) {
        std::strncpy(s->gsfid, v, sizeof(s->gsfid) - 1);
        s->gsfid[sizeof(s->gsfid) - 1] = '\0';
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

const char* TitanHardwareState_GetImei(struct TitanHardwareState* s) {
    (void)s;
    return TitanHardware::getInstance().imeiPtr();
}

int TitanHardware_RefreshFromBridge(void) {
    return TitanHardware::getInstance().refreshFromBridge() ? 1 : 0;
}

int TitanHardware_IsLoaded(void) {
    return TitanHardware::getInstance().isLoaded() ? 1 : 0;
}

} // extern "C"
