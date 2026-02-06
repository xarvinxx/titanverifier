/**
 * Project Titan – TitanHardware Singleton
 * Thread-sicheres Singleton für Hardware-Identitäts-Spoofing.
 * 
 * Bridge-Format (/data/local/tmp/.titan_state):
 *   Zeile 1: serial
 *   Zeile 2: imei
 *   Zeile 3: boot_serial
 *   Zeile 4: gsfid
 * 
 * Schutz gegen: Property-Fingerprinting (Säule 1), IMEI-Leaks (Säule 2)
 */
#ifndef TITAN_HARDWARE_H
#define TITAN_HARDWARE_H

#include <cstring>
#include <cstdint>

#ifdef __cplusplus
#include <mutex>
#include <atomic>

// Bridge-Pfad für Zygisk-Module (früher Prozessstart, /data/local/tmp erreichbar)
#define TITAN_BRIDGE_PATH "/data/local/tmp/.titan_state"

/**
 * TitanHardware - Thread-Safe Singleton
 * Verwaltet alle Hardware-Identifikatoren für das Spoofing.
 */
class TitanHardware {
public:
    // Singleton-Zugriff
    static TitanHardware& getInstance();
    
    // Lösche Copy/Move für Singleton
    TitanHardware(const TitanHardware&) = delete;
    TitanHardware& operator=(const TitanHardware&) = delete;
    TitanHardware(TitanHardware&&) = delete;
    TitanHardware& operator=(TitanHardware&&) = delete;
    
    /**
     * Lädt State aus der Bridge-Datei.
     * Format: serial\nimei\nboot_serial\ngsfid
     * @return true wenn erfolgreich geladen
     */
    bool refreshFromBridge();
    
    /**
     * Prüft ob gültige Daten geladen wurden.
     */
    bool isLoaded() const;
    
    // Getter (thread-safe, kopieren in Buffer)
    void getSerial(char* buf, size_t len) const;
    void getBootSerial(char* buf, size_t len) const;
    void getImei(char* buf, size_t len) const;
    void getGsfId(char* buf, size_t len) const;
    
    // Setter (thread-safe)
    void setSerial(const char* value);
    void setBootSerial(const char* value);
    void setImei(const char* value);
    void setGsfId(const char* value);
    
    // Raw-Pointer-Zugriff (nur für Hooks, NICHT thread-safe außerhalb von Lock)
    const char* serialPtr() const { return m_serial; }
    const char* bootSerialPtr() const { return m_bootSerial; }
    const char* imeiPtr() const { return m_imei; }
    
private:
    TitanHardware();
    ~TitanHardware() = default;
    
    // Interne Daten
    mutable std::mutex m_mutex;
    std::atomic<bool> m_loaded{false};
    
    // Buffer mit festen Größen (Anti-Forensics: keine dynamische Allokation)
    char m_serial[96];
    char m_bootSerial[96];
    char m_imei[32];
    char m_gsfId[32];
    
    // Sichere String-Kopie
    static void safeCopy(char* dest, size_t destSize, const char* src);
};

extern "C" {
#endif

// C-kompatible API für Legacy-Code und JNI
struct TitanHardwareState {
    char serial[96];
    char boot_serial[96];
    char imei[32];
    char gsfid[32];
};

void TitanHardwareState_Init(struct TitanHardwareState* s);
void TitanHardwareState_SetSerial(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetBootSerial(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetImei(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetGsfId(struct TitanHardwareState* s, const char* v);
const char* TitanHardwareState_GetSerial(struct TitanHardwareState* s);
const char* TitanHardwareState_GetBootSerial(struct TitanHardwareState* s);
const char* TitanHardwareState_GetImei(struct TitanHardwareState* s);

// Bridge-Refresh (C-API)
int TitanHardware_RefreshFromBridge(void);
int TitanHardware_IsLoaded(void);

#ifdef __cplusplus
}
#endif

#endif // TITAN_HARDWARE_H
