/**
 * Project Titan – TitanHardware Singleton (Phase 4.1)
 * Thread-sicheres Singleton für Hardware-Identitäts-Spoofing.
 * 
 * Bridge-Format (/data/local/tmp/.titan_identity):
 *   Key=Value Format, eine Zeile pro Feld:
 *   serial=XXXX
 *   boot_serial=XXXX
 *   imei1=XXXX
 *   imei2=XXXX
 *   gsf_id=XXXX
 *   android_id=XXXX
 *   wifi_mac=XX:XX:XX:XX:XX:XX
 *   widevine_id=XXXX
 *   imsi=XXXX
 *   sim_serial=XXXX
 * 
 * Schutz gegen alle Säulen:
 * - Säule 1: Property-Fingerprinting (serial, boot_serial)
 * - Säule 2: IMEI/IMSI-Leaks (imei1, imei2, imsi, sim_serial)
 * - Säule 3: Network-Fingerprinting (wifi_mac)
 * - Säule 4: DRM-Fingerprinting (widevine_id)
 * - Säule 5: ID-Correlation (gsf_id, android_id)
 */
#ifndef TITAN_HARDWARE_H
#define TITAN_HARDWARE_H

#include <cstring>
#include <cstdint>

#ifdef __cplusplus
#include <mutex>
#include <atomic>

// Bridge-Pfade für Zygisk-Module
#define TITAN_BRIDGE_PATH       "/data/local/tmp/.titan_identity"
#define TITAN_BRIDGE_FALLBACK   "/data/adb/modules/titan_verifier/titan_identity"
#define TITAN_BRIDGE_LEGACY     "/data/local/tmp/.titan_state"

// Buffer-Größen (fixiert für Anti-Forensics)
#define TITAN_SERIAL_SIZE       96
#define TITAN_IMEI_SIZE         32
#define TITAN_ID_SIZE           64
#define TITAN_MAC_SIZE          24

/**
 * TitanHardware - Thread-Safe Singleton
 * Verwaltet ALLE Hardware-Identifikatoren für das Spoofing.
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
     * Lädt State aus der Bridge-Datei (Key=Value Format).
     * Versucht primären Pfad, dann Fallback, dann Legacy.
     * @return true wenn erfolgreich geladen
     */
    bool refreshFromBridge();
    
    /**
     * Prüft ob gültige Daten geladen wurden.
     */
    bool isLoaded() const;
    
    // ========== Serial/Boot ==========
    void getSerial(char* buf, size_t len) const;
    void setSerial(const char* value);
    void getBootSerial(char* buf, size_t len) const;
    void setBootSerial(const char* value);
    
    // ========== IMEI (Dual SIM) ==========
    void getImei1(char* buf, size_t len) const;
    void setImei1(const char* value);
    void getImei2(char* buf, size_t len) const;
    void setImei2(const char* value);
    
    // ========== GSF/Android ID ==========
    void getGsfId(char* buf, size_t len) const;
    void setGsfId(const char* value);
    void getAndroidId(char* buf, size_t len) const;
    void setAndroidId(const char* value);
    
    // ========== Network ==========
    void getWifiMac(char* buf, size_t len) const;
    void setWifiMac(const char* value);
    
    // ========== DRM ==========
    void getWidevineId(char* buf, size_t len) const;
    void setWidevineId(const char* value);
    
    // ========== SIM ==========
    void getImsi(char* buf, size_t len) const;
    void setImsi(const char* value);
    void getSimSerial(char* buf, size_t len) const;
    void setSimSerial(const char* value);
    
    // Raw-Pointer-Zugriff (nur für Hooks, NICHT thread-safe außerhalb von Lock)
    const char* serialPtr() const { return m_serial; }
    const char* bootSerialPtr() const { return m_bootSerial; }
    const char* imei1Ptr() const { return m_imei1; }
    const char* imei2Ptr() const { return m_imei2; }
    const char* gsfIdPtr() const { return m_gsfId; }
    const char* androidIdPtr() const { return m_androidId; }
    const char* wifiMacPtr() const { return m_wifiMac; }
    const char* widevineIdPtr() const { return m_widevineId; }
    const char* imsiPtr() const { return m_imsi; }
    const char* simSerialPtr() const { return m_simSerial; }
    
    // Legacy-Kompatibilität
    void getImei(char* buf, size_t len) const { getImei1(buf, len); }
    void setImei(const char* value) { setImei1(value); }
    const char* imeiPtr() const { return imei1Ptr(); }
    
private:
    TitanHardware();
    ~TitanHardware() = default;
    
    // Interne Parser
    bool loadFromFile(const char* path);
    bool parseKeyValue(const char* key, const char* value);
    static void safeCopy(char* dest, size_t destSize, const char* src);
    
    // Interne Daten
    mutable std::mutex m_mutex;
    std::atomic<bool> m_loaded{false};
    
    // Buffer mit festen Größen (Anti-Forensics: keine dynamische Allokation)
    char m_serial[TITAN_SERIAL_SIZE];
    char m_bootSerial[TITAN_SERIAL_SIZE];
    char m_imei1[TITAN_IMEI_SIZE];
    char m_imei2[TITAN_IMEI_SIZE];
    char m_gsfId[TITAN_ID_SIZE];
    char m_androidId[TITAN_ID_SIZE];
    char m_wifiMac[TITAN_MAC_SIZE];
    char m_widevineId[TITAN_ID_SIZE];
    char m_imsi[TITAN_IMEI_SIZE];
    char m_simSerial[TITAN_IMEI_SIZE];
};

extern "C" {
#endif

// C-kompatible API für Legacy-Code und JNI
struct TitanHardwareState {
    char serial[96];
    char boot_serial[96];
    char imei1[32];
    char imei2[32];
    char gsf_id[64];
    char android_id[64];
    char wifi_mac[24];
    char widevine_id[64];
    char imsi[32];
    char sim_serial[32];
};

// C-API Funktionen
void TitanHardwareState_Init(struct TitanHardwareState* s);
void TitanHardwareState_SetSerial(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetBootSerial(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetImei1(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetImei2(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetGsfId(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetAndroidId(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetWifiMac(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetWidevineId(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetImsi(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetSimSerial(struct TitanHardwareState* s, const char* v);

const char* TitanHardwareState_GetSerial(struct TitanHardwareState* s);
const char* TitanHardwareState_GetBootSerial(struct TitanHardwareState* s);
const char* TitanHardwareState_GetImei1(struct TitanHardwareState* s);
const char* TitanHardwareState_GetImei2(struct TitanHardwareState* s);
const char* TitanHardwareState_GetGsfId(struct TitanHardwareState* s);
const char* TitanHardwareState_GetAndroidId(struct TitanHardwareState* s);
const char* TitanHardwareState_GetWifiMac(struct TitanHardwareState* s);

// Legacy-Kompatibilität
void TitanHardwareState_SetImei(struct TitanHardwareState* s, const char* v);
const char* TitanHardwareState_GetImei(struct TitanHardwareState* s);

// Bridge-Refresh (C-API)
int TitanHardware_RefreshFromBridge(void);
int TitanHardware_IsLoaded(void);

#ifdef __cplusplus
}
#endif

#endif // TITAN_HARDWARE_H
