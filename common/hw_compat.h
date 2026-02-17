/**
 * HwCompat - Hardware Compatibility Singleton
 * Thread-safe singleton for hardware identity management.
 */
#ifndef HW_COMPAT_H
#define HW_COMPAT_H

#include <cstring>
#include <cstdint>

#ifdef __cplusplus
#include <mutex>
#include <atomic>

extern const char* HW_BRIDGE_PATH_DEC;
extern const char* HW_BRIDGE_FALLBACK_DEC;
extern const char* HW_BRIDGE_LEGACY_DEC;

#define HW_BRIDGE_PATH       HW_BRIDGE_PATH_DEC
#define HW_BRIDGE_FALLBACK   HW_BRIDGE_FALLBACK_DEC
#define HW_BRIDGE_LEGACY     HW_BRIDGE_LEGACY_DEC

#define HW_SERIAL_SIZE       96
#define HW_IMEI_SIZE         32
#define HW_ID_SIZE           64
#define HW_MAC_SIZE          24

class HwCompat {
public:
    static HwCompat& getInstance();
    
    HwCompat(const HwCompat&) = delete;
    HwCompat& operator=(const HwCompat&) = delete;
    HwCompat(HwCompat&&) = delete;
    HwCompat& operator=(HwCompat&&) = delete;
    
    bool refreshFromBridge();
    bool isLoaded() const;
    
    // Serial/Boot
    void getSerial(char* buf, size_t len) const;
    void setSerial(const char* value);
    void getBootSerial(char* buf, size_t len) const;
    void setBootSerial(const char* value);
    
    // IMEI (Dual SIM)
    void getImei1(char* buf, size_t len) const;
    void setImei1(const char* value);
    void getImei2(char* buf, size_t len) const;
    void setImei2(const char* value);
    
    // GSF/Android ID
    void getGsfId(char* buf, size_t len) const;
    void setGsfId(const char* value);
    void getAndroidId(char* buf, size_t len) const;
    void setAndroidId(const char* value);
    
    // Network
    void getWifiMac(char* buf, size_t len) const;
    void setWifiMac(const char* value);
    
    // DRM
    void getWidevineId(char* buf, size_t len) const;
    void setWidevineId(const char* value);
    
    // SIM
    void getImsi(char* buf, size_t len) const;
    void setImsi(const char* value);
    void getSimSerial(char* buf, size_t len) const;
    void setSimSerial(const char* value);
    
    // Raw pointer access (hooks only)
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
    
    // Legacy compat
    void getImei(char* buf, size_t len) const { getImei1(buf, len); }
    void setImei(const char* value) { setImei1(value); }
    const char* imeiPtr() const { return imei1Ptr(); }
    
private:
    HwCompat();
    ~HwCompat() = default;
    
    bool loadFromFile(const char* path);
    bool parseKeyValue(const char* key, const char* value);
    static void safeCopy(char* dest, size_t destSize, const char* src);
    
    mutable std::mutex m_mutex;
    std::atomic<bool> m_loaded{false};
    
    char m_serial[HW_SERIAL_SIZE];
    char m_bootSerial[HW_SERIAL_SIZE];
    char m_imei1[HW_IMEI_SIZE];
    char m_imei2[HW_IMEI_SIZE];
    char m_gsfId[HW_ID_SIZE];
    char m_androidId[HW_ID_SIZE];
    char m_wifiMac[HW_MAC_SIZE];
    char m_widevineId[HW_ID_SIZE];
    char m_imsi[HW_IMEI_SIZE];
    char m_simSerial[HW_IMEI_SIZE];
};

extern "C" {
#endif

struct HwState {
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

void HwState_Init(struct HwState* s);
void HwState_SetSerial(struct HwState* s, const char* v);
void HwState_SetBootSerial(struct HwState* s, const char* v);
void HwState_SetImei1(struct HwState* s, const char* v);
void HwState_SetImei2(struct HwState* s, const char* v);
void HwState_SetGsfId(struct HwState* s, const char* v);
void HwState_SetAndroidId(struct HwState* s, const char* v);
void HwState_SetWifiMac(struct HwState* s, const char* v);
void HwState_SetWidevineId(struct HwState* s, const char* v);
void HwState_SetImsi(struct HwState* s, const char* v);
void HwState_SetSimSerial(struct HwState* s, const char* v);

const char* HwState_GetSerial(struct HwState* s);
const char* HwState_GetBootSerial(struct HwState* s);
const char* HwState_GetImei1(struct HwState* s);
const char* HwState_GetImei2(struct HwState* s);
const char* HwState_GetGsfId(struct HwState* s);
const char* HwState_GetAndroidId(struct HwState* s);
const char* HwState_GetWifiMac(struct HwState* s);

void HwState_SetImei(struct HwState* s, const char* v);
const char* HwState_GetImei(struct HwState* s);

int HwCompat_RefreshFromBridge(void);
int HwCompat_IsLoaded(void);

#ifdef __cplusplus
}
#endif

#endif // HW_COMPAT_H
