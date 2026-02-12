/*
 * Project Titan - Zygisk Module (Phase 6.0 - Total Stealth)
 * 
 * KERNEL-LEVEL IDENTITY SPOOFING:
 * - __system_property_get: Serial, IMEI, GSF, Android ID
 * - getifaddrs: MAC via AF_PACKET
 * - ioctl SIOCGIFHWADDR: MAC via ioctl
 * - recvmsg: Netlink RTM_NEWLINK MAC spoofing (für libsscronet.so)
 * - open/read: /sys/class/net/wlan0/address shadowing
 * 
 * Target: Google Pixel 6, Android 14, KernelSU + Zygisk Next
 */

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/input.h>
#include <dirent.h>
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <atomic>
#include <mutex>
#include <unordered_set>
#include <unordered_map>

#include "../include/zygisk.hpp"
#include "../include/dobby.h"
#include "../common/titan_hardware.h"

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

#define TITAN_KILL_SWITCH       "/data/local/tmp/titan_stop"
#define TITAN_BRIDGE_PATH       "/data/adb/modules/titan_verifier/titan_identity"

// Target Apps — NUR Social-Media & Verifier.
// GMS/GSF/Vending sind BEWUSST AUSGESCHLOSSEN (v4.0 GMS-Schutz):
//   - GMS muss die ECHTEN Device-IDs sehen für Play Integrity (BASIC+DEVICE)
//   - Hooks in GMS spoofen die GSF-ID → Google sieht "unbekanntes Gerät"
//   - Das zerstört den Checkin und die gesamte Trust-Chain
//   - TikTok/Instagram prüfen NICHT welche IDs GMS intern hat
static const char* TARGET_APPS[] = {
    "com.titan.verifier",
    "com.zhiliaoapp.musically",      // TikTok International
    "com.ss.android.ugc.trill",      // TikTok
    "com.instagram.android",         // Instagram
    "com.snapchat.android",          // Snapchat
    "com.androidfung.drminfo",       // DRM Info App (Verifikation)
    "tw.reh.deviceid",               // Device ID App (Verifikation)
    nullptr
};

// Hardcoded Pixel 6 Defaults
static const char* DEFAULT_SERIAL = "28161FDF6006P8";
static const char* DEFAULT_IMEI1 = "352269111271008";
static const char* DEFAULT_IMEI2 = "358476312016587";
static const char* DEFAULT_ANDROID_ID = "d7f4b30e1b210a83";
static const char* DEFAULT_GSF_ID = "3a8c4f72d91e50b6";
static const char* DEFAULT_WIFI_MAC = "be:08:6e:16:a6:5d";
static const char* DEFAULT_WIDEVINE_ID = "10179c6bcba352dbd5ce5c88fec8e098";

// ==============================================================================
// Original Function Pointers
// ==============================================================================

using SystemPropertyGetFn = int (*)(const char* name, char* value);
using GetifaddrsFn = int (*)(struct ifaddrs** ifap);
using IoctlFn = int (*)(int fd, unsigned long request, ...);
using RecvmsgFn = ssize_t (*)(int sockfd, struct msghdr* msg, int flags);
using OpenFn = int (*)(const char* pathname, int flags, ...);
using ReadFn = ssize_t (*)(int fd, void* buf, size_t count);
using FopenFn = FILE* (*)(const char* pathname, const char* mode);
using FreadFn = size_t (*)(void* ptr, size_t size, size_t nmemb, FILE* stream);
using FgetsFn = char* (*)(char* s, int size, FILE* stream);
using OpendirFn = DIR* (*)(const char* name);
using ReaddirFn = struct dirent* (*)(DIR* dirp);
using ClosedirFn = int (*)(DIR* dirp);
using SystemPropertyReadOldFn = int (*)(const void* pi, char* name, char* value);
using SendmsgFn = ssize_t (*)(int sockfd, const struct msghdr* msg, int flags);

// Widevine NDK API Types (Phase 9.5 - Korrekte Signaturen!)
struct AMediaDrm;
typedef int media_status_t;
#define AMEDIA_OK 0
#define AMEDIA_DRM_NOT_PROVISIONED -10003

// AMediaDrmByteArray - MUSS identisch mit NDK <media/NdkMediaDrm.h> sein!
typedef struct {
    const uint8_t* ptr;
    size_t length;
} TitanDrmByteArray;

// Korrekte Funktionssignaturen (exakt wie in der NDK-API)
using AMediaDrmCreateByUUIDFn = AMediaDrm* (*)(const uint8_t uuid[16]);
using AMediaDrmReleaseFn = void (*)(AMediaDrm*);
using AMediaDrmGetPropertyByteArrayFn = media_status_t (*)(AMediaDrm*, const char*, TitanDrmByteArray*);
using AMediaDrmGetPropertyStringFn = media_status_t (*)(AMediaDrm*, const char*, const char**);
using AMediaDrmIsCryptoSchemeSupportedFn = bool (*)(const uint8_t uuid[16], const char* mimeType);

static SystemPropertyGetFn g_origSystemPropertyGet = nullptr;
static GetifaddrsFn g_origGetifaddrs = nullptr;
static IoctlFn g_origIoctl = nullptr;
static RecvmsgFn g_origRecvmsg = nullptr;
static OpenFn g_origOpen = nullptr;
static ReadFn g_origRead = nullptr;
static FopenFn g_origFopen = nullptr;
static FreadFn g_origFread = nullptr;
static FgetsFn g_origFgets = nullptr;
static OpendirFn g_origOpendir = nullptr;
static ReaddirFn g_origReaddir = nullptr;
static ClosedirFn g_origClosedir = nullptr;
static SystemPropertyReadOldFn g_origSysPropRead = nullptr;
static SendmsgFn g_origSendmsg = nullptr;
static AMediaDrmCreateByUUIDFn g_origAMediaDrmCreateByUUID = nullptr;
static AMediaDrmReleaseFn g_origAMediaDrmRelease = nullptr;
static AMediaDrmGetPropertyByteArrayFn g_origAMediaDrmGetPropertyByteArray = nullptr;
static AMediaDrmGetPropertyStringFn g_origAMediaDrmGetPropertyString = nullptr;
static AMediaDrmIsCryptoSchemeSupportedFn g_origAMediaDrmIsCryptoSchemeSupported = nullptr;

// Track unsere Fake-DRM-Objekte
static std::unordered_set<AMediaDrm*> g_fakeDrmObjects;

// Widevine UUID (ed282e16-fdd2-47c7-8d6d-09946462f367)
static const uint8_t WIDEVINE_UUID[16] = {
    0xed, 0x28, 0x2e, 0x16, 0xfd, 0xd2, 0x47, 0xc7,
    0x8d, 0x6d, 0x09, 0x94, 0x64, 0x62, 0xf3, 0x67
};

// Master Widevine ID (Phase 7.8 - Fixed Pixel 6 Identity)
static const char* MASTER_WIDEVINE_HEX = "10179c6bcba352dbd5ce5c88fec8e098";
static uint8_t g_widevineBytes[16] = {0};
static bool g_widevineParsed = false;

// Track fopen'd MAC files
static std::unordered_set<FILE*> g_macFileStreams;

// Track open'd input device FDs
static std::unordered_set<int> g_inputDeviceFds;

// Track /dev/input/ event FDs → event number (für EVIOCGNAME)
static std::unordered_map<int, int> g_inputEventFdMap;

// Track opendir handles für /dev/input/ Virtualisierung
static std::unordered_set<DIR*> g_inputDirHandles;
static std::unordered_map<DIR*, int> g_inputDirFakeIdx; // Wie viele Fake-Entries schon geliefert

// Track Netlink Sockets für RTM_GETLINK (sendmsg → recvmsg Korrelation)
static std::unordered_set<int> g_netlinkSockets;
static std::mutex g_netlinkMutex;

// Pixel 6 Input-Event-Devices (was in /dev/input/ erscheinen soll)
struct FakeInputEvent {
    const char* filename;  // z.B. "event0"
    const char* devname;   // z.B. "fts_ts" (für EVIOCGNAME)
};
static const FakeInputEvent PIXEL6_INPUT_EVENTS[] = {
    {"event0", "fts_ts"},           // STM Touchscreen
    {"event1", "gpio-keys"},        // Volume Keys
    {"event2", "Power Button"},     // Power Button
    {"event3", "goodix_fp"},        // Fingerprint
    {"event4", "uinput-fpc"},       // Fingerprint HAL
    {nullptr, nullptr}              // Sentinel
};

// ==============================================================================
// State
// ==============================================================================

static std::atomic<bool> g_bridgeLoaded{false};
static std::atomic<bool> g_killSwitchActive{false};
static std::atomic<bool> g_usingDefaults{false};
static std::mutex g_fdMapMutex;
static std::unordered_set<int> g_macFileFds;

// Cached MAC bytes
static unsigned char g_spoofedMacBytes[6] = {0};
static bool g_macParsed = false;

// ==============================================================================
// Helpers
// ==============================================================================

static bool checkKillSwitch() {
    struct stat st;
    if (stat(TITAN_KILL_SWITCH, &st) == 0) {
        g_killSwitchActive = true;
        return true;
    }
    return false;
}

static bool isTargetApp(const char* packageName) {
    if (!packageName) return false;
    for (int i = 0; TARGET_APPS[i] != nullptr; i++) {
        if (strcmp(packageName, TARGET_APPS[i]) == 0) return true;
    }
    return false;
}

static bool parseMacString(const char* macStr, unsigned char* out) {
    if (!macStr || !out) return false;
    int v[6];
    if (sscanf(macStr, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)v[i];
    return true;
}

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
            
            if (strcmp(key, "serial") == 0) { hw.setSerial(value); foundAny = true; }
            else if (strcmp(key, "boot_serial") == 0) { hw.setBootSerial(value); foundAny = true; }
            else if (strcmp(key, "imei1") == 0) { hw.setImei1(value); foundAny = true; }
            else if (strcmp(key, "imei2") == 0) { hw.setImei2(value); foundAny = true; }
            else if (strcmp(key, "gsf_id") == 0) { hw.setGsfId(value); foundAny = true; }
            else if (strcmp(key, "android_id") == 0) { hw.setAndroidId(value); foundAny = true; }
            else if (strcmp(key, "wifi_mac") == 0) { hw.setWifiMac(value); foundAny = true; }
            else if (strcmp(key, "widevine_id") == 0) { hw.setWidevineId(value); foundAny = true; }
            else if (strcmp(key, "imsi") == 0) { hw.setImsi(value); foundAny = true; }
            else if (strcmp(key, "sim_serial") == 0) { hw.setSimSerial(value); foundAny = true; }
        }
    }
    
    return foundAny;
}

static void loadBridge() {
    if (g_bridgeLoaded.load()) return;
    
    if (loadBridgeFromFile(TITAN_BRIDGE_PATH)) {
        LOGI("[TITAN] Bridge loaded from: %s", TITAN_BRIDGE_PATH);
        g_bridgeLoaded = true;
    } else {
        LOGW("[TITAN] Bridge not found, using defaults");
        applyDefaults();
        g_bridgeLoaded = true;
    }
    
    // Cache MAC bytes
    TitanHardware& hw = TitanHardware::getInstance();
    char macStr[24] = {};
    hw.getWifiMac(macStr, sizeof(macStr));
    if (macStr[0] && parseMacString(macStr, g_spoofedMacBytes)) {
        g_macParsed = true;
        LOGI("[TITAN] Cached MAC: %s", macStr);
    }
}

static bool isMacPath(const char* path) {
    if (!path) return false;
    return (strstr(path, "/sys/class/net/") && strstr(path, "/address")) ||
           strcmp(path, "/sys/class/net/wlan0/address") == 0 ||
           strcmp(path, "/sys/class/net/eth0/address") == 0 ||
           strstr(path, "/sys/class/bluetooth/") != nullptr ||  // BT MAC
           strstr(path, "/proc/net/arp") != nullptr;
}

// Phase 11.0: Pfade die sensitive Netzwerk-Informationen enthalten
static bool isNetworkInfoPath(const char* path) {
    if (!path) return false;
    return strcmp(path, "/proc/net/if_inet6") == 0 ||
           strcmp(path, "/proc/net/ipv6_route") == 0 ||
           strcmp(path, "/proc/net/tcp6") == 0 ||
           strcmp(path, "/proc/net/udp6") == 0;
}

// Phase 11.0: Root-Detection Pfade die versteckt werden müssen
static bool isRootDetectionPath(const char* path) {
    if (!path) return false;
    return strstr(path, "/sbin/su") != nullptr ||
           strstr(path, "/system/xbin/su") != nullptr ||
           strstr(path, "/system/bin/su") != nullptr ||
           strstr(path, "/data/adb/modules") != nullptr ||
           strstr(path, "/data/adb/ksu") != nullptr ||
           strstr(path, "/data/adb/magisk") != nullptr ||
           strstr(path, "superuser.apk") != nullptr ||
           strstr(path, "/sbin/.magisk") != nullptr ||
           strstr(path, "zygisk") != nullptr ||
           strstr(path, "lsposed") != nullptr ||
           strstr(path, "xposed") != nullptr ||
           strstr(path, "/data/local/tmp/ksud") != nullptr;
}

static bool isInputDevicesPath(const char* path) {
    if (!path) return false;
    return strcmp(path, "/proc/bus/input/devices") == 0;
}

static bool isCpuInfoPath(const char* path) {
    if (!path) return false;
    return strcmp(path, "/proc/cpuinfo") == 0;
}

static bool isKernelVersionPath(const char* path) {
    if (!path) return false;
    return strcmp(path, "/proc/version") == 0;
}

// Phase 11.0: Dynamischer /proc/net/if_inet6 mit Fake-MAC EUI-64
// Format: <ipv6_hex_no_colons> <idx> <prefix_len> <scope> <flags> <device>
static char g_fake_if_inet6[512] = "";
static const char* getFakeIfInet6() {
    if (g_fake_if_inet6[0] != '\0') return g_fake_if_inet6;
    
    // Hole die Fake-MAC
    TitanHardware& hw = TitanHardware::getInstance();
    char macStr[32] = {0};
    hw.getWifiMac(macStr, sizeof(macStr));
    
    if (macStr[0] == '\0') {
        // Fallback: nur Loopback
        snprintf(g_fake_if_inet6, sizeof(g_fake_if_inet6),
            "00000000000000000000000000000001 01 80 10 80       lo\n");
        return g_fake_if_inet6;
    }
    
    // Parse MAC aa:bb:cc:dd:ee:ff
    unsigned int m[6] = {0};
    sscanf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    
    // EUI-64: Byte 0 XOR 0x02, insert FF:FE
    unsigned int eui0 = m[0] ^ 0x02;
    
    // Generiere Link-Local: fe80::<eui64>
    char ll_hex[33];
    snprintf(ll_hex, sizeof(ll_hex), "fe80000000000000%02x%02xff%02xfe%02x%02x%02x",
        eui0, m[1], m[2], m[3], m[4], m[5]);
    
    // Baue die /proc/net/if_inet6 Ausgabe
    snprintf(g_fake_if_inet6, sizeof(g_fake_if_inet6),
        "00000000000000000000000000000001 01 80 10 80       lo\n"
        "%s 03 40 20 80    wlan0\n",  // Link-Local, scope=0x20(link), prefix=64
        ll_hex);
    
    LOGI("[TITAN] Generated fake if_inet6 with MAC %s", macStr);
    return g_fake_if_inet6;
}
#define FAKE_IF_INET6 getFakeIfInet6()

// Pixel 6 Input-Device-Datei (realistisches Oriole Hardware-Layout)
// Enthält: fts_ts (STM Touchscreen), gpio-keys (Vol+/Vol-), goodix_fp (Fingerabdruck),
//          Power Button, uinput-fpc (Fingerprint Sensor HAL)
static const char* FAKE_INPUT_DEVICES = 
    "I: Bus=0018 Vendor=0000 Product=0000 Version=0000\n"
    "N: Name=\"fts_ts\"\n"
    "P: Phys=i2c-fts_ts\n"
    "S: Sysfs=/devices/platform/110d0000.spi/spi_master/spi7/spi7.0/input/input0\n"
    "U: Uniq=\n"
    "H: Handlers=event0\n"
    "B: PROP=2\n"
    "B: EV=b\n"
    "B: KEY=420 0 0 0 0 0 0 0 0 0 0\n"
    "B: ABS=6e18000 0 0\n"
    "\n"
    "I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
    "N: Name=\"gpio-keys\"\n"
    "P: Phys=gpio-keys/input0\n"
    "S: Sysfs=/devices/platform/gpio-keys/input/input1\n"
    "U: Uniq=\n"
    "H: Handlers=event1 keychord\n"
    "B: PROP=0\n"
    "B: EV=3\n"
    "B: KEY=8000 100000 0 0 0\n"
    "\n"
    "I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n"
    "N: Name=\"Power Button\"\n"
    "P: Phys=LNXPWRBN/button/input0\n"
    "S: Sysfs=/devices/platform/power-button/input/input2\n"
    "U: Uniq=\n"
    "H: Handlers=event2 keychord\n"
    "B: PROP=0\n"
    "B: EV=3\n"
    "B: KEY=10000000000000 0\n"
    "\n"
    "I: Bus=0018 Vendor=27c6 Product=0000 Version=0100\n"
    "N: Name=\"goodix_fp\"\n"
    "P: Phys=\n"
    "S: Sysfs=/devices/platform/odm/odm:fp_hal/goodix_fp/input/input3\n"
    "U: Uniq=\n"
    "H: Handlers=event3\n"
    "B: PROP=0\n"
    "B: EV=1\n"
    "\n"
    "I: Bus=0003 Vendor=0000 Product=0000 Version=0000\n"
    "N: Name=\"uinput-fpc\"\n"
    "P: Phys=\n"
    "S: Sysfs=/devices/virtual/input/input4\n"
    "U: Uniq=\n"
    "H: Handlers=event4\n"
    "B: PROP=0\n"
    "B: EV=3\n"
    "B: KEY=4000000000 0 0 0 0 0\n"
    "\n";

// Pixel 6 /proc/cpuinfo (Tensor G1 / Exynos gs101 - echtes Format)
static const char* FAKE_CPUINFO =
    "Processor\t: AArch64 Processor rev 0 (aarch64)\n"
    "processor\t: 0\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd05\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 1\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd05\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 2\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd05\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 3\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd05\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 4\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd08\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 5\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd08\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 6\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd44\n"
    "CPU revision\t: 0\n"
    "\n"
    "processor\t: 7\n"
    "BogoMIPS\t: 52.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd44\n"
    "CPU revision\t: 0\n"
    "\n"
    "Hardware\t: GS101 Oriole\n"
    "Serial\t\t: 0000000000000000\n";

// Pixel 6 /proc/version (Kernel-Version für GS101)
static const char* FAKE_KERNEL_VERSION =
    "Linux version 5.10.149-android13-4-00003-g05231a35ff43-ab9850636 "
    "(build-user@build-host) (Android (8508608, based on r450784e) clang version "
    "14.0.7, LLD 14.0.7) #1 SMP PREEMPT Mon Jan 30 19:12:27 UTC 2023\n";

// ==============================================================================
// Build Property Overrides (Pixel 6 - Oriole, Android 14)
// ==============================================================================

struct PropertyOverride {
    const char* name;
    const char* value;
};

static const PropertyOverride PIXEL6_BUILD_PROPS[] = {
    // Product Properties
    {"ro.product.manufacturer",             "Google"},
    {"ro.product.model",                    "Pixel 6"},
    {"ro.product.brand",                    "google"},
    {"ro.product.name",                     "oriole"},
    {"ro.product.device",                   "oriole"},
    {"ro.product.board",                    "oriole"},
    {"ro.hardware",                         "oriole"},
    {"ro.hardware.chipname",                "gs101"},
    
    // Product Partitions (system, vendor, odm)
    {"ro.product.system.brand",             "google"},
    {"ro.product.system.model",             "Pixel 6"},
    {"ro.product.system.manufacturer",      "Google"},
    {"ro.product.system.device",            "oriole"},
    {"ro.product.system.name",              "oriole"},
    {"ro.product.vendor.brand",             "google"},
    {"ro.product.vendor.model",             "Pixel 6"},
    {"ro.product.vendor.manufacturer",      "Google"},
    {"ro.product.vendor.device",            "oriole"},
    {"ro.product.vendor.name",              "oriole"},
    {"ro.product.odm.brand",               "google"},
    {"ro.product.odm.model",               "Pixel 6"},
    {"ro.product.odm.manufacturer",        "Google"},
    {"ro.product.odm.device",              "oriole"},
    {"ro.product.odm.name",                "oriole"},
    {"ro.product.first_api_level",          "31"},
    
    // Build Properties
    {"ro.build.display.id",                 "AP1A.240505.004"},
    {"ro.build.description",                "oriole-user 14 AP1A.240505.004 11583682 release-keys"},
    {"ro.build.fingerprint",                "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys"},
    {"ro.build.product",                    "oriole"},
    {"ro.build.type",                       "user"},
    {"ro.build.tags",                       "release-keys"},
    {"ro.build.id",                         "AP1A.240505.004"},
    {"ro.build.flavor",                     "oriole-user"},
    {"ro.build.host",                       "abfarm-release-rbe-64-00044"},
    {"ro.build.user",                       "android-build"},
    
    // Build Versions
    {"ro.build.version.sdk",                "34"},
    {"ro.build.version.release",            "14"},
    {"ro.build.version.release_or_codename","14"},
    {"ro.build.version.security_patch",     "2024-05-05"},
    {"ro.build.version.incremental",        "11583682"},
    {"ro.build.version.codename",           "REL"},
    {"ro.build.version.base_os",            ""},
    {"ro.build.version.preview_sdk",        "0"},
    
    // SoC
    {"ro.soc.manufacturer",                 "Google"},
    {"ro.soc.model",                        "Tensor"},
    
    // Bootloader & Baseband
    {"ro.bootimage.build.fingerprint",      "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys"},
    {"ro.vendor.build.fingerprint",         "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys"},
    {"ro.odm.build.fingerprint",            "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys"},
    {"ro.system.build.fingerprint",         "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys"},
    
    // Sentinel
    {nullptr, nullptr}
};

// ==============================================================================
// Hook: __system_property_get
// ==============================================================================

static int titan_hooked_system_property_get(const char* name, char* value) {
    if (!name || !value) {
        return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
    }
    
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofed[128] = {};
    
    // --- Identity Properties (aus Bridge) ---
    
    if (strcmp(name, "ro.serialno") == 0 || strcmp(name, "ro.boot.serialno") == 0) {
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 91); value[91] = '\0'; return (int)strlen(value); }
    }
    
    if (strstr(name, "gsf") || strcmp(name, "ro.com.google.gservices.gsf.id") == 0) {
        hw.getGsfId(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 91); value[91] = '\0'; return (int)strlen(value); }
    }
    
    if (strcmp(name, "gsm.baseband.imei") == 0 || strstr(name, "imei")) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 31); value[31] = '\0'; return (int)strlen(value); }
    }
    
    if (strstr(name, "wifimacaddr") || strstr(name, "wlan.driver.macaddr") || 
        strcmp(name, "ro.wlan.mac") == 0 || strcmp(name, "wifi.interface.mac") == 0) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 23); value[23] = '\0'; return (int)strlen(value); }
    }
    
    // IMEI via RIL Properties (TikTok libsscronet.so liest diese!)
    if (strcmp(name, "ro.ril.oem.imei") == 0 || strcmp(name, "ro.ril.oem.imei1") == 0 ||
        strcmp(name, "persist.radio.imei") == 0) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 31); value[31] = '\0'; return (int)strlen(value); }
    }
    if (strcmp(name, "ro.ril.oem.imei2") == 0 || strcmp(name, "persist.radio.imei2") == 0) {
        hw.getImei2(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 31); value[31] = '\0'; return (int)strlen(value); }
    }
    
    // --- Build Properties (hardcoded Pixel 6 Werte) ---
    
    for (int i = 0; PIXEL6_BUILD_PROPS[i].name != nullptr; i++) {
        if (strcmp(name, PIXEL6_BUILD_PROPS[i].name) == 0) {
            const char* override = PIXEL6_BUILD_PROPS[i].value;
            size_t len = strlen(override);
            if (len > 91) len = 91;
            memcpy(value, override, len);
            value[len] = '\0';
            // Nur bei erstem Treffer loggen (Performance)
            if (i == 0 || strstr(name, "fingerprint") || strstr(name, "display.id")) {
                LOGI("[TITAN] Property spoofed: %s = %s", name, value);
            }
            return (int)len;
        }
    }
    
    return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
}

// ==============================================================================
// Hook: getifaddrs (AF_PACKET MAC Spoofing)
// ==============================================================================

static int titan_hooked_getifaddrs(struct ifaddrs** ifap) {
    if (!g_origGetifaddrs) return -1;
    int result = g_origGetifaddrs(ifap);
    if (result != 0 || !ifap || !*ifap || !g_macParsed) return result;
    
    for (struct ifaddrs* ifa = *ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, "wlan0") != 0 && strcmp(ifa->ifa_name, "eth0") != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;
        
        struct sockaddr_ll* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen == 6) {
            memcpy(sll->sll_addr, g_spoofedMacBytes, 6);
            LOGI("[TITAN] Spoofed getifaddrs MAC for %s", ifa->ifa_name);
        }
    }
    return result;
}

// ==============================================================================
// Hook: ioctl (SIOCGIFHWADDR MAC Spoofing)
// ==============================================================================

static int titan_hooked_ioctl(int fd, unsigned long request, void* arg) {
    if (!g_origIoctl) return -1;
    
    // === MAC Spoofing: SIOCGIFHWADDR ===
    if (request == SIOCGIFHWADDR && arg && g_macParsed) {
        struct ifreq* ifr = static_cast<struct ifreq*>(arg);
        if (strcmp(ifr->ifr_name, "wlan0") == 0 || strcmp(ifr->ifr_name, "eth0") == 0) {
            int result = g_origIoctl(fd, request, arg);
            ifr->ifr_hwaddr.sa_family = 1; // ARPHRD_ETHER
            memcpy(ifr->ifr_hwaddr.sa_data, g_spoofedMacBytes, 6);
            return 0;
        }
    }
    
    // === Input Virtualizer: EVIOCGNAME ===
    // EVIOCGNAME hat type='E' (0x45), nr=0x06
    if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == 0x06 && arg) {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        auto it = g_inputEventFdMap.find(fd);
        if (it != g_inputEventFdMap.end()) {
            int eventNum = it->second;
            const char* devname = nullptr;
            for (int i = 0; PIXEL6_INPUT_EVENTS[i].filename != nullptr; i++) {
                // event0 -> 0, event1 -> 1, etc.
                char expected[16];
                snprintf(expected, sizeof(expected), "event%d", eventNum);
                if (strcmp(PIXEL6_INPUT_EVENTS[i].filename, expected) == 0) {
                    devname = PIXEL6_INPUT_EVENTS[i].devname;
                    break;
                }
            }
            if (devname) {
                int bufLen = (int)_IOC_SIZE(request);
                char* buf = static_cast<char*>(arg);
                if (bufLen > 0) {
                    strncpy(buf, devname, bufLen);
                    buf[bufLen - 1] = '\0';
                    return (int)strlen(devname);
                }
            }
        }
    }
    
    // === Input Virtualizer: EVIOCGID ===
    if (_IOC_TYPE(request) == 'E' && _IOC_NR(request) == 0x02 && arg) {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        auto it = g_inputEventFdMap.find(fd);
        if (it != g_inputEventFdMap.end()) {
            struct input_id* id = static_cast<struct input_id*>(arg);
            id->bustype = (it->second == 0) ? BUS_I2C : BUS_HOST;
            id->vendor  = 0x0000;
            id->product = 0x0000;
            id->version = 0x0000;
            return 0;
        }
    }
    
    return g_origIoctl(fd, request, arg);
}

// ==============================================================================
// Hook: recvmsg (Netlink RTM_NEWLINK MAC Spoofing - für libsscronet.so)
// ==============================================================================

static ssize_t titan_hooked_recvmsg(int sockfd, struct msghdr* msg, int flags) {
    if (!g_origRecvmsg) return -1;
    
    ssize_t result = g_origRecvmsg(sockfd, msg, flags);
    if (result <= 0 || !msg || !g_macParsed) return result;
    
    // Prüfe ob es ein Netlink Socket ist (via msg_name ODER tracked Sockets)
    bool isNetlink = false;
    if (msg->msg_name && msg->msg_namelen >= sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl* nladdr = static_cast<struct sockaddr_nl*>(msg->msg_name);
        if (nladdr->nl_family == AF_NETLINK) isNetlink = true;
    }
    
    // Auch getrackete Netlink-Sockets (von sendmsg RTM_GETLINK) abfangen
    if (!isNetlink) {
        std::lock_guard<std::mutex> lock(g_netlinkMutex);
        if (g_netlinkSockets.count(sockfd)) isNetlink = true;
    }
    
    if (!isNetlink) return result;
    
    // Parse Netlink Nachrichten und patch MAC in RTM_NEWLINK
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        char* data = static_cast<char*>(msg->msg_iov[i].iov_base);
        size_t len = msg->msg_iov[i].iov_len;
        
        // Suche nach Netlink Header
        struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(data);
        while (NLMSG_OK(nlh, len)) {
            if (nlh->nlmsg_type == RTM_NEWLINK) {
                struct ifinfomsg* ifi = static_cast<struct ifinfomsg*>(NLMSG_DATA(nlh));
                struct rtattr* rta = IFLA_RTA(ifi);
                int rtalen = IFLA_PAYLOAD(nlh);
                
                while (RTA_OK(rta, rtalen)) {
                    if (rta->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(rta) == 6) {
                        // MAC-Adresse gefunden - ersetzen!
                        memcpy(RTA_DATA(rta), g_spoofedMacBytes, 6);
                        LOGI("[TITAN] Spoofed Netlink RTM_NEWLINK MAC");
                    }
                    rta = RTA_NEXT(rta, rtalen);
                }
            }
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
    
    return result;
}

// ==============================================================================
// Hook: open (MAC File Shadowing)
// ==============================================================================

// Helper: Erstellt eine temporäre Datei via open() und gibt den FD zurück
static int createFakeOpenFd(const char* origPath, int flags, mode_t mode,
                             const char* content, size_t contentLen, const char* tag) {
    if (!g_origOpen) return -1;
    
    char tempPath[128];
    snprintf(tempPath, sizeof(tempPath), "/data/local/tmp/.titan_%s_%d", tag, getpid());
    
    int writeFd = g_origOpen(tempPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (writeFd >= 0) {
        write(writeFd, content, contentLen);
        close(writeFd);
        
        int fakeFd = g_origOpen(tempPath, flags & ~(O_WRONLY | O_CREAT | O_TRUNC), mode);
        if (fakeFd >= 0) {
            LOGI("[TITAN] open redirect: %s -> %s (fd=%d) [%s]", origPath, tempPath, fakeFd, tag);
            return fakeFd;
        }
    }
    return -1;
}

static int titan_hooked_open(const char* pathname, int flags, mode_t mode) {
    if (!g_origOpen) return -1;
    
    // Wenn MAC-Pfad, redirect zu Fake-Datei
    if (pathname && g_macParsed && isMacPath(pathname)) {
        LOGI("[TITAN] open() MAC path detected: %s", pathname);
        
        TitanHardware& hw = TitanHardware::getInstance();
        char macStr[24] = {};
        hw.getWifiMac(macStr, sizeof(macStr));
        
        if (macStr[0]) {
            char macContent[32];
            int len = snprintf(macContent, sizeof(macContent), "%s\n", macStr);
            int fakeFd = createFakeOpenFd(pathname, flags, mode, macContent, (size_t)len, "mac_open");
            if (fakeFd >= 0) return fakeFd;
        }
    }
    
    // Input Devices Pfad -> Fake Pixel 6 Device-Liste
    if (pathname && isInputDevicesPath(pathname)) {
        size_t contentLen = strlen(FAKE_INPUT_DEVICES);
        int fakeFd = createFakeOpenFd(pathname, flags, mode, FAKE_INPUT_DEVICES, contentLen, "input_open");
        if (fakeFd >= 0) {
            LOGI("[TITAN] open() input devices redirected: %s (fd=%d, %zu bytes)", pathname, fakeFd, contentLen);
            return fakeFd;
        }
    }
    
    // /proc/cpuinfo -> Fake Tensor G1 CPU-Info
    if (pathname && isCpuInfoPath(pathname)) {
        size_t contentLen = strlen(FAKE_CPUINFO);
        int fakeFd = createFakeOpenFd(pathname, flags, mode, FAKE_CPUINFO, contentLen, "cpuinfo");
        if (fakeFd >= 0) {
            LOGI("[TITAN] open() cpuinfo redirected (Tensor G1, %zu bytes)", contentLen);
            return fakeFd;
        }
    }
    
    // /proc/version -> Fake Kernel Version
    if (pathname && isKernelVersionPath(pathname)) {
        size_t contentLen = strlen(FAKE_KERNEL_VERSION);
        int fakeFd = createFakeOpenFd(pathname, flags, mode, FAKE_KERNEL_VERSION, contentLen, "version");
        if (fakeFd >= 0) return fakeFd;
    }
    
    // Phase 11.0: /proc/net/if_inet6 -> Fake (nur Loopback)
    if (pathname && isNetworkInfoPath(pathname)) {
        size_t contentLen = strlen(FAKE_IF_INET6);
        int fakeFd = createFakeOpenFd(pathname, flags, mode, FAKE_IF_INET6, contentLen, "if_inet6");
        if (fakeFd >= 0) return fakeFd;
    }
    
    // Phase 11.0: Root-Detection Pfade → Fake ENOENT
    if (pathname && isRootDetectionPath(pathname)) {
        errno = ENOENT;
        return -1;
    }
    
    // /dev/input/eventN -> Tracke FDs für EVIOCGNAME Virtualisierung
    if (pathname && strncmp(pathname, "/dev/input/event", 16) == 0) {
        int eventNum = atoi(pathname + 16);
        int fd = g_origOpen(pathname, flags, mode);
        if (fd >= 0) {
            std::lock_guard<std::mutex> lock(g_fdMapMutex);
            g_inputEventFdMap[fd] = eventNum;
        } else {
            // Wenn /dev/input/eventN nicht existiert, simuliere es
            // indem wir /dev/null öffnen und den FD tracken
            bool isFakeEvent = false;
            for (int i = 0; PIXEL6_INPUT_EVENTS[i].filename != nullptr; i++) {
                char expected[16];
                snprintf(expected, sizeof(expected), "event%d", eventNum);
                if (strcmp(PIXEL6_INPUT_EVENTS[i].filename, expected) == 0) {
                    isFakeEvent = true;
                    break;
                }
            }
            if (isFakeEvent) {
                fd = g_origOpen("/dev/null", O_RDONLY, 0);
                if (fd >= 0) {
                    std::lock_guard<std::mutex> lock(g_fdMapMutex);
                    g_inputEventFdMap[fd] = eventNum;
                }
            }
        }
        return fd;
    }
    
    return g_origOpen(pathname, flags, mode);
}

// ==============================================================================
// Hook: read (MAC File Content Injection)
// ==============================================================================

static ssize_t titan_hooked_read(int fd, void* buf, size_t count) {
    if (!g_origRead) return -1;
    
    bool isMacFd = false;
    {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        isMacFd = (g_macFileFds.find(fd) != g_macFileFds.end());
    }
    
    if (isMacFd && buf && count > 0 && g_macParsed) {
        TitanHardware& hw = TitanHardware::getInstance();
        char macStr[24] = {};
        hw.getWifiMac(macStr, sizeof(macStr));
        
        if (macStr[0]) {
            char macWithNewline[32];
            snprintf(macWithNewline, sizeof(macWithNewline), "%s\n", macStr);
            size_t len = strlen(macWithNewline);
            size_t copyLen = (count < len) ? count : len;
            memcpy(buf, macWithNewline, copyLen);
            
            LOGI("[TITAN] Spoofed read() for MAC fd %d -> %s", fd, macStr);
            
            // Remove from tracking
            {
                std::lock_guard<std::mutex> lock(g_fdMapMutex);
                g_macFileFds.erase(fd);
            }
            
            return (ssize_t)copyLen;
        }
    }
    
    return g_origRead(fd, buf, count);
}

// ==============================================================================
// Hook: fopen (für std::ifstream) - Direct MAC Spoofing
// ==============================================================================

// Helper: Erstellt eine temporäre Datei mit beliebigem Inhalt
static FILE* createFakeFopen(const char* origPath, const char* mode, 
                              const char* content, const char* tag) {
    if (!g_origFopen) return nullptr;
    
    char tempPath[128];
    snprintf(tempPath, sizeof(tempPath), "/data/local/tmp/.titan_%s_%d", tag, getpid());
    
    FILE* tempFp = g_origFopen(tempPath, "w");
    if (tempFp) {
        fputs(content, tempFp);
        fclose(tempFp);
        
        FILE* fakeFp = g_origFopen(tempPath, mode);
        if (fakeFp) {
            LOGI("[TITAN] fopen redirect: %s -> %s [%s]", origPath, tempPath, tag);
            return fakeFp;
        }
    }
    return nullptr;
}

static FILE* titan_hooked_fopen(const char* pathname, const char* mode) {
    if (!g_origFopen) return nullptr;
    
    // MAC-Pfad -> Fake-MAC-Datei
    if (pathname && g_macParsed && isMacPath(pathname)) {
        TitanHardware& hw = TitanHardware::getInstance();
        char macStr[24] = {};
        hw.getWifiMac(macStr, sizeof(macStr));
        
        if (macStr[0]) {
            char macContent[32];
            snprintf(macContent, sizeof(macContent), "%s\n", macStr);
            FILE* fake = createFakeFopen(pathname, mode, macContent, "mac");
            if (fake) return fake;
        }
    }
    
    // Input Devices -> Fake Pixel 6 Device-Liste
    if (pathname && isInputDevicesPath(pathname)) {
        FILE* fake = createFakeFopen(pathname, mode, FAKE_INPUT_DEVICES, "input");
        if (fake) return fake;
    }
    
    // /proc/cpuinfo -> Fake Tensor G1
    if (pathname && isCpuInfoPath(pathname)) {
        FILE* fake = createFakeFopen(pathname, mode, FAKE_CPUINFO, "cpuinfo");
        if (fake) return fake;
    }
    
    // /proc/version -> Fake Kernel Version
    if (pathname && isKernelVersionPath(pathname)) {
        FILE* fake = createFakeFopen(pathname, mode, FAKE_KERNEL_VERSION, "version");
        if (fake) return fake;
    }
    
    // Phase 11.0: /proc/net/if_inet6 -> Fake (nur Loopback)
    if (pathname && isNetworkInfoPath(pathname)) {
        FILE* fake = createFakeFopen(pathname, mode, FAKE_IF_INET6, "if_inet6");
        if (fake) return fake;
    }
    
    // Phase 11.0: Root-Detection Pfade → null + ENOENT
    if (pathname && isRootDetectionPath(pathname)) {
        errno = ENOENT;
        return nullptr;
    }
    
    return g_origFopen(pathname, mode);
}

// ==============================================================================
// Hook: fgets (für std::ifstream getline)
// ==============================================================================

static char* titan_hooked_fgets(char* s, int size, FILE* stream) {
    if (!g_origFgets) return nullptr;
    
    bool isMacStream = false;
    {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        isMacStream = (g_macFileStreams.find(stream) != g_macFileStreams.end());
    }
    
    if (isMacStream && s && size > 0 && g_macParsed) {
        TitanHardware& hw = TitanHardware::getInstance();
        char macStr[24] = {};
        hw.getWifiMac(macStr, sizeof(macStr));
        
        if (macStr[0]) {
            snprintf(s, size, "%s\n", macStr);
            LOGI("[TITAN] Spoofed fgets() for MAC stream -> %s", macStr);
            
            // Remove from tracking
            {
                std::lock_guard<std::mutex> lock(g_fdMapMutex);
                g_macFileStreams.erase(stream);
            }
            
            return s;
        }
    }
    
    return g_origFgets(s, size, stream);
}

// ==============================================================================
// Hook: Widevine NDK API (AMediaDrm) - Phase 9.0 Full HAL Mocking
// ==============================================================================

static void parseWidevineHex() {
    if (g_widevineParsed) return;
    
    // Versuche erst Bridge-Wert
    TitanHardware& hw = TitanHardware::getInstance();
    char widevineBuf[64] = {};
    hw.getWidevineId(widevineBuf, sizeof(widevineBuf));
    
    const char* hexStr = widevineBuf[0] ? widevineBuf : MASTER_WIDEVINE_HEX;
    
    for (int i = 0; i < 16 && hexStr[i*2] && hexStr[i*2+1]; i++) {
        char byte[3] = { hexStr[i*2], hexStr[i*2+1], 0 };
        g_widevineBytes[i] = (uint8_t)strtol(byte, nullptr, 16);
    }
    
    g_widevineParsed = true;
    LOGI("[TITAN] Widevine ID parsed: %02x%02x%02x%02x...", 
         g_widevineBytes[0], g_widevineBytes[1], g_widevineBytes[2], g_widevineBytes[3]);
}

static bool isFakeDrm(AMediaDrm* drm) {
    std::lock_guard<std::mutex> lock(g_fdMapMutex);
    return g_fakeDrmObjects.find(drm) != g_fakeDrmObjects.end();
}

// Hook: AMediaDrm_createByUUID - Das Herzstück des HAL-Mockings
static AMediaDrm* titan_hooked_AMediaDrm_createByUUID(const uint8_t uuid[16]) {
    // Versuche erst Original
    AMediaDrm* drm = nullptr;
    if (g_origAMediaDrmCreateByUUID) {
        drm = g_origAMediaDrmCreateByUUID(uuid);
    }
    
    // Wenn Original erfolgreich, nutze es
    if (drm != nullptr) {
        LOGI("[TITAN] AMediaDrm_createByUUID -> Real DRM object");
        return drm;
    }
    
    // HAL defekt? Erstelle Fake-Objekt für Widevine
    if (memcmp(uuid, WIDEVINE_UUID, 16) == 0) {
        // Allokiere echten Speicher (calloc = Nullen) statt 0xDEAD Pointer
        // So crasht die echte getPropertyByteArray nicht, sondern gibt INVALID_OBJECT zurück
        AMediaDrm* fakeDrm = reinterpret_cast<AMediaDrm*>(calloc(1, 256));
        
        {
            std::lock_guard<std::mutex> lock(g_fdMapMutex);
            g_fakeDrmObjects.insert(fakeDrm);
        }
        
        LOGI("[TITAN] AMediaDrm_createByUUID(Widevine) -> Fake DRM object %p (HAL mocked)", fakeDrm);
        return fakeDrm;
    }
    
    LOGW("[TITAN] AMediaDrm_createByUUID -> Failed (non-Widevine UUID)");
    return nullptr;
}

// Hook: AMediaDrm_release
static void titan_hooked_AMediaDrm_release(AMediaDrm* drm) {
    if (isFakeDrm(drm)) {
        {
            std::lock_guard<std::mutex> lock(g_fdMapMutex);
            g_fakeDrmObjects.erase(drm);
        }
        free(drm); // calloc'd Speicher freigeben
        LOGI("[TITAN] AMediaDrm_release(Fake) -> freed");
        return;
    }
    
    if (g_origAMediaDrmRelease) {
        g_origAMediaDrmRelease(drm);
    }
}

// Hook: AMediaDrm_getPropertyByteArray (Phase 9.5 - KORREKTE Signatur!)
// Die NDK-API nutzt AMediaDrmByteArray* (struct mit ptr + length), NICHT uint8_t** + size_t*!
static media_status_t titan_hooked_AMediaDrm_getPropertyByteArray(
    AMediaDrm* drm, const char* propertyName, TitanDrmByteArray* propertyValue) {
    
    if (!propertyName || !propertyValue) {
        return AMEDIA_DRM_NOT_PROVISIONED;
    }
    
    bool isFake = isFakeDrm(drm);
    bool isDeviceId = (strcmp(propertyName, "deviceUniqueId") == 0);
    
    if (isFake || isDeviceId) {
        parseWidevineHex();
        
        // Statischer Buffer - kein malloc nötig, NDK managed den Speicher
        static uint8_t s_widevineResult[16];
        memcpy(s_widevineResult, g_widevineBytes, 16);
        
        propertyValue->ptr = s_widevineResult;
        propertyValue->length = 16;
        
        LOGI("[TITAN] AMediaDrm_getPropertyByteArray(%s) -> Spoofed 16 bytes [%s DRM]", 
             propertyName, isFake ? "Fake" : "Real");
        return AMEDIA_OK;
    }
    
    // Echtes DRM-Objekt mit nicht-device Property -> Original aufrufen
    if (!isFake && g_origAMediaDrmGetPropertyByteArray) {
        return g_origAMediaDrmGetPropertyByteArray(drm, propertyName, propertyValue);
    }
    
    return AMEDIA_DRM_NOT_PROVISIONED;
}

// Hook: AMediaDrm_getPropertyString
static media_status_t titan_hooked_AMediaDrm_getPropertyString(
    AMediaDrm* drm, const char* propertyName, const char** propertyValue) {
    
    if (!propertyName || !propertyValue) {
        return AMEDIA_DRM_NOT_PROVISIONED;
    }
    
    bool isFake = isFakeDrm(drm);
    
    // Standard-Properties für Fake-DRM
    if (isFake) {
        if (strcmp(propertyName, "vendor") == 0) {
            *propertyValue = strdup("Google");
            return AMEDIA_OK;
        }
        if (strcmp(propertyName, "version") == 0) {
            *propertyValue = strdup("16.0.0");
            return AMEDIA_OK;
        }
        if (strcmp(propertyName, "algorithms") == 0) {
            *propertyValue = strdup("AES/CBC/NoPadding");
            return AMEDIA_OK;
        }
        
        LOGI("[TITAN] AMediaDrm_getPropertyString(%s) -> Fake default", propertyName);
        *propertyValue = strdup("");
        return AMEDIA_OK;
    }
    
    // Echtes DRM
    if (g_origAMediaDrmGetPropertyString) {
        return g_origAMediaDrmGetPropertyString(drm, propertyName, propertyValue);
    }
    
    return AMEDIA_DRM_NOT_PROVISIONED;
}

// Hook: AMediaDrm_isCryptoSchemeSupported
static bool titan_hooked_AMediaDrm_isCryptoSchemeSupported(const uint8_t uuid[16], const char* mimeType) {
    // Widevine UUID IMMER unterstützen
    if (memcmp(uuid, WIDEVINE_UUID, 16) == 0) {
        LOGI("[TITAN] AMediaDrm_isCryptoSchemeSupported(Widevine) -> true (forced)");
        return true;
    }
    
    return g_origAMediaDrmIsCryptoSchemeSupported ?
           g_origAMediaDrmIsCryptoSchemeSupported(uuid, mimeType) : false;
}

// ==============================================================================
// Hook: opendir/readdir (/dev/input/ Virtualisierung)
// ==============================================================================

static DIR* titan_hooked_opendir(const char* name) {
    if (!g_origOpendir) return nullptr;
    DIR* dir = g_origOpendir(name);
    
    if (name && (strcmp(name, "/dev/input") == 0 || strcmp(name, "/dev/input/") == 0)) {
        if (dir) {
            std::lock_guard<std::mutex> lock(g_fdMapMutex);
            g_inputDirHandles.insert(dir);
            g_inputDirFakeIdx[dir] = -1; // -1 = erst Original-Entries liefern
        } else {
            // /dev/input/ existiert nicht oder kein Zugriff -> rein virtuell
            dir = g_origOpendir("/proc");  // Öffne irgendein Dir als Handle
            if (dir) {
                std::lock_guard<std::mutex> lock(g_fdMapMutex);
                g_inputDirHandles.insert(dir);
                g_inputDirFakeIdx[dir] = 0;  // 0 = sofort Fake-Entries
            }
        }
    }
    return dir;
}

// Statische dirent-Struktur für Fake-Entries
static struct dirent g_fakeDirent;

static struct dirent* titan_hooked_readdir(DIR* dirp) {
    if (!g_origReaddir) return nullptr;
    
    {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        auto it = g_inputDirHandles.find(dirp);
        if (it != g_inputDirHandles.end()) {
            auto& idx = g_inputDirFakeIdx[dirp];
            
            // Zuerst Original-Entries liefern (. und ..)
            if (idx < 0) {
                struct dirent* real = g_origReaddir(dirp);
                if (real) return real;
                idx = 0; // Original erschöpft, starte Fake-Entries
            }
            
            // Dann unsere Fake-Event-Devices
            if (PIXEL6_INPUT_EVENTS[idx].filename != nullptr) {
                memset(&g_fakeDirent, 0, sizeof(g_fakeDirent));
                g_fakeDirent.d_ino = 1000 + idx;
                g_fakeDirent.d_type = DT_CHR;  // Character Device
                strncpy(g_fakeDirent.d_name, PIXEL6_INPUT_EVENTS[idx].filename, sizeof(g_fakeDirent.d_name) - 1);
                idx++;
                return &g_fakeDirent;
            }
            
            return nullptr; // Ende der Liste
        }
    }
    
    return g_origReaddir(dirp);
}

static int titan_hooked_closedir(DIR* dirp) {
    {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        g_inputDirHandles.erase(dirp);
        g_inputDirFakeIdx.erase(dirp);
    }
    return g_origClosedir ? g_origClosedir(dirp) : -1;
}

// ==============================================================================
// Direct Memory Property Patching (Phase 12 - System Transmutation)
// 
// Statt __system_property_get zu hooken (detektierbar!), remappen wir die
// Property-Memory-Area als MAP_PRIVATE und patchen die Werte direkt im RAM.
// Jede App sieht dann den Fake-Wert über JEDE API (getprop, native, Java).
// ==============================================================================

// __system_property_find - libc Symbol
using SystemPropertyFindFn = const void* (*)(const char*);
static SystemPropertyFindFn g_sysPropFind = nullptr;

// __system_property_read_callback - neuere API (Android 8+)
using SystemPropertyReadCallbackFn = void (*)(
    const void* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie);
static SystemPropertyReadCallbackFn g_origPropReadCallback = nullptr;

/**
 * Phase 1: Privatize Property Mappings
 * 
 * Scannt /proc/self/maps nach __properties__ Regionen und ersetzt
 * die MAP_SHARED Mappings durch MAP_PRIVATE Kopien.
 * Danach sind Schreibzugriffe nur noch prozess-lokal sichtbar.
 */
static int g_privatizedRegions = 0;

static void privatizePropertyMappings() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGW("[TITAN-MEM] Cannot open /proc/self/maps");
        return;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, "__properties__")) continue;
        
        // Parse: start-end perms offset dev inode pathname
        uintptr_t start = 0, end = 0;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        
        size_t size = end - start;
        if (size == 0 || size > 2 * 1024 * 1024) continue; // Safety: max 2MB
        
        // Backup der Originaldaten
        void* backup = malloc(size);
        if (!backup) continue;
        memcpy(backup, (void*)start, size);
        
        // Re-map als MAP_PRIVATE|MAP_ANONYMOUS (ersetzt MAP_SHARED)
        // MAP_FIXED überschreibt das bestehende Mapping an derselben Adresse
        void* newMap = mmap((void*)start, size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (newMap == MAP_FAILED) {
            free(backup);
            LOGW("[TITAN-MEM] mmap failed for %lx-%lx (errno=%d)", start, end, errno);
            continue;
        }
        
        // Originaldaten wiederherstellen (jetzt in privater Kopie)
        memcpy(newMap, backup, size);
        free(backup);
        
        // Read-Only setzen (wird beim Patchen temporär aufgehoben)
        mprotect(newMap, size, PROT_READ);
        
        g_privatizedRegions++;
        LOGI("[TITAN-MEM] Privatized: %lx-%lx (%zu bytes) [%s]", start, end, size, perms);
    }
    
    fclose(maps);
    LOGI("[TITAN-MEM] Privatized %d property regions", g_privatizedRegions);
}

/**
 * Phase 2: Patch einzelne Properties im privatisierten Speicher
 * 
 * prop_info Layout (Android 14):
 *   [uint32_t serial] [char value[92]] [char name[...]]
 *   Offset 0: serial (atomic, Bit 0 = dirty flag)
 *   Offset 4: value (max 91 chars + null)
 */
static bool patchPropertyDirect(const char* name, const char* newValue) {
    if (!g_sysPropFind) {
        void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (libc) {
            g_sysPropFind = (SystemPropertyFindFn)dlsym(libc, "__system_property_find");
        }
    }
    if (!g_sysPropFind) return false;
    
    const void* pi = g_sysPropFind(name);
    if (!pi) return false;
    
    // Value-Pointer: 4 Bytes nach prop_info Start (nach uint32_t serial)
    char* valuePtr = ((char*)pi) + sizeof(uint32_t);
    
    // Seiten-Grenzen berechnen für mprotect
    size_t pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t pageStart = (uintptr_t)valuePtr & ~(pageSize - 1);
    size_t regionSize = pageSize * 2; // 2 Seiten für Sicherheit
    
    // Temporär beschreibbar machen
    if (mprotect((void*)pageStart, regionSize, PROT_READ | PROT_WRITE) != 0) {
        LOGW("[TITAN-MEM] mprotect WRITE failed for %s (errno=%d)", name, errno);
        return false;
    }
    
    // Wert patchen
    size_t len = strlen(newValue);
    if (len > 91) len = 91;
    memcpy(valuePtr, newValue, len);
    valuePtr[len] = '\0';
    
    // Serial aktualisieren (atomic increment, low bit = dirty cleared)
    uint32_t* serialPtr = (uint32_t*)pi;
    uint32_t curSerial = __atomic_load_n(serialPtr, __ATOMIC_RELAXED);
    __atomic_store_n(serialPtr, (curSerial | 1) + 1, __ATOMIC_RELEASE);
    
    // Wieder Read-Only
    mprotect((void*)pageStart, regionSize, PROT_READ);
    
    return true;
}

/**
 * Phase 3: Alle Identity-Properties im RAM patchen
 * 
 * Wird VOR installAllHooks() aufgerufen, damit die Werte bereits
 * im Speicher liegen bevor irgendein Hook aktiv ist.
 */
static void patchAllPropertiesInMemory() {
    if (g_privatizedRegions == 0) {
        LOGW("[TITAN-MEM] No privatized regions - skipping memory patching");
        return;
    }
    
    TitanHardware& hw = TitanHardware::getInstance();
    int patched = 0;
    
    // Identity Properties aus Bridge
    char buf[128];
    
    hw.getSerial(buf, sizeof(buf));
    if (buf[0]) {
        if (patchPropertyDirect("ro.serialno", buf)) patched++;
        if (patchPropertyDirect("ro.boot.serialno", buf)) patched++;
    }
    
    hw.getImei1(buf, sizeof(buf));
    if (buf[0]) {
        if (patchPropertyDirect("ro.ril.oem.imei", buf)) patched++;
        if (patchPropertyDirect("ro.ril.oem.imei1", buf)) patched++;
        if (patchPropertyDirect("persist.radio.imei", buf)) patched++;
        if (patchPropertyDirect("gsm.baseband.imei", buf)) patched++;
    }
    
    hw.getImei2(buf, sizeof(buf));
    if (buf[0]) {
        if (patchPropertyDirect("ro.ril.oem.imei2", buf)) patched++;
        if (patchPropertyDirect("persist.radio.imei2", buf)) patched++;
    }
    
    hw.getWifiMac(buf, sizeof(buf));
    if (buf[0]) {
        if (patchPropertyDirect("ro.wlan.mac", buf)) patched++;
        if (patchPropertyDirect("wifi.interface.mac", buf)) patched++;
    }
    
    // Build Properties (hardcoded Pixel 6)
    for (int i = 0; PIXEL6_BUILD_PROPS[i].name != nullptr; i++) {
        if (patchPropertyDirect(PIXEL6_BUILD_PROPS[i].name, PIXEL6_BUILD_PROPS[i].value)) {
            patched++;
        }
    }
    
    LOGI("[TITAN-MEM] Direct memory patched: %d properties (NO HOOKS NEEDED for these!)", patched);
}

// ==============================================================================
// Hook: __system_property_read_callback (Belt & Suspenders)
// Deckt den neueren API-Pfad ab, den manche Apps statt __system_property_get nutzen
// ==============================================================================

struct PropReadCookieOverride {
    void (*origCallback)(void*, const char*, const char*, uint32_t);
    void* origCookie;
    const char* overrideValue;
};

static void titanPropReadCallbackShim(void* cookie, const char* name, const char* value, uint32_t serial) {
    PropReadCookieOverride* ctx = static_cast<PropReadCookieOverride*>(cookie);
    // Liefere den Override-Wert statt des Original-Werts
    ctx->origCallback(ctx->origCookie, name, ctx->overrideValue, serial);
}

static void titan_hooked_prop_read_callback(
    const void* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie) {
    
    if (!pi || !callback || !g_origPropReadCallback) {
        if (g_origPropReadCallback) g_origPropReadCallback(pi, callback, cookie);
        return;
    }
    
    // Lese zuerst den echten Wert um den Property-Namen zu bekommen
    struct { const char* name; const char* value; } captured = {nullptr, nullptr};
    
    g_origPropReadCallback(pi, [](void* cookie, const char* name, const char* value, uint32_t serial) {
        auto* c = static_cast<decltype(captured)*>(cookie);
        c->name = name;
        c->value = value;
    }, &captured);
    
    if (!captured.name) {
        g_origPropReadCallback(pi, callback, cookie);
        return;
    }
    
    // Prüfe ob wir diesen Wert überschreiben wollen
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofed[128] = {};
    const char* overrideVal = nullptr;
    
    if (strcmp(captured.name, "ro.serialno") == 0 || strcmp(captured.name, "ro.boot.serialno") == 0) {
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0]) overrideVal = spoofed;
    } else if (strstr(captured.name, "imei") || strcmp(captured.name, "gsm.baseband.imei") == 0) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) overrideVal = spoofed;
    } else if (strstr(captured.name, "wlan.mac") || strstr(captured.name, "wifimacaddr")) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0]) overrideVal = spoofed;
    } else {
        // Build Properties checken
        for (int i = 0; PIXEL6_BUILD_PROPS[i].name != nullptr; i++) {
            if (strcmp(captured.name, PIXEL6_BUILD_PROPS[i].name) == 0) {
                overrideVal = PIXEL6_BUILD_PROPS[i].value;
                break;
            }
        }
    }
    
    if (overrideVal) {
        // Liefere unseren Override-Wert
        callback(cookie, captured.name, overrideVal, 0);
    } else {
        // Original durchleiten
        g_origPropReadCallback(pi, callback, cookie);
    }
}

// ==============================================================================
// Hook: __system_property_read (Ältere API - von manchen NDK-Libraries genutzt)
// ==============================================================================

static int titan_hooked_system_property_read(const void* pi, char* name, char* value) {
    if (!g_origSysPropRead) return -1;
    
    // Original aufrufen um den echten Namen und Wert zu bekommen
    int result = g_origSysPropRead(pi, name, value);
    
    if (!name || !value) return result;
    
    // Identity Properties aus der Bridge
    TitanHardware& hw = TitanHardware::getInstance();
    char spoofed[128] = {};
    
    if (strcmp(name, "ro.serialno") == 0 || strcmp(name, "ro.boot.serialno") == 0) {
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 91); value[91] = '\0'; return (int)strlen(value); }
    }
    
    if (strstr(name, "gsf") || strcmp(name, "ro.com.google.gservices.gsf.id") == 0) {
        hw.getGsfId(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 91); value[91] = '\0'; return (int)strlen(value); }
    }
    
    if (strcmp(name, "gsm.baseband.imei") == 0 || strstr(name, "imei")) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 31); value[31] = '\0'; return (int)strlen(value); }
    }
    
    if (strstr(name, "wifimacaddr") || strstr(name, "wlan.driver.macaddr") || 
        strcmp(name, "ro.wlan.mac") == 0 || strcmp(name, "wifi.interface.mac") == 0) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 23); value[23] = '\0'; return (int)strlen(value); }
    }
    
    if (strcmp(name, "ro.ril.oem.imei") == 0 || strcmp(name, "ro.ril.oem.imei1") == 0 ||
        strcmp(name, "persist.radio.imei") == 0) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 31); value[31] = '\0'; return (int)strlen(value); }
    }
    if (strcmp(name, "ro.ril.oem.imei2") == 0 || strcmp(name, "persist.radio.imei2") == 0) {
        hw.getImei2(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 31); value[31] = '\0'; return (int)strlen(value); }
    }
    
    // Build Properties (hardcoded Pixel 6 Werte)
    for (int i = 0; PIXEL6_BUILD_PROPS[i].name != nullptr; i++) {
        if (strcmp(name, PIXEL6_BUILD_PROPS[i].name) == 0) {
            const char* override = PIXEL6_BUILD_PROPS[i].value;
            size_t len = strlen(override);
            if (len > 91) len = 91;
            memcpy(value, override, len);
            value[len] = '\0';
            return (int)len;
        }
    }
    
    return result;
}

// ==============================================================================
// Hook: sendmsg (Netlink RTM_GETLINK Request Tracking + Response MAC Patching)
// ==============================================================================
// TikToks libsscronet.so nutzt sendmsg um RTM_GETLINK Requests zu senden.
// Wir tracken Netlink Sockets und stellen sicher, dass auch sendmsg-Responses
// durch unseren recvmsg Hook laufen. Zusätzlich patchen wir RTM_NEWLINK
// Messages die als Antwort auf RTM_GETLINK direkt im sendmsg-Kontext
// als embedded Responses mitgeliefert werden können.

static ssize_t titan_hooked_sendmsg(int sockfd, const struct msghdr* msg, int flags) {
    if (!g_origSendmsg) return -1;
    
    // Tracke Netlink Sockets (AF_NETLINK)
    if (msg && msg->msg_name && msg->msg_namelen >= sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl* nladdr = static_cast<struct sockaddr_nl*>(msg->msg_name);
        if (nladdr->nl_family == AF_NETLINK) {
            // Parse die Nachricht - wenn RTM_GETLINK, tracke den Socket
            for (size_t i = 0; i < msg->msg_iovlen && msg->msg_iov; i++) {
                char* data = static_cast<char*>(msg->msg_iov[i].iov_base);
                size_t len = msg->msg_iov[i].iov_len;
                if (len >= sizeof(struct nlmsghdr)) {
                    struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(data);
                    if (nlh->nlmsg_type == RTM_GETLINK) {
                        std::lock_guard<std::mutex> lock(g_netlinkMutex);
                        g_netlinkSockets.insert(sockfd);
                        LOGI("[TITAN] Tracked RTM_GETLINK socket fd=%d (MAC will be spoofed on response)", sockfd);
                    }
                }
            }
        }
    }
    
    return g_origSendmsg(sockfd, msg, flags);
}

// ==============================================================================
// Atomicity Check: Cross-Layer Integrity Verification
// ==============================================================================

static bool verifyIdentityAtomicity() {
    TitanHardware& hw = TitanHardware::getInstance();
    
    char serial[128] = {}, mac[24] = {}, imei1[32] = {};
    hw.getSerial(serial, sizeof(serial));
    hw.getWifiMac(mac, sizeof(mac));
    hw.getImei1(imei1, sizeof(imei1));
    
    if (!serial[0] || !mac[0] || !imei1[0]) {
        LOGW("[TITAN] Atomicity FAIL: Missing identity (serial=%s, mac=%s, imei=%s)", 
             serial, mac, imei1);
        return false;
    }
    
    // Prüfe Property-Synchronisation
    if (g_origSystemPropertyGet) {
        char propSerial[128] = {};
        g_origSystemPropertyGet("ro.serialno", propSerial);
        // Original-Property sollte NICHT unserem Spoofed-Wert entsprechen (noch nicht gehookt)
        // Nach dem Hook muss sie identisch sein
    }
    
    LOGI("[TITAN] Atomicity OK: Serial=%s MAC=%s IMEI=%s", serial, mac, imei1);
    return true;
}

// ==============================================================================
// Hook Installation
// ==============================================================================

static void installAllHooks() {
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) {
        LOGE("[TITAN] Failed to open libc");
        return;
    }
    
    int installed = 0;
    
#ifdef USE_DOBBY
    // __system_property_get
    void* propAddr = dlsym(libc, "__system_property_get");
    if (propAddr && DobbyHook(propAddr, (dobby_dummy_func_t)titan_hooked_system_property_get, 
                              (dobby_dummy_func_t*)&g_origSystemPropertyGet) == 0) {
        installed++;
        LOGI("[TITAN] Property hook OK");
    }
    
    // __system_property_read_callback (neuere API, ab Android 8)
    void* propReadCbAddr = dlsym(libc, "__system_property_read_callback");
    if (propReadCbAddr && DobbyHook(propReadCbAddr, (dobby_dummy_func_t)titan_hooked_prop_read_callback,
                                     (dobby_dummy_func_t*)&g_origPropReadCallback) == 0) {
        installed++;
        LOGI("[TITAN] __system_property_read_callback hook OK");
    }
    
    // __system_property_read (ältere API - manche NDK Libs nutzen diese statt _get)
    void* propReadAddr = dlsym(libc, "__system_property_read");
    if (propReadAddr && DobbyHook(propReadAddr, (dobby_dummy_func_t)titan_hooked_system_property_read,
                                   (dobby_dummy_func_t*)&g_origSysPropRead) == 0) {
        installed++;
        LOGI("[TITAN] __system_property_read (legacy) hook OK");
    }
    
    // sendmsg (Netlink RTM_GETLINK Tracking)
    void* sendmsgAddr = dlsym(libc, "sendmsg");
    if (sendmsgAddr && DobbyHook(sendmsgAddr, (dobby_dummy_func_t)titan_hooked_sendmsg,
                                  (dobby_dummy_func_t*)&g_origSendmsg) == 0) {
        installed++;
        LOGI("[TITAN] sendmsg (Netlink) hook OK");
    }
    
    // getifaddrs
    void* getifaddrsAddr = dlsym(libc, "getifaddrs");
    if (getifaddrsAddr && DobbyHook(getifaddrsAddr, (dobby_dummy_func_t)titan_hooked_getifaddrs,
                                    (dobby_dummy_func_t*)&g_origGetifaddrs) == 0) {
        installed++;
        LOGI("[TITAN] getifaddrs hook OK");
    }
    
    // ioctl
    void* ioctlAddr = dlsym(libc, "ioctl");
    if (ioctlAddr && DobbyHook(ioctlAddr, (dobby_dummy_func_t)titan_hooked_ioctl,
                               (dobby_dummy_func_t*)&g_origIoctl) == 0) {
        installed++;
        LOGI("[TITAN] ioctl hook OK");
    }
    
    // recvmsg (Netlink)
    void* recvmsgAddr = dlsym(libc, "recvmsg");
    if (recvmsgAddr && DobbyHook(recvmsgAddr, (dobby_dummy_func_t)titan_hooked_recvmsg,
                                 (dobby_dummy_func_t*)&g_origRecvmsg) == 0) {
        installed++;
        LOGI("[TITAN] recvmsg (Netlink) hook OK");
    }
    
    // open
    void* openAddr = dlsym(libc, "open");
    if (openAddr && DobbyHook(openAddr, (dobby_dummy_func_t)titan_hooked_open,
                              (dobby_dummy_func_t*)&g_origOpen) == 0) {
        installed++;
        LOGI("[TITAN] open hook OK");
    }
    
    // read
    void* readAddr = dlsym(libc, "read");
    if (readAddr && DobbyHook(readAddr, (dobby_dummy_func_t)titan_hooked_read,
                              (dobby_dummy_func_t*)&g_origRead) == 0) {
        installed++;
        LOGI("[TITAN] read hook OK");
    }
    
    // fopen (für std::ifstream)
    void* fopenAddr = dlsym(libc, "fopen");
    if (fopenAddr && DobbyHook(fopenAddr, (dobby_dummy_func_t)titan_hooked_fopen,
                               (dobby_dummy_func_t*)&g_origFopen) == 0) {
        installed++;
        LOGI("[TITAN] fopen hook OK");
    }
    
    // fgets (für std::ifstream getline)
    void* fgetsAddr = dlsym(libc, "fgets");
    if (fgetsAddr && DobbyHook(fgetsAddr, (dobby_dummy_func_t)titan_hooked_fgets,
                               (dobby_dummy_func_t*)&g_origFgets) == 0) {
        installed++;
        LOGI("[TITAN] fgets hook OK");
    }
    
    // opendir (Input Virtualizer)
    void* opendirAddr = dlsym(libc, "opendir");
    if (opendirAddr && DobbyHook(opendirAddr, (dobby_dummy_func_t)titan_hooked_opendir,
                                  (dobby_dummy_func_t*)&g_origOpendir) == 0) {
        installed++;
        LOGI("[TITAN] opendir hook OK");
    }
    
    // readdir (Input Virtualizer)
    void* readdirAddr = dlsym(libc, "readdir");
    if (readdirAddr && DobbyHook(readdirAddr, (dobby_dummy_func_t)titan_hooked_readdir,
                                  (dobby_dummy_func_t*)&g_origReaddir) == 0) {
        installed++;
        LOGI("[TITAN] readdir hook OK");
    }
    
    // closedir (Input Virtualizer cleanup)
    void* closedirAddr = dlsym(libc, "closedir");
    if (closedirAddr && DobbyHook(closedirAddr, (dobby_dummy_func_t)titan_hooked_closedir,
                                   (dobby_dummy_func_t*)&g_origClosedir) == 0) {
        installed++;
        LOGI("[TITAN] closedir hook OK");
    }
    
    // Widevine NDK Hooks - Phase 9.5 SAFE
    // WICHTIG: getPropertyByteArray und getPropertyString NICHT hooken!
    // Dobby's Trampolin korrumpiert diese Funktionen (SIGILL).
    // Stattdessen: createByUUID gibt calloc-Fake zurück → echte getPropertyByteArray
    // sieht mDrm==NULL → gibt INVALID_OBJECT zurück (kein Crash).
    // Widevine Spoofing erfolgt über LSPosed (Java-Layer).
    void* mediandk = dlopen("libmediandk.so", RTLD_NOW | RTLD_NOLOAD);
    if (!mediandk) {
        mediandk = dlopen("libmediandk.so", RTLD_NOW);
    }
    
    if (mediandk) {
        // SAFE: createByUUID - gibt Fake-Objekt zurück wenn HAL defekt
        void* createAddr = dlsym(mediandk, "AMediaDrm_createByUUID");
        if (createAddr && DobbyHook(createAddr, (dobby_dummy_func_t)titan_hooked_AMediaDrm_createByUUID,
                                    (dobby_dummy_func_t*)&g_origAMediaDrmCreateByUUID) == 0) {
            installed++;
            LOGI("[TITAN] AMediaDrm_createByUUID hook OK");
        }
        
        // SAFE: release - Fake-Objekte korrekt freigeben
        void* releaseAddr = dlsym(mediandk, "AMediaDrm_release");
        if (releaseAddr && DobbyHook(releaseAddr, (dobby_dummy_func_t)titan_hooked_AMediaDrm_release,
                                     (dobby_dummy_func_t*)&g_origAMediaDrmRelease) == 0) {
            installed++;
            LOGI("[TITAN] AMediaDrm_release hook OK");
        }
        
        // SAFE: isCryptoSchemeSupported - Widevine immer true
        void* isSupportedAddr = dlsym(mediandk, "AMediaDrm_isCryptoSchemeSupported");
        if (isSupportedAddr && DobbyHook(isSupportedAddr, (dobby_dummy_func_t)titan_hooked_AMediaDrm_isCryptoSchemeSupported,
                                         (dobby_dummy_func_t*)&g_origAMediaDrmIsCryptoSchemeSupported) == 0) {
            installed++;
            LOGI("[TITAN] AMediaDrm_isCryptoSchemeSupported hook OK");
        }
        
        // NICHT GEHOOKED (Dobby SIGILL): getPropertyByteArray, getPropertyString
        LOGI("[TITAN] Widevine: 3/3 safe hooks installed (getProperty via LSPosed)");
    } else {
        LOGW("[TITAN] libmediandk.so not available");
    }
#endif
    
    LOGI("[TITAN] Total hooks installed: %d/13", installed);
}

// ==============================================================================
// Zygisk Module
// ==============================================================================

class TitanModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        m_api = api;
        m_env = env;
        
        if (checkKillSwitch()) {
            LOGW("[TITAN] Kill-switch active");
            return;
        }
        
        LOGI("[TITAN] Module loaded (Phase 6.0 - Total Stealth)");
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
        if (!m_shouldInject || g_killSwitchActive.load()) return;
        
        // Atomicity Check: Identität muss konsistent geladen sein
        if (!verifyIdentityAtomicity()) {
            LOGW("[TITAN] Atomicity check FAILED - hooks deaktiviert für %s", m_packageName);
            return;
        }
        
        LOGI("[TITAN] === Phase 12: System Transmutation für %s ===", m_packageName);
        
        // PHASE 1: Property Area Privatisierung (MAP_SHARED → MAP_PRIVATE)
        // MUSS vor den Hooks passieren!
        privatizePropertyMappings();
        
        // PHASE 2: Direct Memory Patching (Werte direkt im RAM ändern)
        // Danach braucht __system_property_get für diese Props KEINEN Hook mehr
        patchAllPropertiesInMemory();
        
        // PHASE 3: Hooks installieren (Belt & Suspenders für alles was Memory-Patch nicht abdeckt)
        installAllHooks();
        
        LOGI("[TITAN] === Transmutation complete: %d regions privatized ===", g_privatizedRegions);
    }
    
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        (void)args;
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

REGISTER_ZYGISK_MODULE(TitanModule)

static void companionHandler(int fd) {
    loadBridge();
    close(fd);
}

REGISTER_ZYGISK_COMPANION(companionHandler)
