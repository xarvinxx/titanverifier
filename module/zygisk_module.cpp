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
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <android/log.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <atomic>
#include <mutex>
#include <unordered_set>

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

// Target Apps (NIEMALS System-Prozesse global hooken!)
static const char* TARGET_APPS[] = {
    "com.titan.verifier",
    "com.zhiliaoapp.musically",
    "com.ss.android.ugc.trill",
    "com.google.android.gms",
    nullptr
};

// Hardcoded Pixel 6 Defaults
static const char* DEFAULT_SERIAL = "28161FDF6006P8";
static const char* DEFAULT_IMEI1 = "352269111271008";
static const char* DEFAULT_IMEI2 = "358476312016587";
static const char* DEFAULT_ANDROID_ID = "d7f4b30e1b210a83";
static const char* DEFAULT_GSF_ID = "3a8c4f72d91e50b6";
static const char* DEFAULT_WIFI_MAC = "be:08:6e:16:a6:5d";
static const char* DEFAULT_WIDEVINE_ID = "a1b2c3d4e5f67890a1b2c3d4e5f67890";

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

static SystemPropertyGetFn g_origSystemPropertyGet = nullptr;
static GetifaddrsFn g_origGetifaddrs = nullptr;
static IoctlFn g_origIoctl = nullptr;
static RecvmsgFn g_origRecvmsg = nullptr;
static OpenFn g_origOpen = nullptr;
static ReadFn g_origRead = nullptr;
static FopenFn g_origFopen = nullptr;
static FreadFn g_origFread = nullptr;
static FgetsFn g_origFgets = nullptr;

// Track fopen'd MAC files
static std::unordered_set<FILE*> g_macFileStreams;

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
           strstr(path, "/proc/net/arp") != nullptr;
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
    
    if (strstr(name, "wifimacaddr") || strstr(name, "wlan.driver.macaddr")) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0]) { strncpy(value, spoofed, 23); value[23] = '\0'; return (int)strlen(value); }
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
    
    if (request == SIOCGIFHWADDR && arg && g_macParsed) {
        struct ifreq* ifr = static_cast<struct ifreq*>(arg);
        
        // Prüfe ob wlan0 oder eth0
        if (strcmp(ifr->ifr_name, "wlan0") == 0 || strcmp(ifr->ifr_name, "eth0") == 0) {
            // Versuche original ioctl
            int result = g_origIoctl(fd, request, arg);
            
            // Egal ob erfolgreich oder nicht - wir füllen die MAC!
            ifr->ifr_hwaddr.sa_family = 1; // ARPHRD_ETHER
            memcpy(ifr->ifr_hwaddr.sa_data, g_spoofedMacBytes, 6);
            
            LOGI("[TITAN] ioctl SIOCGIFHWADDR spoofed for %s: %02x:%02x:%02x:%02x:%02x:%02x (orig_result=%d)", 
                 ifr->ifr_name,
                 g_spoofedMacBytes[0], g_spoofedMacBytes[1], g_spoofedMacBytes[2],
                 g_spoofedMacBytes[3], g_spoofedMacBytes[4], g_spoofedMacBytes[5],
                 result);
            
            return 0; // Immer Erfolg melden!
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
    
    // Prüfe ob es ein Netlink Socket ist
    struct sockaddr_nl* nladdr = nullptr;
    if (msg->msg_name && msg->msg_namelen >= sizeof(struct sockaddr_nl)) {
        nladdr = static_cast<struct sockaddr_nl*>(msg->msg_name);
        if (nladdr->nl_family != AF_NETLINK) return result;
    }
    
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

static int titan_hooked_open(const char* pathname, int flags, mode_t mode) {
    if (!g_origOpen) return -1;
    
    // Wenn MAC-Pfad, redirect zu Fake-Datei
    if (pathname && g_macParsed && isMacPath(pathname)) {
        LOGI("[TITAN] open() MAC path detected: %s", pathname);
        
        TitanHardware& hw = TitanHardware::getInstance();
        char macStr[24] = {};
        hw.getWifiMac(macStr, sizeof(macStr));
        
        if (macStr[0]) {
            char tempPath[128];
            snprintf(tempPath, sizeof(tempPath), "/data/local/tmp/.titan_mac_%d", getpid());
            
            // Schreibe MAC in temporäre Datei
            int writeFd = g_origOpen(tempPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (writeFd >= 0) {
                char buf[32];
                int len = snprintf(buf, sizeof(buf), "%s\n", macStr);
                write(writeFd, buf, len);
                close(writeFd);
                
                // Öffne die temporäre Datei mit den originalen Flags
                int fakeFd = g_origOpen(tempPath, flags, mode);
                if (fakeFd >= 0) {
                    LOGI("[TITAN] open() MAC redirect: %s -> %s (fd=%d, MAC=%s)", pathname, tempPath, fakeFd, macStr);
                    return fakeFd;
                }
            }
        }
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

static FILE* titan_hooked_fopen(const char* pathname, const char* mode) {
    if (!g_origFopen) return nullptr;
    
    // Wenn MAC-Pfad, erstelle Fake-Datei mit gespoofter MAC
    if (pathname && g_macParsed && isMacPath(pathname)) {
        TitanHardware& hw = TitanHardware::getInstance();
        char macStr[24] = {};
        hw.getWifiMac(macStr, sizeof(macStr));
        
        if (macStr[0]) {
            // Erstelle temporäre Datei mit gespoofter MAC
            char tempPath[128];
            snprintf(tempPath, sizeof(tempPath), "/data/local/tmp/.titan_mac_%d", getpid());
            
            // Schreibe MAC in temporäre Datei
            FILE* tempFp = g_origFopen(tempPath, "w");
            if (tempFp) {
                fprintf(tempFp, "%s\n", macStr);
                fclose(tempFp);
                
                // Öffne die temporäre Datei zum Lesen
                FILE* fakeFp = g_origFopen(tempPath, mode);
                if (fakeFp) {
                    LOGI("[TITAN] fopen MAC redirect: %s -> %s (MAC=%s)", pathname, tempPath, macStr);
                    return fakeFp;
                }
            }
        }
    }
    
    FILE* fp = g_origFopen(pathname, mode);
    return fp;
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
#endif
    
    LOGI("[TITAN] Total hooks installed: %d/8", installed);
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
        
        LOGI("[TITAN] Injecting Total Stealth hooks into %s", m_packageName);
        installAllHooks();
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
