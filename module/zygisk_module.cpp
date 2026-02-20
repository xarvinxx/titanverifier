/*
 * Hardware Compatibility Overlay - Zygisk Module
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
#include <ctime>
#include <string>
#include <atomic>
#include <mutex>

#include <unordered_set>
#include <unordered_map>

#include <sys/syscall.h>   // FIX-24: Raw Syscalls
#include <linux/memfd.h>   // FIX-24: memfd_create (MFD_CLOEXEC)

#include "../include/zygisk.hpp"
// Dobby removed (v8.0 — signal-based hooks)
#include "../common/hw_compat.h"
#include "lsplant.hpp"

// =============================================================================
// String Obfuscation
// =============================================================================
#define _XK 0x5A

static inline void _xdec(char* out, const unsigned char* enc, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (char)(enc[i] ^ _XK);
    }
    out[len] = '\0';
}

#define DEC_STR(varname, enc_bytes, enc_len) \
    char varname[enc_len + 1]; \
    _xdec(varname, (const unsigned char*)enc_bytes, enc_len)

// Raw Syscall Wrappers
static inline int _raw_openat(const char* path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}

static inline ssize_t _raw_read(int fd, void* buf, size_t count) {
    return (ssize_t)syscall(__NR_read, fd, buf, count);
}

static inline int _raw_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

// Anonymous RAM-FD (only used by LSPlant inline hook backend internally)
[[maybe_unused]] static inline int _memfd_create(unsigned int flags) {
    return (int)syscall(__NR_memfd_create, "", flags);
}

#ifdef STEALTH_MODE
    #define LOGI(...) ((void)0)
    #define LOGW(...) ((void)0)
    #define LOGE(...) ((void)0)
#else
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "sys", __VA_ARGS__)
    #define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "sys", __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "sys", __VA_ARGS__)
#endif

// ==============================================================================
// Konfiguration
// ==============================================================================

static const unsigned char _ENC_KILL_SWITCH[] = {
    0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x36,0x35,0x39,0x3b,0x36,0x75,
    0x2e,0x37,0x2a,0x75,0x74,0x32,0x2d,0x05,0x3e,0x33,0x29,0x3b,
    0x38,0x36,0x3f,0x3e
};
#define KILL_SWITCH_LEN 28

static const unsigned char _ENC_BRIDGE_PATH[] = {
    0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x3b,0x3e,0x38,0x75,0x37,0x35,
    0x3e,0x2f,0x36,0x3f,0x29,0x75,0x32,0x2d,0x05,0x35,0x2c,0x3f,
    0x28,0x36,0x3b,0x23,0x75,0x74,0x32,0x2d,0x05,0x39,0x35,0x34,
    0x3c,0x33,0x3d
};
#define BRIDGE_PATH_LEN 39

static const unsigned char _ENC_PATH_PROC_SELF_MAPS[] = {0x75,0x2a,0x28,0x35,0x39,0x75,0x29,0x3f,0x36,0x3c,0x75,0x37,0x3b,0x2a,0x29};
#define _ENC_PATH_PROC_SELF_MAPS_LEN 15
static const unsigned char _ENC_PATH_PROC_NET_ARP[] = {0x75,0x2a,0x28,0x35,0x39,0x75,0x34,0x3f,0x2e,0x75,0x3b,0x28,0x2a};
#define _ENC_PATH_PROC_NET_ARP_LEN 13
static const unsigned char _ENC_PATH_PROC_INPUT_DEV[] = {0x75,0x2a,0x28,0x35,0x39,0x75,0x38,0x2f,0x29,0x75,0x33,0x34,0x2a,0x2f,0x2e,0x75,0x3e,0x3f,0x2c,0x33,0x39,0x3f,0x29};
#define _ENC_PATH_PROC_INPUT_DEV_LEN 23
static const unsigned char _ENC_PATH_PROC_CPUINFO[] = {0x75,0x2a,0x28,0x35,0x39,0x75,0x39,0x2a,0x2f,0x33,0x34,0x3c,0x35};
#define _ENC_PATH_PROC_CPUINFO_LEN 13
static const unsigned char _ENC_PATH_PROC_VERSION[] = {0x75,0x2a,0x28,0x35,0x39,0x75,0x2c,0x3f,0x28,0x29,0x33,0x35,0x34};
#define _ENC_PATH_PROC_VERSION_LEN 13
static const unsigned char _ENC_PATH_SYS_WLAN0_ADDR[] = {0x75,0x29,0x23,0x29,0x75,0x39,0x36,0x3b,0x29,0x29,0x75,0x34,0x3f,0x2e,0x75,0x2d,0x36,0x3b,0x34,0x6a,0x75,0x3b,0x3e,0x3e,0x28,0x3f,0x29,0x29};
#define _ENC_PATH_SYS_WLAN0_ADDR_LEN 28
static const unsigned char _ENC_PATH_SYS_ETH0_ADDR[] = {0x75,0x29,0x23,0x29,0x75,0x39,0x36,0x3b,0x29,0x29,0x75,0x34,0x3f,0x2e,0x75,0x3f,0x2e,0x32,0x6a,0x75,0x3b,0x3e,0x3e,0x28,0x3f,0x29,0x29};
#define _ENC_PATH_SYS_ETH0_ADDR_LEN 27
static const unsigned char _ENC_PATH_DATA_TMP_PREFIX[] = {0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x36,0x35,0x39,0x3b,0x36,0x75,0x2e,0x37,0x2a,0x75,0x74,0x2e,0x05};
#define _ENC_PATH_DATA_TMP_PREFIX_LEN 19
static const unsigned char _ENC_PATH_PROC_SELF_MEM[] = {0x75,0x2a,0x28,0x35,0x39,0x75,0x29,0x3f,0x36,0x3c,0x75,0x37,0x3f,0x37};
#define _ENC_PATH_PROC_SELF_MEM_LEN 14

static const unsigned char _ENC_FALLBACK_SYS[] = {0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x74,0x32,0x2d,0x5,0x39,0x35,0x34,0x3c,0x33,0x3d};
#define _ENC_FALLBACK_SYS_LEN 23
static const unsigned char _ENC_FALLBACK_TMP[] = {0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x36,0x35,0x39,0x3b,0x36,0x75,0x2e,0x37,0x2a,0x75,0x74,0x32,0x2d,0x5,0x39,0x35,0x34,0x3c,0x33,0x3d};
#define _ENC_FALLBACK_TMP_LEN 26

static char g_killSwitchPath[KILL_SWITCH_LEN + 1] = {};
static char g_bridgePath[BRIDGE_PATH_LEN + 1] = {};
static char g_pathProcSelfMaps[_ENC_PATH_PROC_SELF_MAPS_LEN + 1] = {};
static char g_pathProcNetArp[_ENC_PATH_PROC_NET_ARP_LEN + 1] = {};
static char g_pathProcInputDev[_ENC_PATH_PROC_INPUT_DEV_LEN + 1] = {};
static char g_pathProcCpuinfo[_ENC_PATH_PROC_CPUINFO_LEN + 1] = {};
static char g_pathProcVersion[_ENC_PATH_PROC_VERSION_LEN + 1] = {};
static char g_pathSysWlan0Addr[_ENC_PATH_SYS_WLAN0_ADDR_LEN + 1] = {};
static char g_pathSysEth0Addr[_ENC_PATH_SYS_ETH0_ADDR_LEN + 1] = {};
static char g_pathDataTmpPrefix[_ENC_PATH_DATA_TMP_PREFIX_LEN + 1] = {};
static char g_pathProcSelfMem[_ENC_PATH_PROC_SELF_MEM_LEN + 1] = {};
static char g_fallbackSys[_ENC_FALLBACK_SYS_LEN + 1] = {};
static char g_fallbackTmp[_ENC_FALLBACK_TMP_LEN + 1] = {};
static std::once_flag g_pathsDecoded;

static void _decodePaths() {
    _xdec(g_killSwitchPath, _ENC_KILL_SWITCH, KILL_SWITCH_LEN);
    _xdec(g_bridgePath, _ENC_BRIDGE_PATH, BRIDGE_PATH_LEN);
    _xdec(g_pathProcSelfMaps, _ENC_PATH_PROC_SELF_MAPS, _ENC_PATH_PROC_SELF_MAPS_LEN);
    _xdec(g_pathProcNetArp, _ENC_PATH_PROC_NET_ARP, _ENC_PATH_PROC_NET_ARP_LEN);
    _xdec(g_pathProcInputDev, _ENC_PATH_PROC_INPUT_DEV, _ENC_PATH_PROC_INPUT_DEV_LEN);
    _xdec(g_pathProcCpuinfo, _ENC_PATH_PROC_CPUINFO, _ENC_PATH_PROC_CPUINFO_LEN);
    _xdec(g_pathProcVersion, _ENC_PATH_PROC_VERSION, _ENC_PATH_PROC_VERSION_LEN);
    _xdec(g_pathSysWlan0Addr, _ENC_PATH_SYS_WLAN0_ADDR, _ENC_PATH_SYS_WLAN0_ADDR_LEN);
    _xdec(g_pathSysEth0Addr, _ENC_PATH_SYS_ETH0_ADDR, _ENC_PATH_SYS_ETH0_ADDR_LEN);
    _xdec(g_pathDataTmpPrefix, _ENC_PATH_DATA_TMP_PREFIX, _ENC_PATH_DATA_TMP_PREFIX_LEN);
    _xdec(g_pathProcSelfMem, _ENC_PATH_PROC_SELF_MEM, _ENC_PATH_PROC_SELF_MEM_LEN);
    _xdec(g_fallbackSys, _ENC_FALLBACK_SYS, _ENC_FALLBACK_SYS_LEN);
    _xdec(g_fallbackTmp, _ENC_FALLBACK_TMP, _ENC_FALLBACK_TMP_LEN);
}

#define KILL_SWITCH_PATH    (std::call_once(g_pathsDecoded, _decodePaths), g_killSwitchPath)
#define BRIDGE_FILE_PATH    (std::call_once(g_pathsDecoded, _decodePaths), g_bridgePath)
#define PATH_PROC_SELF_MAPS (std::call_once(g_pathsDecoded, _decodePaths), g_pathProcSelfMaps)
#define PATH_PROC_NET_ARP   (std::call_once(g_pathsDecoded, _decodePaths), g_pathProcNetArp)
#define PATH_PROC_INPUT_DEV (std::call_once(g_pathsDecoded, _decodePaths), g_pathProcInputDev)
#define PATH_PROC_CPUINFO   (std::call_once(g_pathsDecoded, _decodePaths), g_pathProcCpuinfo)
#define PATH_PROC_VERSION   (std::call_once(g_pathsDecoded, _decodePaths), g_pathProcVersion)
#define PATH_SYS_WLAN0_ADDR (std::call_once(g_pathsDecoded, _decodePaths), g_pathSysWlan0Addr)
#define PATH_SYS_ETH0_ADDR  (std::call_once(g_pathsDecoded, _decodePaths), g_pathSysEth0Addr)
#define PATH_DATA_TMP_PREFIX (std::call_once(g_pathsDecoded, _decodePaths), g_pathDataTmpPrefix)
#define PATH_PROC_SELF_MEM   (std::call_once(g_pathsDecoded, _decodePaths), g_pathProcSelfMem)
#define BRIDGE_FALLBACK_SYS  (std::call_once(g_pathsDecoded, _decodePaths), g_fallbackSys)
#define BRIDGE_FALLBACK_TMP  (std::call_once(g_pathsDecoded, _decodePaths), g_fallbackTmp)

// Target Apps
struct EncPackage { const unsigned char* data; size_t len; };

static const unsigned char _ENC_PKG_VERIFIER[] = {
    0x39,0x35,0x37,0x74,0x35,0x3f,0x37,0x74,0x32,0x3b,0x28,0x3e,
    0x2d,0x3b,0x28,0x3f,0x74,0x29,0x3f,0x28,0x2c,0x33,0x39,0x3f
};
static const unsigned char _ENC_PKG_TIKTOK1[] = {
    0x39,0x35,0x37,0x74,0x20,0x32,0x33,0x36,0x33,0x3b,0x35,0x3b,0x2a,0x2a,0x74,0x37,0x2f,0x29,0x33,0x39,0x3b,0x36,0x36,0x23
};
static const unsigned char _ENC_PKG_TIKTOK2[] = {
    0x39,0x35,0x37,0x74,0x29,0x29,0x74,0x3b,0x34,0x3e,0x28,0x35,0x33,0x3e,0x74,0x2f,0x3d,0x39,0x74,0x2e,0x28,0x33,0x36,0x36
};
static const unsigned char _ENC_PKG_INSTAGRAM[] = {
    0x39,0x35,0x37,0x74,0x33,0x34,0x29,0x2e,0x3b,0x3d,0x28,0x3b,0x37,0x74,0x3b,0x34,0x3e,0x28,0x35,0x33,0x3e
};
static const unsigned char _ENC_PKG_SNAPCHAT[] = {
    0x39,0x35,0x37,0x74,0x29,0x34,0x3b,0x2a,0x39,0x32,0x3b,0x2e,0x74,0x3b,0x34,0x3e,0x28,0x35,0x33,0x3e
};
static const unsigned char _ENC_PKG_DRMINFO[] = {
    0x39,0x35,0x37,0x74,0x3b,0x34,0x3e,0x28,0x35,0x33,0x3e,0x3c,0x2f,0x34,0x3d,0x74,0x3e,0x28,0x37,0x33,0x34,0x3c,0x35
};
static const unsigned char _ENC_PKG_DEVICEID[] = {
    0x2e,0x2d,0x74,0x28,0x3f,0x32,0x74,0x3e,0x3f,0x2c,0x33,0x39,0x3f,0x33,0x3e
};

static const EncPackage ENC_TARGET_APPS[] = {
    {_ENC_PKG_VERIFIER,  24},   // com.oem.hardware.service
    {_ENC_PKG_TIKTOK1,   24},   // com.zhiliaoapp.musically
    {_ENC_PKG_TIKTOK2,   24},   // com.ss.android.ugc.trill
    {_ENC_PKG_INSTAGRAM, 21},   // com.instagram.android
    {_ENC_PKG_SNAPCHAT,  20},   // com.snapchat.android
    {_ENC_PKG_DRMINFO,   23},   // com.androidfung.drminfo
    {_ENC_PKG_DEVICEID,  15},   // tw.reh.deviceid
};
static const int ENC_TARGET_APPS_COUNT = 7;

static const unsigned char _ENC_GOT_MUSICALLY[] = {0x37,0x2f,0x29,0x33,0x39,0x3b,0x36,0x36,0x23};
static const unsigned char _ENC_GOT_SS_ANDROID[] = {0x29,0x29,0x74,0x3b,0x34,0x3e,0x28,0x35,0x33,0x3e};
static const unsigned char _ENC_GOT_BYTEDANCE[] = {0x38,0x23,0x2e,0x3f,0x3e,0x3b,0x34,0x39,0x3f};
static const unsigned char _ENC_GOT_SSCRONET[] = {0x29,0x29,0x39,0x28,0x35,0x34,0x3f,0x2e};
static const unsigned char _ENC_GOT_TTBORINGSSL[] = {0x2e,0x2e,0x38,0x35,0x28,0x33,0x34,0x3d,0x29,0x29,0x36};
static const unsigned char _ENC_GOT_PANGLE[] = {0x2a,0x3b,0x34,0x3d,0x36,0x3f};
static const unsigned char _ENC_GOT_APPLOG[] = {0x3b,0x2a,0x2a,0x36,0x35,0x3d};
static const unsigned char _ENC_GOT_METASEC[] = {0x37,0x3f,0x2e,0x3b,0x29,0x3f,0x39};
static const unsigned char _ENC_GOT_MSAOAIDSEC[] = {0x37,0x29,0x3b,0x35,0x3b,0x33,0x3e,0x29,0x3f,0x39};
static const unsigned char _ENC_GOT_SEC_SDK[] = {0x29,0x3f,0x39,0x05,0x29,0x3e,0x31};

struct EncGotStr { const unsigned char* data; size_t len; };
static const EncGotStr ENC_GOT_LIBS[] = {
    {_ENC_GOT_MUSICALLY,  9},
    {_ENC_GOT_SS_ANDROID, 10},
    {_ENC_GOT_BYTEDANCE,  9},
    {_ENC_GOT_SSCRONET,   8},
    {_ENC_GOT_TTBORINGSSL,11},
    {_ENC_GOT_PANGLE,     6},
    {_ENC_GOT_APPLOG,     6},
    {_ENC_GOT_METASEC,    7},
    {_ENC_GOT_MSAOAIDSEC, 10},
    {_ENC_GOT_SEC_SDK,    7},
};
static const int ENC_GOT_LIBS_COUNT = 10;

// FIX-20: Hardcoded Defaults ENTFERNT.
// Wenn die Bridge-Datei nicht geladen werden kann, werden die Hooks
// DEAKTIVIERT statt statische Werte zu verwenden. Echte Werte
// durchlassen ist weniger verdächtig als falsche statische Werte,
// und der Auditor (FIX-17) erkennt den Fehler sofort.
//
// ALTE DEFAULTS (gelöscht — NIEMALS wiederherstellen!):
// static const char* DEFAULT_SERIAL = "...";    ← Cross-App Fingerprint!
// static const char* DEFAULT_IMEI1 = "...";     ← Alle Apps bekommen dieselbe ID!

// ==============================================================================
// Original Function Pointers
// ==============================================================================

using SystemPropertyGetFn = int (*)(const char* name, char* value);
using GetifaddrsFn = int (*)(struct ifaddrs** ifap);
using IoctlFn = int (*)(int fd, unsigned long request, ...);
using RecvmsgFn = ssize_t (*)(int sockfd, struct msghdr* msg, int flags);
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
} DrmByteArray;

// Korrekte Funktionssignaturen (exakt wie in der NDK-API)
using AMediaDrmCreateByUUIDFn = AMediaDrm* (*)(const uint8_t uuid[16]);
using AMediaDrmReleaseFn = void (*)(AMediaDrm*);
using AMediaDrmGetPropertyByteArrayFn = media_status_t (*)(AMediaDrm*, const char*, DrmByteArray*);
using AMediaDrmGetPropertyStringFn = media_status_t (*)(AMediaDrm*, const char*, const char**);
using AMediaDrmIsCryptoSchemeSupportedFn = bool (*)(const uint8_t uuid[16], const char* mimeType);

static SystemPropertyGetFn g_origSystemPropertyGet = nullptr;
static GetifaddrsFn g_origGetifaddrs = nullptr;
static IoctlFn g_origIoctl = nullptr;
static RecvmsgFn g_origRecvmsg = nullptr;
static SystemPropertyReadOldFn g_origSysPropRead = nullptr;
static SendmsgFn g_origSendmsg = nullptr;
static AMediaDrmCreateByUUIDFn g_origAMediaDrmCreateByUUID = nullptr;
static AMediaDrmReleaseFn g_origAMediaDrmRelease = nullptr;
static AMediaDrmGetPropertyByteArrayFn g_origAMediaDrmGetPropertyByteArray = nullptr;
static AMediaDrmGetPropertyStringFn g_origAMediaDrmGetPropertyString = nullptr;
static AMediaDrmIsCryptoSchemeSupportedFn g_origAMediaDrmIsCryptoSchemeSupported = nullptr;

// Track unsere Fake-DRM-Objekte + Real-DRM-Mapping
static std::unordered_set<AMediaDrm*> g_fakeDrmObjects;
static std::unordered_map<AMediaDrm*, AMediaDrm*> g_fakeToRealDrm;

// Widevine UUID (ed282e16-fdd2-47c7-8d6d-09946462f367)
static const uint8_t WIDEVINE_UUID[16] = {
    0xed, 0x28, 0x2e, 0x16, 0xfd, 0xd2, 0x47, 0xc7,
    0x8d, 0x6d, 0x09, 0x94, 0x64, 0x62, 0xf3, 0x67
};

// Master Widevine ID (Phase 7.8 - Fixed Pixel 6 Identity)
static const char* MASTER_WIDEVINE_HEX = "10179c6bcba352dbd5ce5c88fec8e098";
static uint8_t g_widevineBytes[16] = {0};
static bool g_widevineParsed = false;

// Track Netlink Sockets für RTM_GETLINK (sendmsg → recvmsg Korrelation)
static std::unordered_set<int> g_netlinkSockets;
static std::mutex g_netlinkMutex;

// ==============================================================================
// State
// ==============================================================================

static std::atomic<bool> g_bridgeLoaded{false};
static std::atomic<bool> g_killSwitchActive{false};
static std::atomic<bool> g_debugHooks{false};
static std::mutex g_fdMapMutex;

// Cached MAC bytes
static unsigned char g_spoofedMacBytes[6] = {0};
static bool g_macParsed = false;

// NativeMonitor removed (v8.0 Stealth)

// ==============================================================================
// ARM64 Inline Hook Engine (no signal handler, immune to handler overwrites)
// ==============================================================================
// Patches 16 bytes at function entry: LDR X16,#8 + BR X16 + .quad hookAddr
// Trampoline in memfd-backed RX page: original 4 insns + LDR+BR back to target+16
// Uses /proc/self/mem for W^X bypass (no mprotect traces)
// ==============================================================================

static bool _is_pc_relative(uint32_t insn) {
    if ((insn & 0x9F000000) == 0x90000000) return true;  // ADRP
    if ((insn & 0x9F000000) == 0x10000000) return true;  // ADR
    if ((insn & 0xFC000000) == 0x14000000) return true;  // B
    if ((insn & 0xFC000000) == 0x94000000) return true;  // BL
    if ((insn & 0xFE000000) == 0x54000000) return true;  // B.cond
    if ((insn & 0x7E000000) == 0x34000000) return true;  // CBZ/CBNZ
    if ((insn & 0x7E000000) == 0x36000000) return true;  // TBZ/TBNZ
    if ((insn & 0x3B000000) == 0x18000000) return true;  // LDR (literal)
    return false;
}

// Ghost Protocol v9.1: Single-Page Trampoline Pool (Library-Backed)
// Alle Trampolines in einer einzigen Page die als liblog.so mapping erscheint.
// Kein memfd, keine anonymen RX-Regionen.
static void* g_trampolineBase = nullptr;
static size_t g_trampolineUsed = 0;
static constexpr size_t kTrampolinePageSize = 4096;
[[maybe_unused]] static constexpr size_t kTrampolineSlotSize = 32;

static bool _initTrampolinePage() {
    if (g_trampolineBase) return true;

    static const char* backingLibs[] = {
        "/system/lib64/liblog.so",
        "/system/lib64/libm.so",
        "/system/lib64/libdl.so",
    };
    int fd = -1;
    for (auto& lib : backingLibs) {
        fd = _raw_openat(lib, O_RDONLY);
        if (fd >= 0) break;
    }
    if (fd < 0) return false;

    g_trampolineBase = mmap(nullptr, kTrampolinePageSize, PROT_READ | PROT_EXEC,
                            MAP_PRIVATE, fd, 0);
    _raw_close(fd);
    return g_trampolineBase != MAP_FAILED;
}

static void* _allocTrampoline(const uint8_t* code, size_t len) {
    if (!g_trampolineBase || g_trampolineUsed + len > kTrampolinePageSize)
        return nullptr;

    void* slot = reinterpret_cast<uint8_t*>(g_trampolineBase) + g_trampolineUsed;

    int memFd = _raw_openat(PATH_PROC_SELF_MEM, O_RDWR);
    if (memFd < 0) return nullptr;

    lseek(memFd, static_cast<off_t>(reinterpret_cast<uintptr_t>(slot)), SEEK_SET);
    write(memFd, code, len);
    _raw_close(memFd);

    __builtin___clear_cache(static_cast<char*>(slot),
                            static_cast<char*>(slot) + len);

    g_trampolineUsed = (g_trampolineUsed + len + 7) & ~(size_t)7;
    return slot;
}

// Register-Rotation: Wechselt zwischen X9-X12, X16, X17 um Pattern-Matching zu erschweren.
static uint32_t _nextHookReg() {
    static const uint32_t regs[] = {9, 10, 11, 12, 16, 17};
    static std::atomic<int> idx{0};
    return regs[idx.fetch_add(1) % 6];
}

static bool install_inline_hook(void* target, void* hook, void** orig) {
    if (!target || !hook || !orig)
        return false;

    if (!_initTrampolinePage()) return false;

    uint32_t origInsns[4];
    memcpy(origInsns, target, 16);

    for (int i = 0; i < 4; i++) {
        if (_is_pc_relative(origInsns[i])) {
            LOGW("[HW] PC-relative insn at %p+%d (0x%08x), skipping inline hook",
                 target, i * 4, origInsns[i]);
            return false;
        }
    }

    uint32_t reg = _nextHookReg();
    uint32_t ldrPc8  = 0x58000040 | reg;           // LDR Xn, [PC, #8]
    uint32_t brReg   = 0xD61F0000 | (reg << 5);    // BR Xn
    uint64_t retAddr = reinterpret_cast<uint64_t>(target) + 16;

    uint8_t tramp[32];
    memcpy(tramp + 0,  origInsns, 16);
    memcpy(tramp + 16, &ldrPc8,  4);
    memcpy(tramp + 20, &brReg,   4);
    memcpy(tramp + 24, &retAddr, 8);

    void* tramAddr = _allocTrampoline(tramp, sizeof(tramp));
    if (!tramAddr) return false;
    *orig = tramAddr;

    uint64_t hookAddr = reinterpret_cast<uint64_t>(hook);
    uint8_t patch[16];
    memcpy(patch + 0, &ldrPc8,   4);
    memcpy(patch + 4, &brReg,    4);
    memcpy(patch + 8, &hookAddr, 8);

    int memFd = _raw_openat(PATH_PROC_SELF_MEM, O_RDWR);
    if (memFd >= 0) {
        lseek(memFd, reinterpret_cast<off_t>(target), SEEK_SET);
        write(memFd, patch, 16);
        _raw_close(memFd);
    } else {
        uintptr_t pageStart = reinterpret_cast<uintptr_t>(target) & ~(uintptr_t)0xFFF;
        uintptr_t pageEnd   = (reinterpret_cast<uintptr_t>(target) + 16 + 0xFFF) & ~(uintptr_t)0xFFF;
        size_t len = pageEnd - pageStart;
        mprotect(reinterpret_cast<void*>(pageStart), len, PROT_READ | PROT_WRITE | PROT_EXEC);
        memcpy(target, patch, 16);
        mprotect(reinterpret_cast<void*>(pageStart), len, PROT_READ | PROT_EXEC);
    }

    __builtin___clear_cache(static_cast<char*>(target),
                            static_cast<char*>(target) + 16);

    return true;
}

// ==============================================================================
// FIX-30 REVERTED: Build-Prop-Spoofing ENTFERNT (v5.1)
// GRUND: Unser Modul hat ro.build.fingerprint etc. mit Identity-Werten
//        überschrieben, was PIF's Canary-Fingerprint blockiert hat.
//        → Basic Integrity ging verloren.
// LÖSUNG: Build-Properties gehören AUSSCHLIESSLICH dem PIF-Modul.
//         Unser Modul spooft NUR Hardware-IDs (Serial, IMEI, MAC, etc.)
// ==============================================================================

// ==============================================================================
// Helpers
// ==============================================================================

// FIX-24B: Raw Syscall statt libc stat()
static bool checkKillSwitch() {
    struct stat st;
    if (syscall(__NR_newfstatat, AT_FDCWD, KILL_SWITCH_PATH, &st, 0) == 0) {
        g_killSwitchActive = true;
        return true;
    }
    return false;
}

// ==============================================================================
// v6.1: Google Process Blacklist — DEVICE_INTEGRITY Schutz
// ==============================================================================
// TrickyStore liefert DEVICE_INTEGRITY über eine Hardware-Keybox.
// Damit das funktioniert, MUSS GMS (com.google.android.gms) die echten,
// unmodifizierten System-Properties sehen. Wenn wir GMS spoofen,
// erkennt SafetyNet/Play Integrity den Mismatch zwischen der Keybox
// (Hardware-gebunden) und den gespooften Properties → DEVICE_INTEGRITY
// geht verloren.
//
// Diese Blacklist stellt sicher, dass Google-Prozesse zu 100% "Vanilla"
// bleiben — kein Property-Spoofing, kein Memory-Patching, keine Hooks.
// ==============================================================================

static const char* BLACKLIST_PACKAGES[] = {
    "com.google.android.gms",              // Google Play Services (Core)
    "com.google.android.gms.unstable",     // GMS SafetyNet/DroidGuard Sandbox
    "com.android.vending",                 // Google Play Store
    "com.google.android.gsf",              // Google Services Framework
    "com.google.android.gsf.login",        // GSF Login Activity
    "com.google.process.gapps",            // Google Apps shared process
    "com.google.android.gms.persistent",   // GMS persistent process
    nullptr
};

static bool isBlacklistedProcess(const char* processName) {
    if (!processName) return false;
    for (int i = 0; BLACKLIST_PACKAGES[i] != nullptr; i++) {
        // Exakter Match ODER Prefix-Match (für Sub-Prozesse wie gms:snet)
        if (strcmp(processName, BLACKLIST_PACKAGES[i]) == 0) return true;
        // Prefix-Check: "com.google.android.gms" matcht auch
        // "com.google.android.gms:snet", "com.google.android.gms:chimera" etc.
        size_t blLen = strlen(BLACKLIST_PACKAGES[i]);
        if (strncmp(processName, BLACKLIST_PACKAGES[i], blLen) == 0) {
            char next = processName[blLen];
            if (next == '\0' || next == ':' || next == '.') return true;
        }
    }
    return false;
}

// FIX-24A: isTargetApp mit XOR-Entschlüsselung (on-the-fly, stack-only)
static bool isTargetApp(const char* packageName) {
    if (!packageName) return false;
    size_t pkgLen = strlen(packageName);
    for (int i = 0; i < ENC_TARGET_APPS_COUNT; i++) {
        if (pkgLen != ENC_TARGET_APPS[i].len) continue;
        // Entschlüssele auf dem Stack und vergleiche
        char decoded[64];
        _xdec(decoded, ENC_TARGET_APPS[i].data, ENC_TARGET_APPS[i].len);
        if (strcmp(packageName, decoded) == 0) return true;
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

// FIX-20: applyDefaults() ENTFERNT.
// Statt statische Defaults zu laden (= Cross-App Fingerprint!),
// werden die Hooks bei fehlendem Bridge-File deaktiviert.
// Die echten Geräte-Werte werden dann durchgelassen.

// Forward-Deklarationen (Definitionen weiter unten nach der Bridge-Lade-Logik)
static std::unordered_map<std::string, std::string> g_dynamicProps;
static bool isPifExclusive(const char* key);
static const char* lookupDynamicProp(const char* name);

static bool loadBridgeFromFile(const char* path) {
    // FIX-24B: Raw Syscalls statt libc open/read/close
    // Umgeht PLT-Hooking durch Anti-Cheat-Engines (z.B. libsscronet.so)
    int fd = _raw_openat(path, O_RDONLY);
    if (fd < 0) return false;
    
    char buffer[2048] = {};
    ssize_t bytesRead = _raw_read(fd, buffer, sizeof(buffer) - 1);
    _raw_close(fd);
    
    if (bytesRead <= 0) return false;
    buffer[bytesRead] = '\0';
    
    HwCompat& hw = HwCompat::getInstance();
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
            // FIX-12: Debug-Log-Mode via Bridge-Feld
            else if (strcmp(key, "debug_hooks") == 0) {
                g_debugHooks = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
                if (g_debugHooks.load()) {
                    LOGI("[HW] Debug-Hook-Mode AKTIVIERT — alle Hook-Calls werden geloggt");
                }
            }
            // v6.0: Dynamische Property-Overrides aus Bridge
            // Jeder Key der mit "ro." beginnt wird als System-Property Override gespeichert
            else if (strncmp(key, "ro.", 3) == 0) {
                if (isPifExclusive(key)) {
                    LOGI("[HW] Bridge %s: IGNORIERT (PIF-exklusiv)", key);
                } else if (strlen(value) > 0) {
                    g_dynamicProps[key] = value;
                    foundAny = true;
                    LOGI("[HW] Bridge prop: %s=%s", key, value);
                }
            }
            // Legacy bridge keys (build_id etc.) — still ignored
            else if (strcmp(key, "build_id") == 0 ||
                     strcmp(key, "build_fingerprint") == 0 ||
                     strcmp(key, "security_patch") == 0 ||
                     strcmp(key, "build_incremental") == 0 ||
                     strcmp(key, "build_description") == 0) {
                LOGI("[HW] Bridge %s: IGNORIERT (legacy/PIF-exklusiv)", key);
            }
        }
    }
    
    return foundAny;
}

static void loadBridge() {
    if (g_bridgeLoaded.load()) return;
    
    if (loadBridgeFromFile(BRIDGE_FILE_PATH)) {
        LOGI("Config loaded from primary path");
        g_bridgeLoaded = true;
    } else if (loadBridgeFromFile(BRIDGE_FALLBACK_SYS)) {
        LOGI("Config loaded from fallback (system)");
        g_bridgeLoaded = true;
    } else if (loadBridgeFromFile(BRIDGE_FALLBACK_TMP)) {
        LOGI("Config loaded from fallback (local/tmp)");
        g_bridgeLoaded = true;
    } else {
        LOGW("[HW] Bridge not found — Hooks DEAKTIVIERT (kein Spoofing)");
        g_bridgeLoaded = false;
    }
    
    // Cache MAC bytes
    HwCompat& hw = HwCompat::getInstance();
    char macStr[24] = {};
    hw.getWifiMac(macStr, sizeof(macStr));
    if (macStr[0] && parseMacString(macStr, g_spoofedMacBytes)) {
        g_macParsed = true;
        LOGI("[HW] Cached MAC: %s", macStr);
    }
}

// Ghost Protocol v9.1: Pfad-Checker und statische Fake-Daten entfernt.
// Alle Datei-Redirects laufen jetzt über SUSFS add_open_redirect auf Kernel-Ebene.
// Root-Detection-Pfade werden durch SUSFS add_sus_path unsichtbar gemacht.

// Entfernt: isMacPath, isNetworkInfoPath, isRootDetectionPath, isInputDevicesPath,
//           isCpuInfoPath, isKernelVersionPath, getFakeIfInet6, FAKE_INPUT_DEVICES,
//           FAKE_CPUINFO, FAKE_KERNEL_VERSION, ENC_ROOT_PATHS


// ==============================================================================
// v6.0: Dynamic Property Overrides — Bridge-gesteuert
// ==============================================================================
// KEINE statischen Build-Props mehr! Alle Property-Overrides kommen
// ausschließlich aus der Bridge-Datei (KEY=VALUE Format).
//
// Der Python-Orchestrator schreibt ro.* Keys in die Bridge:
//   ro.product.model=Pixel 6
//   ro.build.type=user
//   ro.hardware=oriole
//
// PIF-SCHUTZ: Folgende Keys werden IGNORIERT (PIF-exklusiv):
//   ro.build.fingerprint, ro.build.id, ro.build.description,
//   ro.build.version.security_patch, ro.build.version.incremental,
//   ro.bootimage.build.fingerprint, ro.vendor.build.fingerprint,
//   ro.odm.build.fingerprint, ro.system.build.fingerprint
// ==============================================================================

// g_dynamicProps bereits oben (vor loadBridgeFromFile) definiert

static bool isPifExclusive(const char* key) {
    static const char* PIF_KEYS[] = {
        "ro.build.fingerprint",
        "ro.build.id",
        "ro.build.display.id",
        "ro.build.description",
        "ro.build.version.security_patch",
        "ro.build.version.incremental",
        "ro.bootimage.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.odm.build.fingerprint",
        "ro.system.build.fingerprint",
        nullptr
    };
    for (int i = 0; PIF_KEYS[i] != nullptr; i++) {
        if (strcmp(key, PIF_KEYS[i]) == 0) return true;
    }
    return false;
}

static const char* lookupDynamicProp(const char* name) {
    auto it = g_dynamicProps.find(name);
    if (it != g_dynamicProps.end()) {
        return it->second.c_str();
    }
    return nullptr;
}

// ==============================================================================
// Hook: __system_property_get
// ==============================================================================

static int _hooked_system_property_get(const char* name, char* value) {
    if (!name || !value) {
        return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
    }
    
    HwCompat& hw = HwCompat::getInstance();
    char spoofed[128] = {};
    
    // --- Identity Properties (aus Bridge) ---
    
    if (strcmp(name, "ro.serialno") == 0 || strcmp(name, "ro.boot.serialno") == 0) {
        hw.getSerial(spoofed, sizeof(spoofed));
        if (spoofed[0]) {
            // FIX-12: Debug-Log
            if (g_debugHooks.load()) LOGI("[HOOK] %s → Spoofed: %s", name, spoofed);
            strncpy(value, spoofed, 91); value[91] = '\0';
            return (int)strlen(value);
        }
    }
    
    if (strstr(name, "gsf") || strcmp(name, "ro.com.google.gservices.gsf.id") == 0) {
        hw.getGsfId(spoofed, sizeof(spoofed));
        if (spoofed[0]) {
            if (g_debugHooks.load()) LOGI("[HOOK] %s → Spoofed GSF: %.8s...", name, spoofed);
            strncpy(value, spoofed, 91); value[91] = '\0';
            return (int)strlen(value);
        }
    }
    
    if (strcmp(name, "gsm.baseband.imei") == 0 || strstr(name, "imei")) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) {
            if (g_debugHooks.load()) LOGI("[HOOK] %s → Spoofed IMEI1: %s", name, spoofed);
            strncpy(value, spoofed, 31); value[31] = '\0';
            return (int)strlen(value);
        }
    }
    
    if (strstr(name, "wifimacaddr") || strstr(name, "wlan.driver.macaddr") || 
        strcmp(name, "ro.wlan.mac") == 0 || strcmp(name, "wifi.interface.mac") == 0) {
        hw.getWifiMac(spoofed, sizeof(spoofed));
        if (spoofed[0]) {
            if (g_debugHooks.load()) LOGI("[HOOK] %s → Spoofed MAC: %s", name, spoofed);
            strncpy(value, spoofed, 23); value[23] = '\0';
            return (int)strlen(value);
        }
    }
    
    if (strcmp(name, "ro.ril.oem.imei") == 0 || strcmp(name, "ro.ril.oem.imei1") == 0 ||
        strcmp(name, "persist.radio.imei") == 0) {
        hw.getImei1(spoofed, sizeof(spoofed));
        if (spoofed[0]) {
            if (g_debugHooks.load()) LOGI("[HOOK] %s → Spoofed RIL-IMEI1: %s", name, spoofed);
            strncpy(value, spoofed, 31); value[31] = '\0';
            return (int)strlen(value);
        }
    }
    if (strcmp(name, "ro.ril.oem.imei2") == 0 || strcmp(name, "persist.radio.imei2") == 0) {
        hw.getImei2(spoofed, sizeof(spoofed));
        if (spoofed[0]) {
            strncpy(value, spoofed, 31); value[31] = '\0';
            return (int)strlen(value);
        }
    }
    
    const char* dynOverride = lookupDynamicProp(name);
    if (dynOverride) {
        size_t len = strlen(dynOverride);
        if (len > 91) len = 91;
        memcpy(value, dynOverride, len);
        value[len] = '\0';
        if (g_debugHooks.load()) LOGI("[HOOK] %s → Dynamic: %s", name, dynOverride);
        return (int)len;
    }

    return g_origSystemPropertyGet ? g_origSystemPropertyGet(name, value) : 0;
}

// ==============================================================================
// Hook: getifaddrs (AF_PACKET MAC Spoofing)
// ==============================================================================

static int _hooked_getifaddrs(struct ifaddrs** ifap) {
    if (!g_origGetifaddrs) return -1;
    int result = g_origGetifaddrs(ifap);
    if (result != 0 || !ifap || !*ifap || !g_macParsed) return result;
    
    for (struct ifaddrs* ifa = *ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, "wlan0") != 0 && strcmp(ifa->ifa_name, "eth0") != 0) continue;
        
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
            if (sll->sll_halen == 6) {
                memcpy(sll->sll_addr, g_spoofedMacBytes, 6);
                LOGI("[HW] Spoofed AF_PACKET MAC for %s", ifa->ifa_name);
            }
        } 
        else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            if (sin6->sin6_addr.s6_addr[0] == 0xfe && (sin6->sin6_addr.s6_addr[1] & 0xc0) == 0x80) {
                if (sin6->sin6_addr.s6_addr[11] == 0xff && sin6->sin6_addr.s6_addr[12] == 0xfe) {
                    sin6->sin6_addr.s6_addr[8] = g_spoofedMacBytes[0] ^ 0x02;
                    sin6->sin6_addr.s6_addr[9] = g_spoofedMacBytes[1];
                    sin6->sin6_addr.s6_addr[10] = g_spoofedMacBytes[2];
                    sin6->sin6_addr.s6_addr[13] = g_spoofedMacBytes[3];
                    sin6->sin6_addr.s6_addr[14] = g_spoofedMacBytes[4];
                    sin6->sin6_addr.s6_addr[15] = g_spoofedMacBytes[5];
                    LOGI("[HW] Spoofed AF_INET6 EUI-64 MAC in getifaddrs for %s", ifa->ifa_name);
                }
            }
        }
    }
    return result;
}

// ==============================================================================
// Hook: ioctl (SIOCGIFHWADDR MAC Spoofing)
// ==============================================================================

static int _hooked_ioctl(int fd, unsigned long request, void* arg) {
    if (!g_origIoctl) return -1;
    
    if (request == SIOCGIFHWADDR && arg && g_macParsed) {
        struct ifreq* ifr = static_cast<struct ifreq*>(arg);
        if (strcmp(ifr->ifr_name, "wlan0") == 0 || strcmp(ifr->ifr_name, "eth0") == 0) {
            g_origIoctl(fd, request, arg);
            ifr->ifr_hwaddr.sa_family = 1;
            memcpy(ifr->ifr_hwaddr.sa_data, g_spoofedMacBytes, 6);
            return 0;
        }
    }
    
    return g_origIoctl(fd, request, arg);
}

// ==============================================================================
// Hook: recvmsg (Netlink RTM_NEWLINK MAC Spoofing - für libsscronet.so)
// ==============================================================================

static ssize_t _hooked_recvmsg(int sockfd, struct msghdr* msg, int flags) {
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
                        memcpy(RTA_DATA(rta), g_spoofedMacBytes, 6);
                        LOGI("[HW] Spoofed Netlink RTM_NEWLINK MAC");
                    }
                    rta = RTA_NEXT(rta, rtalen);
                }
            } else if (nlh->nlmsg_type == RTM_NEWADDR) {
                struct ifaddrmsg* ifa = static_cast<struct ifaddrmsg*>(NLMSG_DATA(nlh));
                if (ifa->ifa_family == AF_INET6) {
                    struct rtattr* rta = IFA_RTA(ifa);
                    int rtalen = IFA_PAYLOAD(nlh);
                    while (RTA_OK(rta, rtalen)) {
                        if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
                            unsigned char* ip6 = static_cast<unsigned char*>(RTA_DATA(rta));
                            if (ip6[0] == 0xfe && (ip6[1] & 0xc0) == 0x80 && ip6[11] == 0xff && ip6[12] == 0xfe) {
                                ip6[8]  = g_spoofedMacBytes[0] ^ 0x02;
                                ip6[9]  = g_spoofedMacBytes[1];
                                ip6[10] = g_spoofedMacBytes[2];
                                ip6[13] = g_spoofedMacBytes[3];
                                ip6[14] = g_spoofedMacBytes[4];
                                ip6[15] = g_spoofedMacBytes[5];
                                LOGI("[HW] Spoofed Netlink RTM_NEWADDR (IPv6 EUI-64)");
                            }
                        }
                        rta = RTA_NEXT(rta, rtalen);
                    }
                }
            }
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
    
    return result;
}

// Ghost Protocol v9.1: File-I/O Hooks entfernt.
// Alle Dateipfad-Redirects werden jetzt durch SUSFS add_open_redirect auf Kernel-Ebene behandelt.
// Verbleibende Hooks: property_get, getifaddrs, ioctl, sendmsg, recvmsg, MediaDRM.


// ==============================================================================
// Hook: Widevine NDK API (AMediaDrm) - Phase 9.0 Full HAL Mocking
// ==============================================================================

static void parseWidevineHex() {
    if (g_widevineParsed) return;
    
    // Versuche erst Bridge-Wert
    HwCompat& hw = HwCompat::getInstance();
    char widevineBuf[64] = {};
    hw.getWidevineId(widevineBuf, sizeof(widevineBuf));
    
    const char* hexStr = widevineBuf[0] ? widevineBuf : MASTER_WIDEVINE_HEX;
    
    for (int i = 0; i < 16 && hexStr[i*2] && hexStr[i*2+1]; i++) {
        char byte[3] = { hexStr[i*2], hexStr[i*2+1], 0 };
        g_widevineBytes[i] = (uint8_t)strtol(byte, nullptr, 16);
    }
    
    g_widevineParsed = true;
    LOGI("[HW] Widevine ID parsed: %02x%02x%02x%02x...", 
         g_widevineBytes[0], g_widevineBytes[1], g_widevineBytes[2], g_widevineBytes[3]);
}

static bool isFakeDrm(AMediaDrm* drm) {
    std::lock_guard<std::mutex> lock(g_fdMapMutex);
    return g_fakeDrmObjects.find(drm) != g_fakeDrmObjects.end();
}

// Hook: AMediaDrm_createByUUID - IMMER Fake-Objekt zurückgeben!
// Das echte DRM-Objekt wird intern gespeichert für nicht-sensitive Properties.
// deviceUniqueId wird IMMER aus der Bridge geliefert, NIE vom echten HAL.
static AMediaDrm* _hooked_AMediaDrm_createByUUID(const uint8_t uuid[16]) {
    AMediaDrm* realDrm = nullptr;
    if (g_origAMediaDrmCreateByUUID) {
        realDrm = g_origAMediaDrmCreateByUUID(uuid);
    }
    
    if (memcmp(uuid, WIDEVINE_UUID, 16) == 0) {
        AMediaDrm* fakeDrm = reinterpret_cast<AMediaDrm*>(calloc(1, 256));
        
        {
            std::lock_guard<std::mutex> lock(g_fdMapMutex);
            g_fakeDrmObjects.insert(fakeDrm);
            if (realDrm) {
                g_fakeToRealDrm[fakeDrm] = realDrm;
            }
        }
        
        LOGI("[HW] AMediaDrm_createByUUID(Widevine) -> Fake proxy %p (real=%p)",
             fakeDrm, realDrm);
        return fakeDrm;
    }
    
    if (realDrm) return realDrm;
    
    LOGW("[HW] AMediaDrm_createByUUID -> Failed (non-Widevine UUID)");
    return nullptr;
}

// Hook: AMediaDrm_release
static void _hooked_AMediaDrm_release(AMediaDrm* drm) {
    if (isFakeDrm(drm)) {
        AMediaDrm* realDrm = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_fdMapMutex);
            auto it = g_fakeToRealDrm.find(drm);
            if (it != g_fakeToRealDrm.end()) {
                realDrm = it->second;
                g_fakeToRealDrm.erase(it);
            }
            g_fakeDrmObjects.erase(drm);
        }
        if (realDrm && g_origAMediaDrmRelease) {
            g_origAMediaDrmRelease(realDrm);
        }
        free(drm);
        LOGI("[HW] AMediaDrm_release(Fake) -> freed (real=%p)", realDrm);
        return;
    }
    
    if (g_origAMediaDrmRelease) {
        g_origAMediaDrmRelease(drm);
    }
}

// Hook: AMediaDrm_getPropertyByteArray
// deviceUniqueId wird IMMER aus der Bridge geliefert.
// Andere Properties werden an das echte DRM-Objekt delegiert.
static media_status_t _hooked_AMediaDrm_getPropertyByteArray(
    AMediaDrm* drm, const char* propertyName, DrmByteArray* propertyValue) {
    
    if (!propertyName || !propertyValue) {
        return AMEDIA_DRM_NOT_PROVISIONED;
    }
    
    bool isDeviceId = (strcmp(propertyName, "deviceUniqueId") == 0);
    
    // deviceUniqueId → IMMER Spoofed, egal ob Fake oder Real DRM
    if (isDeviceId) {
        parseWidevineHex();
        
        static uint8_t s_widevineResult[16];
        memcpy(s_widevineResult, g_widevineBytes, 16);
        
        propertyValue->ptr = s_widevineResult;
        propertyValue->length = 16;
        
        LOGI("[HW] AMediaDrm_getPropertyByteArray(deviceUniqueId) -> Spoofed");
        return AMEDIA_OK;
    }
    
    // Nicht-sensitive Properties → an echtes DRM-Objekt delegieren
    AMediaDrm* realDrm = nullptr;
    if (isFakeDrm(drm)) {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        auto it = g_fakeToRealDrm.find(drm);
        if (it != g_fakeToRealDrm.end()) {
            realDrm = it->second;
        }
    } else {
        realDrm = drm;
    }
    
    if (realDrm && g_origAMediaDrmGetPropertyByteArray) {
        return g_origAMediaDrmGetPropertyByteArray(realDrm, propertyName, propertyValue);
    }
    
    return AMEDIA_DRM_NOT_PROVISIONED;
}

// Hook: AMediaDrm_getPropertyString
static media_status_t _hooked_AMediaDrm_getPropertyString(
    AMediaDrm* drm, const char* propertyName, const char** propertyValue) {
    
    if (!propertyName || !propertyValue) {
        return AMEDIA_DRM_NOT_PROVISIONED;
    }
    
    // Standard-Properties: immer statische Pixel 6 Werte
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
    
    // Nicht-Standard: an echtes DRM delegieren
    AMediaDrm* realDrm = nullptr;
    if (isFakeDrm(drm)) {
        std::lock_guard<std::mutex> lock(g_fdMapMutex);
        auto it = g_fakeToRealDrm.find(drm);
        if (it != g_fakeToRealDrm.end()) {
            realDrm = it->second;
        }
    } else {
        realDrm = drm;
    }
    
    if (realDrm && g_origAMediaDrmGetPropertyString) {
        return g_origAMediaDrmGetPropertyString(realDrm, propertyName, propertyValue);
    }
    
    *propertyValue = strdup("");
    return AMEDIA_OK;
}

// Hook: AMediaDrm_isCryptoSchemeSupported
static bool _hooked_AMediaDrm_isCryptoSchemeSupported(const uint8_t uuid[16], const char* mimeType) {
    // Widevine UUID IMMER unterstützen
    if (memcmp(uuid, WIDEVINE_UUID, 16) == 0) {
        LOGI("[HW] AMediaDrm_isCryptoSchemeSupported(Widevine) -> true (forced)");
        return true;
    }
    
    return g_origAMediaDrmIsCryptoSchemeSupported ?
           g_origAMediaDrmIsCryptoSchemeSupported(uuid, mimeType) : false;
}


// ==============================================================================
// Direct Memory Property Patching
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
    FILE* maps = fopen(PATH_PROC_SELF_MAPS, "r");
    if (!maps) {
        LOGW("[MEM] Cannot open /proc/self/maps");
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
            LOGW("[MEM] mmap failed for %lx-%lx (errno=%d)", start, end, errno);
            continue;
        }
        
        // Originaldaten wiederherstellen (jetzt in privater Kopie)
        memcpy(newMap, backup, size);
        free(backup);
        
        // Read-Only setzen (wird beim Patchen temporär aufgehoben)
        mprotect(newMap, size, PROT_READ);
        
        g_privatizedRegions++;
        LOGI("[MEM] Privatized: %lx-%lx (%zu bytes) [%s]", start, end, size, perms);
    }
    
    fclose(maps);
    LOGI("[MEM] Privatized %d property regions", g_privatizedRegions);
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
        LOGW("[MEM] mprotect WRITE failed for %s (errno=%d)", name, errno);
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
        LOGW("[MEM] No privatized regions - skipping memory patching");
        return;
    }
    
    HwCompat& hw = HwCompat::getInstance();
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
    
    // v6.0: Dynamische Properties aus Bridge-Datei patchen
    for (const auto& [propName, propValue] : g_dynamicProps) {
        if (patchPropertyDirect(propName.c_str(), propValue.c_str())) {
            patched++;
        }
    }
    
    LOGI("[MEM] Direct memory patched: %d properties (v6.0: bridge-driven, %zu dynamic props)",
         patched, g_dynamicProps.size());
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

[[maybe_unused]] static void _propReadCallbackShim(void* cookie, const char* name, const char* value, uint32_t serial) {
    PropReadCookieOverride* ctx = static_cast<PropReadCookieOverride*>(cookie);
    // Liefere den Override-Wert statt des Original-Werts
    ctx->origCallback(ctx->origCookie, name, ctx->overrideValue, serial);
}

static void _hooked_prop_read_callback(
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
    HwCompat& hw = HwCompat::getInstance();
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
        // v6.0: Dynamic Property Overrides (aus Bridge-Datei)
        const char* dynVal = lookupDynamicProp(captured.name);
        if (dynVal) {
            overrideVal = dynVal;
        }
    }
    
    if (overrideVal) {
        callback(cookie, captured.name, overrideVal, 0);
    } else {
        g_origPropReadCallback(pi, callback, cookie);
    }
}

// ==============================================================================
// Hook: __system_property_read (Ältere API - von manchen NDK-Libraries genutzt)
// ==============================================================================

static int _hooked_system_property_read(const void* pi, char* name, char* value) {
    if (!g_origSysPropRead) return -1;
    
    // Original aufrufen um den echten Namen und Wert zu bekommen
    int result = g_origSysPropRead(pi, name, value);
    
    if (!name || !value) return result;
    
    // Identity Properties aus der Bridge
    HwCompat& hw = HwCompat::getInstance();
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
    
    // v6.0: Dynamic Property Overrides (aus Bridge-Datei)
    const char* dynOverride = lookupDynamicProp(name);
    if (dynOverride) {
        size_t len = strlen(dynOverride);
        if (len > 91) len = 91;
        memcpy(value, dynOverride, len);
        value[len] = '\0';
        return (int)len;
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

static ssize_t _hooked_sendmsg(int sockfd, const struct msghdr* msg, int flags) {
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
                        LOGI("[HW] Tracked RTM_GETLINK socket fd=%d (MAC will be spoofed on response)", sockfd);
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
    HwCompat& hw = HwCompat::getInstance();
    
    char serial[128] = {}, mac[24] = {}, imei1[32] = {};
    hw.getSerial(serial, sizeof(serial));
    hw.getWifiMac(mac, sizeof(mac));
    hw.getImei1(imei1, sizeof(imei1));
    
    if (!serial[0] || !mac[0] || !imei1[0]) {
        LOGW("[HW] Atomicity FAIL: Missing identity (serial=%s, mac=%s, imei=%s)", 
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
    
    LOGI("[HW] Atomicity OK: Serial=%s MAC=%s IMEI=%s", serial, mac, imei1);
    return true;
}

// ==============================================================================
// GOT Patching — for functions with short prologues (AMediaDrm_getProperty*)
// Modifies the GOT in loaded ELF modules so PLT calls go through our hooks.
// ==============================================================================

#include <elf.h>
#include <link.h>

struct GotPatchEntry {
    const char* symbol_name;
    void* replacement;
    void** original_save;
};

static int _got_patch_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    GotPatchEntry* entry = static_cast<GotPatchEntry*>(data);
    
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    
    const char* name = info->dlpi_name;
    bool isAppLib = false;
    for (int i = 0; i < ENC_GOT_LIBS_COUNT; i++) {
        char decoded[16];
        _xdec(decoded, ENC_GOT_LIBS[i].data, ENC_GOT_LIBS[i].len);
        decoded[ENC_GOT_LIBS[i].len] = '\0';
        if (strstr(name, decoded) != nullptr) { isAppLib = true; break; }
    }
    if (!isAppLib) return 0;
    
    ElfW(Addr) base = info->dlpi_addr;
    const ElfW(Phdr)* dynPhdr = nullptr;
    
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynPhdr = &info->dlpi_phdr[i];
            break;
        }
    }
    if (!dynPhdr) return 0;
    
    ElfW(Dyn)* dyn = reinterpret_cast<ElfW(Dyn)*>(base + dynPhdr->p_vaddr);
    
    ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    ElfW(Rela)* rela = nullptr;
    size_t rela_count = 0;
    ElfW(Rela)* plt_rela = nullptr;
    size_t plt_rela_count = 0;
    
    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB: symtab = reinterpret_cast<ElfW(Sym)*>(dyn[i].d_un.d_ptr); break;
            case DT_STRTAB: strtab = reinterpret_cast<const char*>(dyn[i].d_un.d_ptr); break;
            case DT_RELA: rela = reinterpret_cast<ElfW(Rela)*>(dyn[i].d_un.d_ptr); break;
            case DT_RELASZ: rela_count = dyn[i].d_un.d_val / sizeof(ElfW(Rela)); break;
            case DT_JMPREL: plt_rela = reinterpret_cast<ElfW(Rela)*>(dyn[i].d_un.d_ptr); break;
            case DT_PLTRELSZ: plt_rela_count = dyn[i].d_un.d_val / sizeof(ElfW(Rela)); break;
        }
    }
    
    if (!symtab || !strtab) return 0;
    
    auto patchRelaTable = [&](ElfW(Rela)* table, size_t count) {
        if (!table) return;
        for (size_t i = 0; i < count; i++) {
            uint32_t sym_idx = ELF64_R_SYM(table[i].r_info);
            if (sym_idx == 0) continue;
            
            const char* sym_name = strtab + symtab[sym_idx].st_name;
            if (strcmp(sym_name, entry->symbol_name) != 0) continue;
            
            void** got_entry = reinterpret_cast<void**>(base + table[i].r_offset);
            
            size_t pageSize = sysconf(_SC_PAGESIZE);
            uintptr_t pageStart = reinterpret_cast<uintptr_t>(got_entry) & ~(pageSize - 1);
            
            if (mprotect(reinterpret_cast<void*>(pageStart), pageSize * 2,
                         PROT_READ | PROT_WRITE) != 0) continue;
            
            if (*entry->original_save == nullptr) {
                *entry->original_save = *got_entry;
            }
            *got_entry = entry->replacement;
            
            mprotect(reinterpret_cast<void*>(pageStart), pageSize * 2, PROT_READ);
            
            LOGI("[GOT] Patched %s in %s (GOT@%p)", entry->symbol_name, name, got_entry);
        }
    };
    
    patchRelaTable(rela, rela_count);
    patchRelaTable(plt_rela, plt_rela_count);
    
    return 0;
}

static bool installGotHook(const char* symbol, void* replacement, void** originalSave) {
    GotPatchEntry entry = { symbol, replacement, originalSave };
    dl_iterate_phdr(_got_patch_callback, &entry);
    return (*originalSave != nullptr);
}

// ==============================================================================
// LSPlant ART-Hooks (Java Method Interception)
// ==============================================================================

static bool g_lsplantInitialized = false;

static void* _lsplant_inline_hook(void* target, void* hooker) {
    void* orig = nullptr;
    if (install_inline_hook(target, hooker, &orig))
        return orig;
    return nullptr;
}

static bool _lsplant_inline_unhook(void* func) {
    (void)func;
    return false;
}

static void* _resolve_art_symbol(std::string_view symbol) {
    static void* libart = nullptr;
    if (!libart) {
        libart = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
        if (!libart) libart = dlopen("libart.so", RTLD_NOW);
    }
    if (!libart) return nullptr;
    return dlsym(libart, std::string(symbol).c_str());
}

static bool initLSPlant(JNIEnv* env) {
    if (g_lsplantInitialized) return true;

    lsplant::InitInfo info;
    info.inline_hooker = _lsplant_inline_hook;
    info.inline_unhooker = _lsplant_inline_unhook;
    info.art_symbol_resolver = _resolve_art_symbol;

    if (!lsplant::Init(env, info)) {
        LOGE("[HW] LSPlant Init failed");
        return false;
    }
    g_lsplantInitialized = true;
    LOGI("[HW] LSPlant initialized");
    return true;
}

// JNI native callbacks for the generated hooker class
static jstring g_globalFakeImei = nullptr;
static jstring g_globalFakeSubscriberId = nullptr;
static jstring g_globalFakeSimSerial = nullptr;
static jstring g_globalFakeMac = nullptr;

static jobject JNICALL nativeHookGetImei(JNIEnv* env, [[maybe_unused]] jobject thiz, [[maybe_unused]] jobjectArray args) {
    return g_globalFakeImei ? g_globalFakeImei : env->NewStringUTF("");
}

static jobject JNICALL nativeHookGetSubscriberId(JNIEnv* env, [[maybe_unused]] jobject thiz, [[maybe_unused]] jobjectArray args) {
    return g_globalFakeSubscriberId ? g_globalFakeSubscriberId : env->NewStringUTF("");
}

static jobject JNICALL nativeHookGetSimSerial(JNIEnv* env, [[maybe_unused]] jobject thiz, [[maybe_unused]] jobjectArray args) {
    return g_globalFakeSimSerial ? g_globalFakeSimSerial : env->NewStringUTF("");
}

static jobject JNICALL nativeHookGetMacAddress(JNIEnv* env, [[maybe_unused]] jobject thiz, [[maybe_unused]] jobjectArray args) {
    return g_globalFakeMac ? g_globalFakeMac : env->NewStringUTF("02:00:00:00:00:00");
}

struct JavaHookDef {
    const char* className;
    const char* methodName;
    const char* sig;
    void* nativeCallback;
};

static bool installArtHooks(JNIEnv* env) {
    if (!env || !initLSPlant(env)) return false;

    auto& hw = HwCompat::getInstance();
    char buf[128];

    hw.getImei1(buf, sizeof(buf));
    g_globalFakeImei = (jstring)env->NewGlobalRef(env->NewStringUTF(buf));

    hw.getImsi(buf, sizeof(buf));
    g_globalFakeSubscriberId = (jstring)env->NewGlobalRef(env->NewStringUTF(buf));

    hw.getSimSerial(buf, sizeof(buf));
    g_globalFakeSimSerial = (jstring)env->NewGlobalRef(env->NewStringUTF(buf));

    hw.getWifiMac(buf, sizeof(buf));
    g_globalFakeMac = (jstring)env->NewGlobalRef(env->NewStringUTF(buf));

    // For each target: get reflected Method, create hooker, hook via LSPlant
    // LSPlant generates a stub class internally and handles the callback routing.
    JavaHookDef targets[] = {
        {"android/telephony/TelephonyManager", "getImei",            "()Ljava/lang/String;",  (void*)nativeHookGetImei},
        {"android/telephony/TelephonyManager", "getImei",            "(I)Ljava/lang/String;", (void*)nativeHookGetImei},
        {"android/telephony/TelephonyManager", "getDeviceId",        "()Ljava/lang/String;",  (void*)nativeHookGetImei},
        {"android/telephony/TelephonyManager", "getDeviceId",        "(I)Ljava/lang/String;", (void*)nativeHookGetImei},
        {"android/telephony/TelephonyManager", "getSubscriberId",    "()Ljava/lang/String;",  (void*)nativeHookGetSubscriberId},
        {"android/telephony/TelephonyManager", "getSubscriberId",    "(I)Ljava/lang/String;", (void*)nativeHookGetSubscriberId},
        {"android/telephony/TelephonyManager", "getSimSerialNumber", "()Ljava/lang/String;",  (void*)nativeHookGetSimSerial},
        {"android/net/wifi/WifiInfo",          "getMacAddress",      "()Ljava/lang/String;",  (void*)nativeHookGetMacAddress},
    };

    // LSPlant callback class: We need a Java class with Object(Object[]) methods.
    // We use java.lang.Object and create methods at runtime via JNI reflection.
    // LSPlant's Hook() handles this by generating stub classes.
    jclass callbackCls = env->FindClass("java/lang/Object");
    if (!callbackCls || env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("[HW] ART hooks: Cannot find Object class");
        return false;
    }

    int installed = 0;
    for (auto& t : targets) {
        jclass cls = env->FindClass(t.className);
        if (!cls || env->ExceptionCheck()) { env->ExceptionClear(); continue; }

        jmethodID mid = env->GetMethodID(cls, t.methodName, t.sig);
        if (!mid || env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(cls); continue; }

        jobject reflected = env->ToReflectedMethod(cls, mid, JNI_FALSE);
        if (!reflected || env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(cls); continue; }

        bool ok = lsplant::Deoptimize(env, reflected);
        if (ok) installed++;

        env->DeleteLocalRef(reflected);
        env->DeleteLocalRef(cls);
    }

    LOGI("[HW] ART deoptimized: %d/%d methods (LSPlant)", installed, (int)(sizeof(targets)/sizeof(targets[0])));
    return installed > 0;
}

// ==============================================================================
// Hook Installation
// ==============================================================================

static void installAllHooks() {
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) {
        LOGE("[HW] Failed to open libc");
        return;
    }
    
    int installed = 0;

    // Ghost Protocol: Reduziert auf essentielle Hooks.
    // File-I/O (open/fopen/read/fgets) → ersetzt durch SUSFS add_open_redirect
    // Dir-Enum (opendir/readdir/closedir) → ersetzt durch SUSFS add_sus_path
    struct { const char* sym; void* hook; void** orig; } libcHooks[] = {
        {"__system_property_get",           (void*)_hooked_system_property_get,   (void**)&g_origSystemPropertyGet},
        {"__system_property_read_callback", (void*)_hooked_prop_read_callback,    (void**)&g_origPropReadCallback},
        {"__system_property_read",          (void*)_hooked_system_property_read,  (void**)&g_origSysPropRead},
        {"getifaddrs",                      (void*)_hooked_getifaddrs,           (void**)&g_origGetifaddrs},
        {"ioctl",                           (void*)_hooked_ioctl,                (void**)&g_origIoctl},
        {"sendmsg",                         (void*)_hooked_sendmsg,              (void**)&g_origSendmsg},
        {"recvmsg",                         (void*)_hooked_recvmsg,              (void**)&g_origRecvmsg},
    };

    for (auto& h : libcHooks) {
        void* addr = dlsym(libc, h.sym);
        if (addr && install_inline_hook(addr, h.hook, h.orig))
            installed++;
    }
    LOGI("[HW] libc hooks: %d/%d via inline dispatch",
         installed, (int)(sizeof(libcHooks)/sizeof(libcHooks[0])));

    // Widevine NDK Hooks via signal-based dispatch + GOT-Patching
    void* mediandk = dlopen("libmediandk.so", RTLD_NOW | RTLD_NOLOAD);
    if (!mediandk)
        mediandk = dlopen("libmediandk.so", RTLD_NOW);

    if (mediandk) {
        struct { const char* sym; void* hook; void** orig; } ndkHooks[] = {
            {"AMediaDrm_createByUUID",            (void*)_hooked_AMediaDrm_createByUUID,            (void**)&g_origAMediaDrmCreateByUUID},
            {"AMediaDrm_release",                 (void*)_hooked_AMediaDrm_release,                 (void**)&g_origAMediaDrmRelease},
            {"AMediaDrm_isCryptoSchemeSupported",  (void*)_hooked_AMediaDrm_isCryptoSchemeSupported, (void**)&g_origAMediaDrmIsCryptoSchemeSupported},
        };
        for (auto& h : ndkHooks) {
            void* addr = dlsym(mediandk, h.sym);
            if (addr && install_inline_hook(addr, h.hook, h.orig))
                installed++;
        }

        // GOT-Patching for getPropertyByteArray/String (short prologues)
        if (installGotHook("AMediaDrm_getPropertyByteArray",
                           (void*)_hooked_AMediaDrm_getPropertyByteArray,
                           (void**)&g_origAMediaDrmGetPropertyByteArray))
            installed++;

        if (installGotHook("AMediaDrm_getPropertyString",
                           (void*)_hooked_AMediaDrm_getPropertyString,
                           (void**)&g_origAMediaDrmGetPropertyString))
            installed++;

        LOGI("[HW] Widevine hooks installed (inline+GOT)");
    }

    LOGI("[HW] Total hooks installed: %d", installed);
}

// ==============================================================================
// Zygisk Module
// ==============================================================================

class CompatModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        m_api = api;
        m_env = env;
        
        if (checkKillSwitch()) {
            LOGW("[HW] Kill-switch active");
            return;
        }
        
        LOGI("[HW] Module loaded");
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
        
        // ======================================================================
        // v6.1: BLACKLIST CHECK — Erste Prüfung, höchste Priorität!
        // Google-Prozesse MÜSSEN vanilla bleiben für DEVICE_INTEGRITY.
        // Kein Spoofing, kein Memory-Patching, keine Hooks. Punkt.
        // ======================================================================
        if (isBlacklistedProcess(m_packageName)) {
            LOGI("[HW] BLACKLISTED: %s — kein Spoofing (DEVICE_INTEGRITY Schutz)", m_packageName);
            if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            m_shouldInject = false;
            return;
        }
        
        if (!isTargetApp(m_packageName)) {
            if (m_api) m_api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            m_shouldInject = false;
        } else {
            m_shouldInject = true;
            LOGI("[HW] Target: %s — Spoofing wird angewendet", m_packageName);
        }
    }
    
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        (void)args;
        if (!m_shouldInject || g_killSwitchActive.load()) return;
        
        // FIX-20: Bridge muss geladen sein — sonst keine Hooks
        if (!g_bridgeLoaded.load()) {
            LOGW("[HW] Bridge nicht geladen — Hooks DEAKTIVIERT für %s", m_packageName);
            return;
        }
        
        // Atomicity Check: Identität muss konsistent geladen sein
        if (!verifyIdentityAtomicity()) {
            LOGW("[HW] Atomicity check FAILED - hooks deaktiviert für %s", m_packageName);
            return;
        }
        
        LOGI("[HW] Init for %s", m_packageName);
        
        // PHASE 1: Property Area Privatisierung (MAP_SHARED → MAP_PRIVATE)
        // MUSS vor den Hooks passieren!
        privatizePropertyMappings();
        
        // PHASE 2: Direct Memory Patching (Werte direkt im RAM ändern)
        // Danach braucht __system_property_get für diese Props KEINEN Hook mehr
        patchAllPropertiesInMemory();
        
        // PHASE 3: Native hooks installieren
        installAllHooks();
        
        // PHASE 4: ART-Level Deoptimierung (verhindert JIT-Inlining von Telephony/WiFi Methoden)
        installArtHooks(m_env);
        
        LOGI("[HW] Init complete: %d regions", g_privatizedRegions);
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

REGISTER_ZYGISK_MODULE(CompatModule)

static void companionHandler(int fd) {
    loadBridge();
    close(fd);
}

REGISTER_ZYGISK_COMPANION(companionHandler)
