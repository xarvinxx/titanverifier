/**
 * Project Titan – Ground Truth Audit Engine
 * - Native properties, Widevine, Root forensics, SELinux, MAC
 * - GPU Renderer (EGL/GLES), Input devices (/proc/bus/input/devices), RAM (/proc/meminfo)
 */

#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <string>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <mutex>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <media/NdkMediaDrm.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>

#define LOG_TAG "AuditEngine"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" int __system_property_get(const char* name, char* value);

namespace {

constexpr size_t kPropValueMax = 92;

constexpr uint8_t kWidevineUuid[16] = {
    0xed, 0x28, 0x2e, 0x16, 0xfd, 0xd2, 0x47, 0xc7,
    0x8d, 0x6d, 0x09, 0x94, 0x64, 0x62, 0xf3, 0x67
};

// Thread-safe native identity cache (synced from Java/Root)
static std::mutex g_identityMutex;
static std::string g_syncedGsfId;
static std::string g_syncedAndroidId;

// Native-Backdoor: IMEI Hook-Memory (wenn Kernel Java-API blockiert)
static std::string hooked_imei = "PENDING";

std::string getSystemProperty(const char* name) {
    char value[kPropValueMax] = {};
    if (__system_property_get(name, value) > 0) {
        return std::string(value);
    }
    return {};
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex[(data[i] >> 4) & 0xf];
        out += hex[data[i] & 0xf];
    }
    return out;
}

std::string getWidevineIdImpl() {
    // Prüfen ob libmediadrm.so bzw. libmediandk.so für die App zugänglich ist
    void* handle = dlopen("libmediadrm.so", RTLD_NOW);
    if (!handle) {
        handle = dlopen("libmediandk.so", RTLD_NOW);
    }
    if (!handle) {
        const char* err = dlerror();
        LOGI("Widevine: dlopen failed, dlerror=%s", err ? err : "unknown");
        return "ERROR: LIBRARY_UNAVAILABLE(dlopen)";
    }
    dlclose(handle);  // Nur Verfügbarkeitsprüfung; eigentliche Calls nutzen Link-Zeit-Bindung

    // Widevine UUID: ED282E16-FDD2-47C7-8D6D-09946462F367 (16 bytes, big-endian)
    AMediaDrm* drm = AMediaDrm_createByUUID(kWidevineUuid);
    if (drm == nullptr) {
        const int err = errno;
        LOGI("AMediaDrm_createByUUID failed (null), UUID=ED282E16-FDD2-47C7-8D6D-09946462F367, errno=%d", err);
        return "ERROR: CREATE_FAILED(errno=" + std::to_string(err) + ")";
    }

    AMediaDrmByteArray value = {};
    media_status_t status = AMediaDrm_getPropertyByteArray(
            drm, PROPERTY_DEVICE_UNIQUE_ID, &value);
    std::string result;
    if (status == AMEDIA_OK && value.ptr != nullptr && value.length > 0) {
        result = bytesToHex(value.ptr, value.length);
    } else {
        LOGI("AMediaDrm_getPropertyByteArray failed, status=%d (AMEDIA_OK=0)", static_cast<int>(status));
        result = "ERROR: GET_PROPERTY_" + std::to_string(static_cast<int>(status));
    }
    AMediaDrm_release(drm);
    return result;
}

#ifndef __NR_statx
#  define __NR_statx 291
#endif
#ifndef AT_FDCWD
#  define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x100
#endif

struct StatxBuf { char pad[256]; };

bool statxExists(const char* path) {
    StatxBuf buf = {};
    long ret = syscall(__NR_statx, static_cast<long>(AT_FDCWD), path,
                      AT_SYMLINK_NOFOLLOW, 0u, &buf);
    return (ret == 0);
}

std::string readSmallFile(const char* path, size_t maxLen = 64) {
    std::ifstream f(path);
    if (!f) return {};
    std::string line;
    if (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.length() > maxLen) line.resize(maxLen);
        return line;
    }
    return {};
}

int getSelinuxEnforceImpl() {
    std::string s = readSmallFile("/sys/fs/selinux/enforce", 4);
    if (!s.empty()) {
        return (s[0] == '1') ? 1 : 0;
    }
    // Fallback: ro.boot.selinux Property (z.B. "enforcing" / "permissive")
    char prop[kPropValueMax] = {};
    if (__system_property_get("ro.boot.selinux", prop) > 0) {
        std::string p(prop);
        if (p.find("enforcing") != std::string::npos || p == "1") return 1;
        if (p.find("permissive") != std::string::npos || p == "0") return 0;
    }
    return -1;
}

std::string getMacAddressWlan0Impl() {
    return readSmallFile("/sys/class/net/wlan0/address", 32);
}

std::string getNativePropertyForKey(const char* key) {
    if (key == nullptr) return {};

    if (strcmp(key, "SERIAL") == 0) {
        std::string v = getSystemProperty("ro.serialno");
        if (v.empty()) v = getSystemProperty("ro.boot.serialno");
        if (v.empty()) return "ROOT_REQUIRED";  // SELinux block → Kotlin nutzt RootShell getprop
        return v;
    }
    if (strcmp(key, "BOOT_SERIAL") == 0) return getSystemProperty("ro.boot.serialno");
    if (strcmp(key, "MODEL") == 0) return getSystemProperty("ro.product.model");
    if (strcmp(key, "BOARD") == 0) return getSystemProperty("ro.product.board");
    if (strcmp(key, "ID") == 0) return getSystemProperty("ro.build.id");
    if (strcmp(key, "FINGERPRINT") == 0) return getSystemProperty("ro.build.fingerprint");
    return {};
}

// ─── GPU (EGL/GLES) ────────────────────────────────────────────────────────
std::string getGpuRendererImpl() {
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) return {};

    if (eglInitialize(display, nullptr, nullptr) != EGL_TRUE) {
        eglTerminate(display);
        return {};
    }

    const EGLint configAttribs[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_NONE
    };
    EGLConfig config = nullptr;
    EGLint numConfig = 0;
    if (eglChooseConfig(display, configAttribs, &config, 1, &numConfig) != EGL_TRUE || numConfig == 0) {
        eglTerminate(display);
        return {};
    }

    static const EGLint pbufferAttribs[] = { EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE };
    EGLSurface surface = eglCreatePbufferSurface(display, config, pbufferAttribs);
    if (surface == EGL_NO_SURFACE) {
        eglTerminate(display);
        return {};
    }

    const EGLint contextAttribs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttribs);
    if (context == EGL_NO_CONTEXT) {
        eglDestroySurface(display, surface);
        eglTerminate(display);
        return {};
    }

    if (eglMakeCurrent(display, surface, surface, context) != EGL_TRUE) {
        eglDestroyContext(display, context);
        eglDestroySurface(display, surface);
        eglTerminate(display);
        return {};
    }

    const char* vendor = reinterpret_cast<const char*>(glGetString(GL_VENDOR));
    const char* renderer = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
    std::string v = vendor ? vendor : "";
    std::string r = renderer ? renderer : "";

    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroyContext(display, context);
    eglDestroySurface(display, surface);
    eglTerminate(display);

    return "VENDOR: " + v + " / RENDERER: " + r;
}

// ─── Input devices (/proc/bus/input/devices) ─────────────────────────────────
static bool containsEmulatorKeyword(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
    return lower.find("virtual") != std::string::npos ||
           lower.find("vbox") != std::string::npos ||
           lower.find("goldfish") != std::string::npos;
}

std::string getInputDeviceListImpl() {
    std::ifstream f("/proc/bus/input/devices");
    if (!f) return {};
    std::string line;
    std::ostringstream out;
    bool first = true;
    while (std::getline(f, line)) {
        const char* prefix = "N: Name=";
        if (line.size() > 8 && line.compare(0, 8, prefix) == 0) {
            std::string name = line.substr(8);
            while (!name.empty() && (name.back() == '\r' || name.back() == '\n')) name.pop_back();
            if (containsEmulatorKeyword(name)) name += " [EMULATOR]";
            if (!first) out << "\n";
            out << name;
            first = false;
        }
    }
    return out.str();
}

// ─── RAM (MemTotal from /proc/meminfo) ──────────────────────────────────────
std::string getTotalRamImpl() {
    std::ifstream f("/proc/meminfo");
    if (!f) return {};
    std::string line;
    while (std::getline(f, line)) {
        if (line.compare(0, 9, "MemTotal:") != 0) continue;
        size_t i = 9;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        size_t start = i;
        while (i < line.size() && std::isdigit(static_cast<unsigned char>(line[i]))) ++i;
        std::string numStr = line.substr(start, i - start);
        unsigned long kB = 0;
        try { kB = std::stoul(numStr); } catch (...) { return {}; }
        double gb = kB / (1024.0 * 1024.0);
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f GB", gb);
        return std::string(buf);
    }
    return {};
}

} // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getNativeProperty(JNIEnv* env, jclass clazz, jstring key) {
    (void)clazz;
    if (key == nullptr) return env->NewStringUTF("");

    const char* keyChars = env->GetStringUTFChars(key, nullptr);
    if (keyChars == nullptr) return env->NewStringUTF("");

    std::string value = getNativePropertyForKey(keyChars);
    env->ReleaseStringUTFChars(key, keyChars);
    return env->NewStringUTF(value.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getWidevineID(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::string id = getWidevineIdImpl();
    return env->NewStringUTF(id.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_titan_verifier_AuditEngine_checkRootForensics(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    return statxExists("/data/adb/ksu") ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_titan_verifier_AuditEngine_checkRootPath(JNIEnv* env, jclass clazz, jstring path) {
    (void)clazz;
    if (path == nullptr) return JNI_FALSE;
    const char* pathChars = env->GetStringUTFChars(path, nullptr);
    if (pathChars == nullptr) return JNI_FALSE;
    bool exists = statxExists(pathChars);
    env->ReleaseStringUTFChars(path, pathChars);
    return exists ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getNativeBoard(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::string board = getSystemProperty("ro.product.board");
    std::string hardware = getSystemProperty("ro.hardware");
    if (board.empty() && hardware.empty()) return env->NewStringUTF("");
    if (board.empty()) return env->NewStringUTF(hardware.c_str());
    if (hardware.empty()) return env->NewStringUTF(board.c_str());
    std::string combined = board + " / " + hardware;
    return env->NewStringUTF(combined.c_str());
}

JNIEXPORT jint JNICALL
Java_com_titan_verifier_AuditEngine_getSelinuxEnforce(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    return getSelinuxEnforceImpl();
}

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getMacAddressWlan0(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::string mac = getMacAddressWlan0Impl();
    return env->NewStringUTF(mac.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getGpuRenderer(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::string s = getGpuRendererImpl();
    return env->NewStringUTF(s.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getInputDeviceList(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::string s = getInputDeviceListImpl();
    return env->NewStringUTF(s.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_titan_verifier_AuditEngine_getTotalRam(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::string s = getTotalRamImpl();
    return env->NewStringUTF(s.c_str());
}

// NativeEngine.setFakeImei: IMEI in Native Hook-Memory setzen (Backdoor bei Kernel-Block)
JNIEXPORT void JNICALL
Java_com_titan_verifier_NativeEngine_setFakeImei(JNIEnv* env, jclass clazz, jstring imei) {
    (void)clazz;
    std::lock_guard<std::mutex> lock(g_identityMutex);
    if (imei != nullptr) {
        const char* chars = env->GetStringUTFChars(imei, nullptr);
        if (chars) {
            hooked_imei = chars;
            env->ReleaseStringUTFChars(imei, chars);
        }
    } else {
        hooked_imei = "PENDING";
    }
}

// NativeEngine.getNativeImei: Hook-Memory IMEI auslesen
JNIEXPORT jstring JNICALL
Java_com_titan_verifier_NativeEngine_getNativeImei(JNIEnv* env, jclass clazz) {
    (void)clazz;
    std::lock_guard<std::mutex> lock(g_identityMutex);
    return env->NewStringUTF(hooked_imei.c_str());
}

// NativeEngine.syncIdentity: Thread-sicher GSF + Android ID im Native-Speicher ablegen
JNIEXPORT void JNICALL
Java_com_titan_verifier_NativeEngine_syncIdentity(JNIEnv* env, jclass clazz, jstring gsfId, jstring androidId) {
    (void)clazz;
    std::lock_guard<std::mutex> lock(g_identityMutex);
    if (gsfId != nullptr) {
        const char* chars = env->GetStringUTFChars(gsfId, nullptr);
        if (chars) {
            g_syncedGsfId = chars;
            env->ReleaseStringUTFChars(gsfId, chars);
        }
    } else {
        g_syncedGsfId.clear();
    }
    if (androidId != nullptr) {
        const char* chars = env->GetStringUTFChars(androidId, nullptr);
        if (chars) {
            g_syncedAndroidId = chars;
            env->ReleaseStringUTFChars(androidId, chars);
        }
    } else {
        g_syncedAndroidId.clear();
    }
}

} // extern "C"
