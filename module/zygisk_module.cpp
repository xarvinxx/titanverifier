/**
 * Project Titan – Zygisk Module
 * Hook für __system_property_get: ro.serialno aus TitanHardwareState
 * Nutzt postAppSpecialize für com.titan.verifier
 * android_get_device_api_level() für Android 14 Kompatibilität
 */

#include <dlfcn.h>
#include <android/log.h>
#include <android/api-level.h>
#include <cstring>
#include <cstdio>
#include <string>

#include "../include/zygisk.hpp"
#include "../common/titan_hardware.h"

#define LOG_TAG "TitanZygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define TITAN_SERIAL_CACHE "/data/data/com.titan.verifier/cache/.titan_serial"
#define TITAN_BOOT_SERIAL_CACHE "/data/data/com.titan.verifier/cache/.titan_boot_serial"

// Original __system_property_get (libc)
using SystemPropertyGetFn = int (*)(const char* name, char* value);
static SystemPropertyGetFn real_system_property_get = nullptr;

static struct TitanHardwareState g_titanState = {};

static void try_load_serial_from_cache() {
    char buf[96] = {};
    FILE* f = fopen(TITAN_SERIAL_CACHE, "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f) && buf[0]) {
            buf[strcspn(buf, "\n\r")] = '\0';
            TitanHardwareState_SetSerial(&g_titanState, buf);
        }
        fclose(f);
    }
    f = fopen(TITAN_BOOT_SERIAL_CACHE, "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f) && buf[0]) {
            buf[strcspn(buf, "\n\r")] = '\0';
            TitanHardwareState_SetBootSerial(&g_titanState, buf);
        }
        fclose(f);
    }
}

// Hook-Handler: Bei ro.serialno / ro.boot.serialno → TitanHardwareState
extern "C" int hooked_system_property_get(const char* name, char* value) {
    if (name == nullptr || value == nullptr) {
        if (real_system_property_get) return real_system_property_get(name, value);
        return 0;
    }
    try_load_serial_from_cache();
    if (strcmp(name, "ro.serialno") == 0) {
        const char* v = TitanHardwareState_GetSerial(&g_titanState);
        if (v && v[0] != '\0') {
            strncpy(value, v, 91);
            value[91] = '\0';
            return (int)strlen(value);
        }
    }
    if (strcmp(name, "ro.boot.serialno") == 0) {
        const char* v = TitanHardwareState_GetBootSerial(&g_titanState);
        if (v && v[0] != '\0') {
            strncpy(value, v, 91);
            value[91] = '\0';
            return (int)strlen(value);
        }
    }
    if (real_system_property_get)
        return real_system_property_get(name, value);
    return 0;
}

static void install_property_hook() {
    void* libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) {
        LOGI("dlopen libc failed");
        return;
    }
    real_system_property_get = (SystemPropertyGetFn)dlsym(libc, "__system_property_get");
    dlclose(libc);
    if (!real_system_property_get) {
        LOGI("dlsym __system_property_get failed");
        return;
    }
#if defined(USE_DOBBY) && USE_DOBBY
    void* hook_lib = dlopen("libdobby.so", RTLD_NOW);
    if (hook_lib) {
        auto DobbyHook = (int(*)(void*,void*,void**))dlsym(hook_lib, "DobbyHook");
        if (DobbyHook && DobbyHook((void*)real_system_property_get,
                (void*)hooked_system_property_get,
                (void**)&real_system_property_get) == 0) {
            LOGI("DobbyHook installed");
        }
        dlclose(hook_lib);
    }
#else
    LOGI("property hook ready (Dobby nicht gelinkt, Cache-Bridge aktiv)");
#endif
}

class TitanModule : public zygisk::ModuleBase {
public:
    static TitanModule& instance() {
        static TitanModule inst;
        return inst;
    }

    void onLoad(void* api) override {
        (void)api;
        TitanHardwareState_Init(&g_titanState);
        LOGI("TitanModule onLoad, API level %d", android_get_device_api_level());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        (void)args;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (args == nullptr || args->package_name == nullptr) return;
        const char* pkg = args->package_name;
        if (strcmp(pkg, "com.titan.verifier") != 0) return;

        int api = android_get_device_api_level();
        if (api < 30) {
            LOGI("Skip hook: API %d < 30", api);
            return;
        }

        LOGI("Injecting into com.titan.verifier (API %d)", api);
        install_property_hook();
    }
};

REGISTER_ZYGISK_MODULE(TitanModule)
