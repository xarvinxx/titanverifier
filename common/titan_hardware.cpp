/**
 * TitanHardwareState Implementierung
 */
#include "titan_hardware.h"
#include <mutex>

static std::mutex g_titanMutex;
static struct TitanHardwareState g_state = {};
static bool g_initialized = false;

static void ensureInit() {
    if (!g_initialized) {
        g_state.serial[0] = '\0';
        g_state.boot_serial[0] = '\0';
        g_state.imei[0] = '\0';
        g_initialized = true;
    }
}

void TitanHardwareState_Init(struct TitanHardwareState* s) {
    (void)s;
    std::lock_guard<std::mutex> lock(g_titanMutex);
    ensureInit();
}

void TitanHardwareState_SetSerial(struct TitanHardwareState* s, const char* v) {
    (void)s;
    std::lock_guard<std::mutex> lock(g_titanMutex);
    ensureInit();
    if (v) {
        strncpy(g_state.serial, v, sizeof(g_state.serial) - 1);
        g_state.serial[sizeof(g_state.serial) - 1] = '\0';
    } else {
        g_state.serial[0] = '\0';
    }
}

void TitanHardwareState_SetBootSerial(struct TitanHardwareState* s, const char* v) {
    (void)s;
    std::lock_guard<std::mutex> lock(g_titanMutex);
    ensureInit();
    if (v) {
        strncpy(g_state.boot_serial, v, sizeof(g_state.boot_serial) - 1);
        g_state.boot_serial[sizeof(g_state.boot_serial) - 1] = '\0';
    } else {
        g_state.boot_serial[0] = '\0';
    }
}

void TitanHardwareState_SetImei(struct TitanHardwareState* s, const char* v) {
    (void)s;
    std::lock_guard<std::mutex> lock(g_titanMutex);
    ensureInit();
    if (v) {
        strncpy(g_state.imei, v, sizeof(g_state.imei) - 1);
        g_state.imei[sizeof(g_state.imei) - 1] = '\0';
    } else {
        g_state.imei[0] = '\0';
    }
}

const char* TitanHardwareState_GetSerial(struct TitanHardwareState* s) {
    (void)s;
    std::lock_guard<std::mutex> lock(g_titanMutex);
    ensureInit();
    return g_state.serial;
}

const char* TitanHardwareState_GetBootSerial(struct TitanHardwareState* s) {
    (void)s;
    std::lock_guard<std::mutex> lock(g_titanMutex);
    ensureInit();
    return g_state.boot_serial;
}
