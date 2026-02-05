/**
 * Project Titan – TitanHardwareState
 * Shared zwischen Zygisk-Modul und AuditEngine.
 * Native Bridge für Identitäts-Spoofing bei Kernel-Block.
 */
#ifndef TITAN_HARDWARE_H
#define TITAN_HARDWARE_H

#include <string>
#include <mutex>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

struct TitanHardwareState {
    char serial[96];
    char boot_serial[96];
    char imei[32];
};

void TitanHardwareState_Init(struct TitanHardwareState* s);
void TitanHardwareState_SetSerial(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetBootSerial(struct TitanHardwareState* s, const char* v);
void TitanHardwareState_SetImei(struct TitanHardwareState* s, const char* v);
const char* TitanHardwareState_GetSerial(struct TitanHardwareState* s);
const char* TitanHardwareState_GetBootSerial(struct TitanHardwareState* s);

#ifdef __cplusplus
}
#endif

#endif
