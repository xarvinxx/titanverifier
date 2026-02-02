/**
 * Project Titan – Audit Engine
 * Java-Abfrage: Build.SERIAL, Build.MODEL, Build.ID, Build.FINGERPRINT (Kotlin-Seite).
 * Native-Abfrage: __system_property_get für ro.serialno, ro.boot.serialno etc.
 * Vergleich Serial Java vs Native → Indikator für Hook (Abweichung = Rot in UI).
 */

#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <string>

#define LOG_TAG "AuditEngine"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Bionic (Android libc) – nicht im öffentlichen NDK-Header, Symbol in libc vorhanden
extern "C" int __system_property_get(const char* name, char* value);

namespace {

constexpr size_t kPropValueMax = 92;

std::string getSystemProperty(const char* name) {
    char value[kPropValueMax] = {};
    if (__system_property_get(name, value) > 0) {
        return std::string(value);
    }
    return {};
}

// Key (von Java) auf native Property-Namen abbilden
std::string getNativePropertyForKey(const char* key) {
    if (key == nullptr) return {};

    if (strcmp(key, "SERIAL") == 0) {
        std::string v = getSystemProperty("ro.serialno");
        if (v.empty()) v = getSystemProperty("ro.boot.serialno");
        return v;
    }
    if (strcmp(key, "MODEL") == 0) return getSystemProperty("ro.product.model");
    if (strcmp(key, "ID") == 0) return getSystemProperty("ro.build.id");
    if (strcmp(key, "FINGERPRINT") == 0) return getSystemProperty("ro.build.fingerprint");

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

} // extern "C"
