/**
 * Zygisk API – Magisk / Zygisk Next kompatibel
 * postAppSpecialize, REGISTER_ZYGISK_MODULE
 */
#pragma once

#include <cstdint>
#include <cstdlib>
#include <android/api-level.h>

namespace zygisk {

struct AppSpecializeArgs {
    int32_t *uid;
    int32_t *gid;
    int32_t *gids;
    int32_t *runtime_flags;
    int32_t *mount_external;
    const char *se_info;
    const char *nice_name;
    const char *instruction_set;
    const char *app_data_dir;
    const char *package_name;  // nullable vor pre, gesetzt in post
    int32_t *app_zygote_flags;
};

class ModuleBase {
public:
    virtual void onLoad(void* api) { (void)api; }
    virtual void preAppSpecialize(AppSpecializeArgs* args) { (void)args; }
    virtual void postAppSpecialize(const AppSpecializeArgs* args) { (void)args; }
    virtual ~ModuleBase() = default;
};

template <class T>
void entry_impl(void* self) {
    T::instance().onLoad(self);
}

template <class T>
void preAppSpecialize_impl(void* args) {
    T::instance().preAppSpecialize(static_cast<AppSpecializeArgs*>(args));
}

template <class T>
void postAppSpecialize_impl(void* args) {
    T::instance().postAppSpecialize(static_cast<const AppSpecializeArgs*>(args));
}

} // namespace zygisk

#define REGISTER_ZYGISK_MODULE(ModuleClass)                                  \
    extern "C" {                                                             \
    zygisk::ModuleBase* zygisk_module() {                                    \
        static ModuleClass mod;                                              \
        return &mod;                                                         \
    }                                                                        \
    }
