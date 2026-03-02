#ifndef WINSECRUNTIME_EXPORTS
#define WINSECRUNTIME_EXPORTS 1
#endif

#include "WinSecRuntime/WinSecRuntime.h"

namespace WinSecRuntime {

WINSECRUNTIME_API bool Initialize(Mode mode, const secure::runtime::Config& cfg) {
    (void)mode;
    (void)cfg;
    return true;
}

WINSECRUNTIME_API void StartIntegrityEngine(const Policy& p) {
#if SECURE_ENABLE_HEARTBEAT
    static secure::runtime::Heartbeat hb(5000, nullptr, p.cfg);
    (void)hb;
#endif
}

WINSECRUNTIME_API secure::Report RunAll(const Policy& p) {
    return secure::runtime::run_all_checks(p.cfg);
}

WINSECRUNTIME_API void EnableAntiDebug(const Policy& p) {
    (void)RunAll(p);
}

WINSECRUNTIME_API void EnableHookGuard(const Policy& p) {
    (void)RunAll(p);
}

} // namespace WinSecRuntime
