#include "WinSecRuntime/WinSecRuntime.h"

namespace WinSecRuntime {

bool Initialize(Mode mode, const secure::runtime::Config& cfg) {
    (void)mode;
    (void)cfg;
    return true;
}

void StartIntegrityEngine(const Policy& p) {
#if SECURE_ENABLE_HEARTBEAT
    static secure::runtime::Heartbeat hb(5000, nullptr, p.cfg);
    (void)hb;
#endif
}

secure::Report RunAll(const Policy& p) {
    return secure::runtime::run_all_checks(p.cfg);
}

void EnableAntiDebug(const Policy& p) {
    (void)RunAll(p);
}

void EnableHookGuard(const Policy& p) {
    (void)RunAll(p);
}

} // namespace WinSecRuntime
