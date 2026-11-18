#include "WinSecRuntime/WinSecRuntime.h"

static HANDLE checked = nullptr;

static void on_check(secure::Report) {
    ::SetEvent(checked);
}

int main() {
    checked = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!checked) return 1;
    DWORD result;
    {
        secure::runtime::Heartbeat heartbeat(60000, &on_check);
        result = ::WaitForSingleObject(checked, 10000);
    }
    ::CloseHandle(checked);
    return result == WAIT_OBJECT_0 ? 0 : 1;
}
