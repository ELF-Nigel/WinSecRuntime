# WinSecRuntime

Windows runtime security library for C++20 (MSVC/Clang). Supports header-only usage and a library build layout for static `.lib` or protected `.dll` builds. This project focuses on **defensive** runtime integrity, anti-debug, anti-hook, and injection detection without deception.

## Layout

```
/include
  wingurdrt.h
  WinSecRuntime/
    WinSecRuntime.h
    /core
    /anti_debug
    /anti_hook
    /anti_inject
    /memory_guard
    /integrity
    /network_guard
    /crypto
    /vm_detect
    /runtime_vm
    /self_protect
/src
  core.cpp
  integrity.cpp
  anti_debug.cpp
  anti_hook.cpp
  memory_guard.cpp
  runtime_obfuscation.cpp
  injection_guard.cpp
  tls_guard.cpp
  crypto.cpp
/examples
  full_example.cpp
```

## Build Targets

- Header-only inline mode
- Static library (.lib)
- Hardened DLL (.dll)
- Minimal mode (reduced footprint)
- Full hardened mode

## Build (CMake)

Header-only (default):

```bash
cmake -S . -B build
cmake --build build
```

Static library:

```bash
cmake -S . -B build -DWINSECRUNTIME_HEADER_ONLY=OFF
cmake --build build
```

Shared library:

```bash
cmake -S . -B build -DWINSECRUNTIME_HEADER_ONLY=OFF -DWINSECRUNTIME_BUILD_SHARED=ON
cmake --build build
```

## Core Interface

```cpp
WinSecRuntime::Initialize(WinSecRuntime::Mode::Moderate);
WinSecRuntime::StartIntegrityEngine();
WinSecRuntime::EnableAntiDebug();
WinSecRuntime::EnableHookGuard();
```

## Current Defensive Capabilities

- Anti-debug: PEB flags, debug object/port, HW breakpoints (current thread + all threads), trap flag, timing anomalies, QPC drift, `.text` INT3 scan, debug privilege detection, SEH chain validation (x86).
- Anti-tamper: PE header validation, entry-point validation, section bounds validation, `.text` CRC32, `.text` SHA-256 baseline compare, rolling CRC baseline compare, entropy anomaly detection, randomized chunk hash validation.
- Memory guard: RWX section detection, writable `.text` detection, private executable region scan, executable private region anomaly scan, optional private exec whitelist.
- Anti-hook: prologue hash validation with caller-supplied baselines.
- Anti-injection: module blacklist scanning by hash, thread start address anomaly detection.
- Process integrity: parent PID and image path validation, parent chain validation (hash whitelist).
- IAT guard: runtime IAT hash with caller baseline, IAT mirror comparison, IAT pointer bounds validation, IAT read-only enforcement, import name hash validation, import module hash validation.
- PE directory validation: import/export/tls/reloc/delay-import directory bounds checks + export forwarder validation.
- TLS callback protection: TLS callback count + hash baselines.
- Entry point protection: entry-point prologue hash baseline.
- Export protection: export name hash baseline.
- Signature presence check: optional certificate table presence.
- VM heuristic: CPUID hypervisor bit + vendor string blacklist.
- Crypto utilities: CRC32, FNV-1a, SHA-256, HMAC-SHA256, secure RNG (BCrypt on Windows).

## Usage (Header-Only)

```cpp
#include "WinSecRuntime/WinSecRuntime.h"

int main() {
    WinSecRuntime::Policy policy{};

    policy.cfg.expected_parent_pid = 0;
    policy.cfg.expected_image_path = L"C:\\Path\\To\\YourApp.exe";

    static constexpr uint32_t module_hashes[] = {
        secure::util::fnv1a32_ci_literal("x64dbg.dll"),
        secure::util::fnv1a32_ci_literal("scyllahide.dll"),
        secure::util::fnv1a32_ci_literal("titanengine.dll")
    };
    policy.cfg.module_hashes = module_hashes;
    policy.cfg.module_hash_count = sizeof(module_hashes) / sizeof(module_hashes[0]);

    static constexpr uint32_t process_hashes[] = {
        secure::util::fnv1a32_ci_literal("x64dbg.exe"),
        secure::util::fnv1a32_ci_literal("x32dbg.exe"),
        secure::util::fnv1a32_ci_literal("ollydbg.exe"),
        secure::util::fnv1a32_ci_literal("ida64.exe"),
        secure::util::fnv1a32_ci_literal("ida.exe"),
        secure::util::fnv1a32_ci_literal("windbg.exe"),
        secure::util::fnv1a32_ci_literal("windbgx.exe")
    };
    policy.cfg.process_hashes = process_hashes;
    policy.cfg.process_hash_count = sizeof(process_hashes) / sizeof(process_hashes[0]);

    static constexpr uint32_t window_hashes[] = {
        secure::util::fnv1a32_ci_literal("x64dbg"),
        secure::util::fnv1a32_ci_literal("x32dbg"),
        secure::util::fnv1a32_ci_literal("ollydbg"),
        secure::util::fnv1a32_ci_literal("ida"),
        secure::util::fnv1a32_ci_literal("windbg")
    };
    policy.cfg.window_hashes = window_hashes;
    policy.cfg.window_hash_count = sizeof(window_hashes) / sizeof(window_hashes[0]);

    policy.cfg.iat_baseline = secure::iat_guard::iat_hash(::GetModuleHandleW(nullptr));
    policy.cfg.iat_bounds_check = true;

    // Optional: rolling CRC baseline + entropy bounds
    policy.cfg.text_rolling_crc_baseline = 0; // set to precomputed value if desired
    policy.cfg.text_rolling_crc_window = 64;
    policy.cfg.text_rolling_crc_stride = 16;
    policy.cfg.text_entropy_min = 5.2;
    policy.cfg.text_entropy_max = 7.9;

    static const secure::anti_hook::PrologueGuard guards[] = {
        { (const void*)&::GetProcAddress, secure::anti_hook::prologue_hash((const void*)&::GetProcAddress, 16), 16 }
    };
    policy.cfg.prologue_guards = guards;
    policy.cfg.prologue_guard_count = sizeof(guards) / sizeof(guards[0]);

    WinSecRuntime::Initialize(WinSecRuntime::Mode::Moderate, policy.cfg);

    secure::Report r = WinSecRuntime::RunAll(policy);
    if (!r.ok()) {
        // handle violations
    }

    return 0;
}
```

## Full Example

See `examples/full_example.cpp` for a complete configuration including IAT mirror capture, `.text` baselines, chunk-hash baselines, TLS callback baselines, VM vendor blacklist, and export/import hash baselines.

## Heartbeat

```cpp
static void on_alert(secure::Report r) {
    if (!r.ok()) {
        // telemetry, shutdown, degrade, etc.
    }
}

WinSecRuntime::Policy policy{};
secure::runtime::Heartbeat hb(5000, &on_alert, policy.cfg);
```

## Feature Toggles

```cpp
#define SECURE_ENABLE_ANTI_DEBUG 1
#define SECURE_ENABLE_VM_CHECK 1
#define SECURE_ENABLE_IAT_GUARD 1
#define SECURE_ENABLE_HEARTBEAT 1
#define SECURE_ENABLE_CRYPTO 1
#define SECURE_ENABLE_UNDOCUMENTED 0
```

## Build Hardening (Recommended)

- `/GS /guard:cf`
- `/DYNAMICBASE /HIGHENTROPYVA`
- LTCG enabled

## Disclaimer

This library raises the cost of debugging and tampering but cannot provide absolute prevention. Use defense in depth.
