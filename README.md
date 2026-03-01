# WinSecRuntime

Windows runtime security library for C++20 (MSVC/Clang). Supports header-only usage and a library build layout for static `.lib` or protected `.dll` builds. This project focuses on **defensive** runtime integrity, anti-debug, anti-hook, and injection detection without deception.

## Table of Contents

- Overview
- Project Layout
- Build Targets
- Build (CMake)
- Core Interface
- Configuration Reference
- Feature Reference
- Examples
- Hardening Flags
- Notes and Limits

## Overview

WinSecRuntime provides a defensive, production‑oriented runtime guard for Windows applications. It is designed to raise the cost of tampering and debugging by combining multiple independent signals for integrity validation, memory safety checks, and API/loader sanity checks. The system favors redundancy and safe detection over evasive or deceptive behaviors.

## Project Layout

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
/Build
  WinSecRuntime.dll
  WinSecRuntime.lib
  WinSecRuntime.a
  WinSecRuntime.dll.a
  WinSecRuntime_import.lib
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

## Configuration Reference

All configuration lives in `secure::runtime::Config`.

```cpp
secure::runtime::Config cfg{};

cfg.expected_parent_pid = 0;
cfg.expected_image_path = L"...";
cfg.require_same_session = false;
cfg.expected_integrity_rid = 0;
cfg.cmdline_hash_baseline = 0;
cfg.cwd_hash_baseline = 0;
cfg.disallow_unc = false;
cfg.disallow_motw = false;

cfg.parent_chain_hashes = nullptr;
cfg.parent_chain_hash_count = 0;
cfg.parent_chain_max_depth = 4;

cfg.module_hashes = nullptr;
cfg.module_hash_count = 0;

cfg.module_whitelist_hashes = nullptr;
cfg.module_whitelist_count = 0;

cfg.module_list_hash_baseline = 0;
cfg.module_count_baseline = 0;

cfg.driver_blacklist_hashes = nullptr;
cfg.driver_blacklist_count = 0;

cfg.exec_private_max_regions = 0;

cfg.process_hashes = nullptr;
cfg.process_hash_count = 0;

cfg.window_hashes = nullptr;
cfg.window_hash_count = 0;

cfg.vm_vendor_hashes = nullptr;
cfg.vm_vendor_hash_count = 0;
cfg.vm_min_cores = 0;
cfg.vm_min_ram_gb = 0;

cfg.iat_baseline = 0;
cfg.import_name_hash_baseline = 0;
cfg.import_module_hash_baseline = 0;
cfg.import_module_count_baseline = 0;
cfg.import_func_count_baseline = 0;

cfg.iat_write_protect = false;
cfg.iat_writable_check = false;
cfg.iat_count_baseline = 0;
cfg.iat_mirror = nullptr;
cfg.iat_mirror_count = 0;
cfg.iat_bounds_check = false;

cfg.text_sha256_baseline = {};
cfg.text_rolling_crc_baseline = 0;
cfg.text_rolling_crc_window = 64;
cfg.text_rolling_crc_stride = 16;

cfg.text_entropy_min = 0.0;
cfg.text_entropy_max = 0.0;

cfg.text_chunk_seed = 0;
cfg.text_chunk_size = 64;
cfg.text_chunk_count = 32;
cfg.text_chunk_baseline = 0;

cfg.nop_sled_threshold = 0;

cfg.delay_import_name_hash_baseline = 0;

cfg.tls_callback_expected = 0;
cfg.tls_callback_hash_baseline = 0;

cfg.entry_prologue_size = 16;
cfg.entry_prologue_baseline = 0;

cfg.signature_required = false;

cfg.export_name_hash_baseline = 0;
cfg.export_rva_hash_baseline = 0;
cfg.export_name_table_hash_baseline = 0;
cfg.export_ordinal_table_hash_baseline = 0;
cfg.export_count_baseline = 0;

cfg.export_whitelist_hashes = nullptr;
cfg.export_whitelist_count = 0;

cfg.export_blacklist_hashes = nullptr;
cfg.export_blacklist_count = 0;

cfg.exec_private_whitelist = nullptr;
cfg.exec_private_whitelist_count = 0;

cfg.prologue_guards = nullptr;
cfg.prologue_guard_count = 0;
```

## Feature Reference

### Parent / Ancestry Validation (Defensive)

- Parent PID check
- Same session ID check
- Integrity level RID check
- Command-line hash baseline
- Current directory hash baseline
- UNC execution detection
- Mark‑of‑the‑Web (Zone.Identifier) detection

Example configuration:

```cpp
WinSecRuntime::Policy p{};

p.cfg.require_same_session = true;
p.cfg.expected_integrity_rid = SECURITY_MANDATORY_MEDIUM_RID;

p.cfg.cmdline_hash_baseline = secure::process_integrity::cmdline_hash();
p.cfg.cwd_hash_baseline = secure::process_integrity::cwd_hash();

p.cfg.disallow_unc = true;
p.cfg.disallow_motw = true;
```

### Anti‑Debug

- `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`
- PEB `BeingDebugged` and `NtGlobalFlag`
- Debug object and debug port (optional undocumented)
- Hardware breakpoints for current thread and all threads
- Trap flag
- Timing anomalies (RDTSC, QPC drift)
- INT3 scan for `.text`
- Debug privilege enabled check
- SEH chain validation (x86)
- Suspended thread detection (optional undocumented)

### Anti‑Tamper and Integrity

- PE header validation
- Entry point RVA is within `.text`
- Entry point page is RX (not RWX)
- Section bounds validation
- `.text` CRC32 baseline
- `.text` SHA‑256 baseline
- Rolling CRC window hash baseline
- Entropy bounds for `.text`
- Randomized `.text` chunk hash baseline
- NOP sled detection in `.text`
- Import/export/tls/reloc/delay‑import directory bounds checks
- Export forwarder validation
- Export name hash baseline
- Export RVA table hash baseline
- Export name table hash baseline
- Export ordinal table hash baseline
- Export count baseline
- Export whitelist/blacklist checks (hashed names)
- Import module hash baseline
- Import name hash baseline (IAT)
- Import module count baseline
- Import function count baseline

### Anti‑Hook

- Prologue hash validation for sensitive functions
- IAT mirror comparison
- IAT pointer bounds validation
- IAT writable detection
- IAT read‑only enforcement
- IAT count baseline

### Anti‑Injection and Memory Guard

- Module blacklist scanning by hash
- Module list hash baseline
- Module count baseline
- Module whitelist validation
- Driver blacklist detection (user‑mode)
- Thread start address anomaly detection
- RWX section detection
- Writable `.text` detection
- Private executable region scan
- Exec private region threshold check
- Optional private exec whitelist
- Main image unlinked from module list detection

### Process Integrity

- Expected parent PID check
- Expected image path check
- Parent chain hash whitelist check

### VM / Sandbox Heuristics

- CPUID hypervisor bit
- CPUID vendor string blacklist
- Low CPU core count detection
- Low RAM detection

### TLS Callback Protection

- TLS callback count baseline
- TLS callback hash baseline

### Entry Point Protection

- Entry prologue hash baseline
- Entry point RX page validation

### Signature Presence Check

- Optional check that PE security directory is present

### String Obfuscation (Compile‑Time)

```cpp
auto obf = SECURE_OBF("WinSecRuntime");
auto plain = obf.decrypt();
secure::util::secure_zero(plain.data(), plain.size());

auto obfw = SECURE_OBF_W(L"WinSecRuntime");
auto plainw = obfw.decrypt();
secure::util::secure_zero(plainw.data(), plainw.size() * sizeof(wchar_t));
```

## Examples

Full example with baselines and advanced configuration is at `examples/full_example.cpp`.

## Hardening Flags

- `/GS /guard:cf`
- `/DYNAMICBASE /HIGHENTROPYVA`
- `LTCG` enabled

## Notes and Limits

- Defensive only. No deception or evasive techniques.
- Some checks use undocumented APIs when `SECURE_ENABLE_UNDOCUMENTED` is enabled.
- Baseline hashes should be computed at startup and reused for periodic validation.

## Disclaimer

This library raises the cost of debugging and tampering but cannot provide absolute prevention. Use defense in depth.
