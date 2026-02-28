#pragma once

#ifndef SECURE_RUNTIME_H
#define SECURE_RUNTIME_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <array>
#include <atomic>
#include <chrono>
#include <type_traits>
#include <cmath>
#include <limits>

// feature toggles
#ifndef SECURE_ENABLE_ANTI_DEBUG
#define SECURE_ENABLE_ANTI_DEBUG 1
#endif
#ifndef SECURE_ENABLE_VM_CHECK
#define SECURE_ENABLE_VM_CHECK 1
#endif
#ifndef SECURE_ENABLE_IAT_GUARD
#define SECURE_ENABLE_IAT_GUARD 1
#endif
#ifndef SECURE_ENABLE_HEARTBEAT
#define SECURE_ENABLE_HEARTBEAT 1
#endif
#ifndef SECURE_ENABLE_CRYPTO
#define SECURE_ENABLE_CRYPTO 1
#endif
#ifndef SECURE_ENABLE_UNDOCUMENTED
#define SECURE_ENABLE_UNDOCUMENTED 0
#endif

// platform
#if defined(_WIN32) || defined(_WIN64)
#define SECURE_PLATFORM_WINDOWS 1
#else
#define SECURE_PLATFORM_WINDOWS 0
#endif

#if SECURE_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <delayimp.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace secure {

// reporting
enum class Alert : uint64_t {
    none                            = 0,
    debugger_present                = 1ull << 0,
    remote_debugger_present         = 1ull << 1,
    peb_being_debugged              = 1ull << 2,
    peb_ntglobalflag                = 1ull << 3,
    timing_anomaly                  = 1ull << 4,
    qpc_drift_anomaly                = 1ull << 5,
    hw_breakpoint                   = 1ull << 6,
    trap_flag                       = 1ull << 7,
    text_int3_scan                  = 1ull << 8,
    vm_detected                     = 1ull << 9,
    iat_tamper                      = 1ull << 10,
    iat_bounds_invalid              = 1ull << 11,
    code_crc_mismatch               = 1ull << 12,
    self_debug_fail                 = 1ull << 12,
    parent_pid_mismatch             = 1ull << 13,
    image_path_mismatch              = 1ull << 14,
    debug_object_detected            = 1ull << 15,
    module_blacklist_detected        = 1ull << 16,
    pe_header_invalid                = 1ull << 17,
    rwx_section_detected             = 1ull << 18,
    exec_private_region              = 1ull << 19,
    text_writable                    = 1ull << 20,
    window_blacklist_detected        = 1ull << 21,
    process_blacklist_detected       = 1ull << 22,
    debug_privilege_enabled          = 1ull << 24,
    text_sha256_mismatch             = 1ull << 25,
    text_rolling_crc_mismatch        = 1ull << 26,
    text_entropy_anomaly             = 1ull << 27,
    export_rva_invalid               = 1ull << 28,
    tls_directory_invalid            = 1ull << 29,
    reloc_directory_invalid          = 1ull << 30,
    import_directory_invalid         = 1ull << 31,
    exec_region_anomaly              = 1ull << 32,
    thread_start_anomaly             = 1ull << 33,
    inline_hook_detected             = 1ull << 34,
    seh_chain_invalid                = 1ull << 35,
    entry_point_invalid              = 1ull << 36,
    section_bounds_invalid           = 1ull << 37,
    text_chunk_hash_mismatch         = 1ull << 38,
    parent_chain_mismatch            = 1ull << 39,
    vm_vendor_blacklisted            = 1ull << 40,
    iat_write_protect_fail           = 1ull << 41,
    import_name_hash_mismatch        = 1ull << 42,
    delay_import_invalid             = 1ull << 43,
    delay_import_name_hash_mismatch  = 1ull << 44,
    tls_callback_mismatch            = 1ull << 45,
    entry_prologue_mismatch          = 1ull << 46,
    signature_missing                = 1ull << 47,
    exec_region_whitelist_violation  = 1ull << 48
    , export_name_hash_mismatch      = 1ull << 49
    , import_module_hash_mismatch    = 1ull << 50
};

inline constexpr Alert operator|(Alert a, Alert b) {
    return static_cast<Alert>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}
inline constexpr Alert operator&(Alert a, Alert b) {
    return static_cast<Alert>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}

struct Report {
    uint64_t flags = 0;

    inline bool ok() const { return flags == 0; }
    inline bool has(Alert a) const { return (flags & static_cast<uint64_t>(a)) != 0; }
    inline void set(Alert a) { flags |= static_cast<uint64_t>(a); }
};

// util
namespace util {

inline uint64_t rdtsc() {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return __rdtsc();
#elif defined(__i386__) || defined(__x86_64__)
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
#endif
}

inline uint32_t fnv1a32(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

inline uint32_t crc32(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= p[i];
        for (int j = 0; j < 8; ++j) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

struct sha256_ctx {
    uint64_t bitlen = 0;
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint8_t data[64] = {0};
    size_t datalen = 0;
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

inline uint8_t tolower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c + 32) : c;
}

inline uint32_t fnv1a32_ci(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= tolower_ascii(static_cast<uint8_t>(*s++));
        h *= 16777619u;
    }
    return h;
}

template <size_t N>
constexpr uint32_t fnv1a32_ci_literal(const char (&s)[N]) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i + 1 < N; ++i) {
        uint8_t c = static_cast<uint8_t>(s[i]);
        if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c + 32);
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

inline uint32_t fnv1a32_ci_w(const wchar_t* s) {
    uint32_t h = 2166136261u;
    while (*s) {
        wchar_t c = *s++;
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + 32);
        h ^= static_cast<uint8_t>(c & 0xFF);
        h *= 16777619u;
    }
    return h;
}

inline void sha256_transform(sha256_ctx& ctx, const uint8_t data[64]) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];
    uint32_t e = ctx.state[4];
    uint32_t f = ctx.state[5];
    uint32_t g = ctx.state[6];
    uint32_t h = ctx.state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k[i] + m[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

inline void sha256_update(sha256_ctx& ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx.data[ctx.datalen++] = data[i];
        if (ctx.datalen == 64) {
            sha256_transform(ctx, ctx.data);
            ctx.bitlen += 512;
            ctx.datalen = 0;
        }
    }
}

inline void sha256_final(sha256_ctx& ctx, uint8_t hash[32]) {
    size_t i = ctx.datalen;

    if (ctx.datalen < 56) {
        ctx.data[i++] = 0x80;
        while (i < 56) ctx.data[i++] = 0x00;
    } else {
        ctx.data[i++] = 0x80;
        while (i < 64) ctx.data[i++] = 0x00;
        sha256_transform(ctx, ctx.data);
        std::memset(ctx.data, 0, 56);
    }

    ctx.bitlen += ctx.datalen * 8;
    ctx.data[63] = static_cast<uint8_t>(ctx.bitlen);
    ctx.data[62] = static_cast<uint8_t>(ctx.bitlen >> 8);
    ctx.data[61] = static_cast<uint8_t>(ctx.bitlen >> 16);
    ctx.data[60] = static_cast<uint8_t>(ctx.bitlen >> 24);
    ctx.data[59] = static_cast<uint8_t>(ctx.bitlen >> 32);
    ctx.data[58] = static_cast<uint8_t>(ctx.bitlen >> 40);
    ctx.data[57] = static_cast<uint8_t>(ctx.bitlen >> 48);
    ctx.data[56] = static_cast<uint8_t>(ctx.bitlen >> 56);
    sha256_transform(ctx, ctx.data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx.state[0] >> (24 - i * 8)) & 0xFF;
        hash[i + 4]  = (ctx.state[1] >> (24 - i * 8)) & 0xFF;
        hash[i + 8]  = (ctx.state[2] >> (24 - i * 8)) & 0xFF;
        hash[i + 12] = (ctx.state[3] >> (24 - i * 8)) & 0xFF;
        hash[i + 16] = (ctx.state[4] >> (24 - i * 8)) & 0xFF;
        hash[i + 20] = (ctx.state[5] >> (24 - i * 8)) & 0xFF;
        hash[i + 24] = (ctx.state[6] >> (24 - i * 8)) & 0xFF;
        hash[i + 28] = (ctx.state[7] >> (24 - i * 8)) & 0xFF;
    }
}

inline std::array<uint8_t, 32> sha256(const void* data, size_t len) {
    sha256_ctx ctx;
    sha256_update(ctx, static_cast<const uint8_t*>(data), len);
    std::array<uint8_t, 32> out{};
    sha256_final(ctx, out.data());
    return out;
}

inline uint32_t rolling_crc_hash(const uint8_t* data, size_t len, size_t window, size_t stride) {
    if (!data || len == 0 || window == 0 || stride == 0) return 0;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i + window <= len; i += stride) {
        uint32_t c = crc32(data + i, window);
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

inline double shannon_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) counts[data[i]]++;
    double entropy = 0.0;
    const double inv = 1.0 / static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = counts[i] * inv;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

inline uint32_t xorshift32(uint32_t& s) {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

inline void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t out[32]) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];

    if (key_len > 64) {
        auto hashed = sha256(key, key_len);
        std::memcpy(tk, hashed.data(), 32);
        key = tk;
        key_len = 32;
    }

    std::memset(k_ipad, 0, 64);
    std::memset(k_opad, 0, 64);
    std::memcpy(k_ipad, key, key_len);
    std::memcpy(k_opad, key, key_len);

    for (int i = 0; i < 64; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha256_ctx ctx;
    sha256_update(ctx, k_ipad, 64);
    sha256_update(ctx, msg, msg_len);
    uint8_t inner[32];
    sha256_final(ctx, inner);

    sha256_ctx ctx2;
    sha256_update(ctx2, k_opad, 64);
    sha256_update(ctx2, inner, 32);
    sha256_final(ctx2, out);
}

#if SECURE_PLATFORM_WINDOWS
inline bool secure_random(void* out, size_t len) {
    if (!out || len == 0) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) != 0) return false;
    NTSTATUS st = BCryptGenRandom(hAlg, static_cast<PUCHAR>(out), static_cast<ULONG>(len), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st == 0;
}
#else
inline bool secure_random(void* out, size_t len) {
    if (!out || len == 0) return false;
    uint8_t* p = static_cast<uint8_t*>(out);
    for (size_t i = 0; i < len; ++i) {
        p[i] = static_cast<uint8_t>(rdtsc() & 0xFF);
    }
    return true;
}
#endif

} // namespace util

// anti-debug
namespace anti_debug {

#if SECURE_PLATFORM_WINDOWS
inline bool is_debugger_present() {
    return ::IsDebuggerPresent() != 0;
}

inline bool check_remote_debugger() {
    BOOL present = FALSE;
    ::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &present);
    return present != FALSE;
}

inline bool peb_being_debugged() {
#if defined(_M_X64)
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#elif defined(_M_IX86)
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#else
    PPEB peb = nullptr;
#endif
    if (!peb) return false;
    return peb->BeingDebugged != 0;
}

inline bool peb_ntglobalflag() {
#if SECURE_ENABLE_UNDOCUMENTED
#if defined(_M_X64)
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#elif defined(_M_IX86)
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#else
    PPEB peb = nullptr;
#endif
    if (!peb) return false;
    const uint32_t* ntg = reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(peb) + 0xBC);
    return (*ntg & 0x70) != 0;
#else
    return false;
#endif
}

inline bool timing_anomaly() {
    uint64_t t1 = util::rdtsc();
    ::Sleep(1);
    uint64_t t2 = util::rdtsc();
    uint64_t delta = t2 - t1;
    return delta > 25'000'000ull;
}

inline bool qpc_drift_anomaly() {
    LARGE_INTEGER freq{};
    LARGE_INTEGER a{};
    LARGE_INTEGER b{};
    if (!::QueryPerformanceFrequency(&freq)) return false;
    ::QueryPerformanceCounter(&a);
    ::Sleep(10);
    ::QueryPerformanceCounter(&b);
    const double elapsed_ms = (static_cast<double>(b.QuadPart - a.QuadPart) * 1000.0) /
                              static_cast<double>(freq.QuadPart);
    return (elapsed_ms < 1.0) || (elapsed_ms > 200.0);
}

inline bool debug_object_detected() {
#if SECURE_ENABLE_UNDOCUMENTED
    using NtQueryInformationProcess_t = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto* ntq = reinterpret_cast<NtQueryInformationProcess_t>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntq) return false;
    HANDLE h = nullptr;
    NTSTATUS st = ntq(::GetCurrentProcess(), ProcessDebugObjectHandle, &h, sizeof(h), nullptr);
    if (st >= 0 && h) return true;
    ULONG dbgPort = 0;
    st = ntq(::GetCurrentProcess(), ProcessDebugPort, &dbgPort, sizeof(dbgPort), nullptr);
    return (st >= 0 && dbgPort != 0);
#else
    return false;
#endif
}

inline bool text_int3_scan() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            size_t hits = 0;
            for (size_t j = 0; j < size; ++j) {
                if (text[j] == 0xCC) {
                    if (++hits > 0) return true;
                }
            }
        }
    }
    return false;
}

inline bool hw_breakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!::GetThreadContext(::GetCurrentThread(), &ctx)) return false;
    return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
}

inline bool hw_breakpoints_all_threads() {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    bool hit = false;
    if (::Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ::GetCurrentProcessId()) continue;
            if (te.th32ThreadID == ::GetCurrentThreadId()) {
                if (hw_breakpoints()) { hit = true; break; }
                continue;
            }
            HANDLE h = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (::SuspendThread(h) != (DWORD)-1) {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (::GetThreadContext(h, &ctx)) {
                    if ((ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0) hit = true;
                }
                ::ResumeThread(h);
            }
            ::CloseHandle(h);
            if (hit) break;
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
    return hit;
}

#if defined(_M_IX86)
inline bool seh_chain_valid() {
    void* head = reinterpret_cast<void*>(__readfsdword(0));
    size_t guard = 0;
    while (head && guard++ < 128) {
        auto* rec = reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(head);
        if (rec == reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(0xFFFFFFFF)) return true;
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(rec, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (rec->Handler == nullptr) return false;
        MEMORY_BASIC_INFORMATION mbi2{};
        if (::VirtualQuery(reinterpret_cast<void*>(rec->Handler), &mbi2, sizeof(mbi2)) == 0) return false;
        if (mbi2.Type != MEM_IMAGE) return false;
        head = rec->Next;
    }
    return guard < 128;
}
#else
inline bool seh_chain_valid() { return true; }
#endif

inline bool trap_flag_set() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!::GetThreadContext(::GetCurrentThread(), &ctx)) return false;
#if defined(_M_X64)
    return (ctx.EFlags & 0x100) != 0;
#else
    return (ctx.EFlags & 0x100) != 0;
#endif
}

inline bool process_blacklist_detected(const uint32_t* hashes, size_t count) {
    if (!hashes || count == 0) return false;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool hit = false;
    if (::Process32FirstW(snap, &pe)) {
        do {
            uint32_t h = util::fnv1a32_ci_w(pe.szExeFile);
            for (size_t i = 0; i < count; ++i) {
                if (hashes[i] == h) { hit = true; break; }
            }
            if (hit) break;
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return hit;
}

struct win_scan_ctx {
    const uint32_t* hashes;
    size_t count;
    bool hit;
};

inline bool is_hash_hit(const uint32_t* hashes, size_t count, uint32_t h) {
    for (size_t i = 0; i < count; ++i) {
        if (hashes[i] == h) return true;
    }
    return false;
}

inline BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<win_scan_ctx*>(lparam);
    if (!ctx || !ctx->hashes || ctx->count == 0) return TRUE;
    wchar_t cls[256] = {0};
    wchar_t title[256] = {0};
    ::GetClassNameW(hwnd, cls, 255);
    ::GetWindowTextW(hwnd, title, 255);
    if (cls[0]) {
        uint32_t h = util::fnv1a32_ci_w(cls);
        if (is_hash_hit(ctx->hashes, ctx->count, h)) { ctx->hit = true; return FALSE; }
    }
    if (title[0]) {
        uint32_t h = util::fnv1a32_ci_w(title);
        if (is_hash_hit(ctx->hashes, ctx->count, h)) { ctx->hit = true; return FALSE; }
    }
    return TRUE;
}

inline bool window_blacklist_detected(const uint32_t* hashes, size_t count) {
    if (!hashes || count == 0) return false;
    win_scan_ctx ctx{hashes, count, false};
    ::EnumWindows(enum_windows_cb, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hit;
}

inline bool debug_privilege_enabled() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD size = 0;
    ::GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
    if (size == 0) { ::CloseHandle(token); return false; }
    auto* buf = static_cast<TOKEN_PRIVILEGES*>(std::malloc(size));
    if (!buf) { ::CloseHandle(token); return false; }
    bool enabled = false;
    if (::GetTokenInformation(token, TokenPrivileges, buf, size, &size)) {
        LUID dbgLuid{};
        if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &dbgLuid)) {
            for (DWORD i = 0; i < buf->PrivilegeCount; ++i) {
                const LUID& luid = buf->Privileges[i].Luid;
                if ((buf->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) &&
                    luid.LowPart == dbgLuid.LowPart && luid.HighPart == dbgLuid.HighPart) {
                    enabled = true;
                    break;
                }
            }
        }
    }
    std::free(buf);
    ::CloseHandle(token);
    return enabled;
}

#else
inline bool is_debugger_present() { return false; }
inline bool check_remote_debugger() { return false; }
inline bool peb_being_debugged() { return false; }
inline bool peb_ntglobalflag() { return false; }
inline bool timing_anomaly() { return false; }
inline bool qpc_drift_anomaly() { return false; }
inline bool debug_object_detected() { return false; }
inline bool text_int3_scan() { return false; }
inline bool hw_breakpoints() { return false; }
inline bool hw_breakpoints_all_threads() { return false; }
inline bool trap_flag_set() { return false; }
inline bool seh_chain_valid() { return true; }
inline bool process_blacklist_detected(const uint32_t*, size_t) { return false; }
inline bool window_blacklist_detected(const uint32_t*, size_t) { return false; }
inline bool debug_privilege_enabled() { return false; }
#endif

inline Report run_static(const uint32_t* window_hashes = nullptr, size_t window_count = 0,
                         const uint32_t* process_hashes = nullptr, size_t process_count = 0) {
    Report r;
#if SECURE_ENABLE_ANTI_DEBUG
    if (is_debugger_present()) r.set(Alert::debugger_present);
    if (check_remote_debugger()) r.set(Alert::remote_debugger_present);
    if (peb_being_debugged()) r.set(Alert::peb_being_debugged);
    if (peb_ntglobalflag()) r.set(Alert::peb_ntglobalflag);
    if (debug_object_detected()) r.set(Alert::debug_object_detected);
    if (window_blacklist_detected(window_hashes, window_count)) r.set(Alert::window_blacklist_detected);
    if (process_blacklist_detected(process_hashes, process_count)) r.set(Alert::process_blacklist_detected);
    if (debug_privilege_enabled()) r.set(Alert::debug_privilege_enabled);
    if (!seh_chain_valid()) r.set(Alert::seh_chain_invalid);
#endif
    return r;
}

inline Report run_dynamic() {
    Report r;
#if SECURE_ENABLE_ANTI_DEBUG
    if (timing_anomaly()) r.set(Alert::timing_anomaly);
    if (qpc_drift_anomaly()) r.set(Alert::qpc_drift_anomaly);
    if (hw_breakpoints()) r.set(Alert::hw_breakpoint);
    if (hw_breakpoints_all_threads()) r.set(Alert::hw_breakpoint);
    if (trap_flag_set()) r.set(Alert::trap_flag);
    if (text_int3_scan()) r.set(Alert::text_int3_scan);
#endif
    return r;
}

} // namespace anti_debug

// vm
namespace vm {

#if SECURE_PLATFORM_WINDOWS
inline bool cpuid_hypervisor_bit() {
#if defined(_MSC_VER)
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 1);
    return (cpu_info[2] & (1 << 31)) != 0;
#elif defined(__i386__) || defined(__x86_64__)
    uint32_t eax=1, ebx=0, ecx=0, edx=0;
    __asm__ __volatile__("cpuid" : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx));
    return (ecx & (1u << 31)) != 0;
#else
    return false;
#endif
}

inline bool cpuid_vm_vendor_blacklisted(const uint32_t* hashes, size_t count) {
    if (!hashes || count == 0) return false;
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 0x40000000);
    char vendor[13] = {0};
    std::memcpy(vendor + 0, &cpu_info[1], 4);
    std::memcpy(vendor + 4, &cpu_info[2], 4);
    std::memcpy(vendor + 8, &cpu_info[3], 4);
    uint32_t h = util::fnv1a32_ci(vendor);
    for (size_t i = 0; i < count; ++i) {
        if (hashes[i] == h) return true;
    }
    return false;
}
#else
inline bool cpuid_hypervisor_bit() { return false; }
inline bool cpuid_vm_vendor_blacklisted(const uint32_t*, size_t) { return false; }
#endif

inline Report run(const uint32_t* vendor_hashes = nullptr, size_t vendor_count = 0) {
    Report r;
#if SECURE_ENABLE_VM_CHECK
    if (cpuid_hypervisor_bit()) r.set(Alert::vm_detected);
    if (cpuid_vm_vendor_blacklisted(vendor_hashes, vendor_count)) r.set(Alert::vm_vendor_blacklisted);
#endif
    return r;
}

} // namespace vm

// tamper
namespace anti_tamper {

#if SECURE_PLATFORM_WINDOWS
inline bool image_range_contains(uint8_t* base, size_t size, uintptr_t rva, size_t len) {
    if (!base || size == 0) return false;
    if (rva == 0 || rva + len < rva) return false;
    return rva + len <= size;
}

inline bool code_crc_mismatch() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return true;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            uint32_t crc = util::crc32(text, size);
            (void)crc;
            return false;
        }
    }
    return false;
}

inline bool export_rva_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    if (!image_range_contains(base, image_size, dir.VirtualAddress, dir.Size)) return false;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfFunctions; ++i) {
        uint32_t rva = funcs[i];
        if (rva == 0) continue;
        if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
            continue;
        }
        if (rva >= image_size) return false;
    }
    return true;
}

inline bool export_forwarders_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    if (!image_range_contains(base, image_size, dir.VirtualAddress, dir.Size)) return false;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfFunctions; ++i) {
        uint32_t rva = funcs[i];
        if (rva == 0) continue;
        if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
            const char* fwd = reinterpret_cast<const char*>(base + rva);
            const char* end = reinterpret_cast<const char*>(base + dir.VirtualAddress + dir.Size);
            if (fwd < reinterpret_cast<const char*>(base + dir.VirtualAddress) || fwd >= end) return false;
            bool has_sep = false;
            for (const char* p = fwd; p < end && *p; ++p) {
                char c = *p;
                if (c == '.' || c == '#') has_sep = true;
                if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return false;
            }
            if (!has_sep) return false;
        }
    }
    return true;
}

inline uint32_t export_name_hash() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* s = reinterpret_cast<const char*>(base + names[i]);
        while (*s) {
            h ^= static_cast<uint8_t>(*s++);
            h *= 16777619u;
        }
    }
    return h;
}
inline bool tls_directory_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) return true;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    if (!image_range_contains(base, image_size, dir.VirtualAddress, dir.Size)) return false;
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + dir.VirtualAddress);
    auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
    if (!callbacks) return true;
    for (; *callbacks; ++callbacks) {
        auto cb = reinterpret_cast<uint8_t*>(*callbacks);
        if (cb < base || cb >= base + image_size) return false;
    }
    return true;
}

inline size_t tls_callback_count() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + dir.VirtualAddress);
    auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
    if (!callbacks) return 0;
    size_t n = 0;
    for (; *callbacks; ++callbacks) ++n;
    return n;
}

inline uint32_t tls_callback_hash() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + dir.VirtualAddress);
    auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
    if (!callbacks) return 0;
    uint32_t h = 2166136261u;
    for (; *callbacks; ++callbacks) {
        auto addr = reinterpret_cast<uintptr_t>(*callbacks);
        h ^= static_cast<uint32_t>(addr & 0xFFFFFFFFu);
        h *= 16777619u;
        h ^= static_cast<uint32_t>((addr >> 32) & 0xFFFFFFFFu);
        h *= 16777619u;
    }
    return h;
}

inline bool reloc_directory_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) return true;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    if (!image_range_contains(base, image_size, dir.VirtualAddress, dir.Size)) return false;
    return true;
}

inline bool import_directory_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    if (!image_range_contains(base, image_size, dir.VirtualAddress, dir.Size)) return false;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        if (desc->Name >= image_size) return false;
        if (desc->OriginalFirstThunk && desc->OriginalFirstThunk >= image_size) return false;
        if (desc->FirstThunk >= image_size) return false;
    }
    return true;
}

inline uint32_t import_module_hash() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    uint32_t h = 2166136261u;
    for (; desc->Name; ++desc) {
        const char* s = reinterpret_cast<const char*>(base + desc->Name);
        while (*s) {
            h ^= static_cast<uint8_t>(*s++);
            h *= 16777619u;
        }
    }
    return h;
}

inline bool delay_import_directory_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    if (!image_range_contains(base, image_size, dir.VirtualAddress, dir.Size)) return false;
    return true;
}

inline uint32_t delay_import_name_hash() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* desc = reinterpret_cast<ImgDelayDescr*>(base + dir.VirtualAddress);
    uint32_t h = 2166136261u;
    for (; desc->rvaDLLName; ++desc) {
        auto* thunk = reinterpret_cast<ImgThunkData*>(base + desc->rvaINT);
        for (; thunk->u1.AddressOfData; ++thunk) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                uint16_t ord = static_cast<uint16_t>(IMAGE_ORDINAL(thunk->u1.Ordinal));
                h ^= ord & 0xFF;
                h *= 16777619u;
                h ^= (ord >> 8) & 0xFF;
                h *= 16777619u;
            } else {
                auto* name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunk->u1.AddressOfData);
                const char* s = reinterpret_cast<const char*>(name->Name);
                while (*s) {
                    h ^= static_cast<uint8_t>(*s++);
                    h *= 16777619u;
                }
            }
        }
    }
    return h;
}

inline bool signature_present() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    return dir.VirtualAddress != 0 && dir.Size != 0;
}

inline bool entry_prologue_mismatch(uint32_t baseline, uint32_t size) {
    if (baseline == 0 || size == 0) return false;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    uint32_t ep = nt->OptionalHeader.AddressOfEntryPoint;
    if (ep == 0) return false;
    void* ep_ptr = base + ep;
    uint32_t h = util::crc32(ep_ptr, size);
    return h != baseline;
}

inline uint32_t entry_prologue_hash_current(uint32_t size) {
    if (size == 0) return 0;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    uint32_t ep = nt->OptionalHeader.AddressOfEntryPoint;
    if (ep == 0) return 0;
    void* ep_ptr = base + ep;
    return util::crc32(ep_ptr, size);
}
inline bool entry_point_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    uint32_t ep = nt->OptionalHeader.AddressOfEntryPoint;
    if (ep == 0) return false;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t vsz = sec[i].Misc.VirtualSize;
            return (ep >= va && ep < va + vsz);
        }
    }
    return false;
}

inline bool section_bounds_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t va = sec[i].VirtualAddress;
        uint32_t vsz = sec[i].Misc.VirtualSize;
        if (va == 0 || vsz == 0) continue;
        if (va + vsz < va) return false;
        if (va + vsz > image_size) return false;
    }
    return true;
}

inline bool text_sha256_mismatch(const std::array<uint8_t, 32>& baseline) {
    if (baseline == std::array<uint8_t, 32>{}) return false;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            auto h = util::sha256(text, size);
            return h != baseline;
        }
    }
    return false;
}

inline std::array<uint8_t, 32> text_sha256_current() {
    std::array<uint8_t, 32> zero{};
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return zero;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return zero;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            return util::sha256(text, size);
        }
    }
    return zero;
}

inline bool text_rolling_crc_mismatch(uint32_t baseline, size_t window, size_t stride) {
    if (baseline == 0 || window == 0 || stride == 0) return false;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            uint32_t h = util::rolling_crc_hash(text, size, window, stride);
            return h != baseline;
        }
    }
    return false;
}

inline uint32_t text_rolling_crc_current(size_t window, size_t stride) {
    if (window == 0 || stride == 0) return 0;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            return util::rolling_crc_hash(text, size, window, stride);
        }
    }
    return 0;
}

inline bool text_entropy_anomaly(double min_entropy, double max_entropy) {
    if (min_entropy <= 0.0 && max_entropy <= 0.0) return false;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            double e = util::shannon_entropy(text, size);
            if (min_entropy > 0.0 && e < min_entropy) return true;
            if (max_entropy > 0.0 && e > max_entropy) return true;
            return false;
        }
    }
    return false;
}

inline uint32_t text_chunk_hash_current(uint32_t seed, uint32_t chunk_size, uint32_t chunk_count) {
    if (seed == 0 || chunk_size == 0 || chunk_count == 0) return 0;
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            uint32_t size = sec[i].Misc.VirtualSize;
            if (size < chunk_size) return 0;
            uint32_t h = 2166136261u;
            uint32_t s = seed;
            for (uint32_t c = 0; c < chunk_count; ++c) {
                uint32_t off = util::xorshift32(s) % (size - chunk_size + 1);
                uint32_t crc = util::crc32(text + off, chunk_size);
                h ^= crc;
                h *= 16777619u;
            }
            return h;
        }
    }
    return 0;
}

inline double text_entropy_current() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return 0.0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0.0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            size_t size = sec[i].Misc.VirtualSize;
            return util::shannon_entropy(text, size);
        }
    }
    return 0.0;
}
inline bool pe_header_valid() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
#if defined(_WIN64)
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
#else
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
#endif
    return true;
}

inline bool rwx_section_detected() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto ch = sec[i].Characteristics;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) return true;
    }
    return false;
}

inline bool exec_private_region() {
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    uint8_t* p = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    uint8_t* end = static_cast<uint8_t*>(si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    while (p < end) {
        if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            mbi.Type == MEM_PRIVATE) {
            return true;
        }
        p += mbi.RegionSize;
    }
    return false;
}

inline bool text_writable() {
    HMODULE hMod = ::GetModuleHandleW(nullptr);
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            uint8_t* text = base + sec[i].VirtualAddress;
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(text, &mbi, sizeof(mbi)) == 0) return false;
            const DWORD p = mbi.Protect & 0xFF;
            if (p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY ||
                p == PAGE_READWRITE || p == PAGE_WRITECOPY) {
                return true;
            }
            return false;
        }
    }
    return false;
}
#else
inline bool code_crc_mismatch() { return false; }
inline bool export_rva_valid() { return true; }
inline bool tls_directory_valid() { return true; }
inline bool reloc_directory_valid() { return true; }
inline bool import_directory_valid() { return true; }
inline uint32_t import_module_hash() { return 0; }
inline bool delay_import_directory_valid() { return true; }
inline uint32_t delay_import_name_hash() { return 0; }
inline bool signature_present() { return true; }
inline bool entry_prologue_mismatch(uint32_t, uint32_t) { return false; }
inline uint32_t entry_prologue_hash_current(uint32_t) { return 0; }
inline size_t tls_callback_count() { return 0; }
inline uint32_t tls_callback_hash() { return 0; }
inline uint32_t export_name_hash() { return 0; }
inline bool text_sha256_mismatch(const std::array<uint8_t, 32>&) { return false; }
inline std::array<uint8_t, 32> text_sha256_current() { return {}; }
inline bool text_rolling_crc_mismatch(uint32_t, size_t, size_t) { return false; }
inline uint32_t text_rolling_crc_current(size_t, size_t) { return 0; }
inline bool text_entropy_anomaly(double, double) { return false; }
inline double text_entropy_current() { return 0.0; }
inline bool entry_point_valid() { return true; }
inline bool section_bounds_valid() { return true; }
inline uint32_t text_chunk_hash_current(uint32_t, uint32_t, uint32_t) { return 0; }
inline bool pe_header_valid() { return true; }
inline bool rwx_section_detected() { return false; }
inline bool exec_private_region() { return false; }
inline bool text_writable() { return false; }
#endif

inline Report run() {
    Report r;
    if (code_crc_mismatch()) r.set(Alert::code_crc_mismatch);
    if (!export_rva_valid()) r.set(Alert::export_rva_invalid);
    if (!export_forwarders_valid()) r.set(Alert::export_rva_invalid);
    if (!tls_directory_valid()) r.set(Alert::tls_directory_invalid);
    if (!reloc_directory_valid()) r.set(Alert::reloc_directory_invalid);
    if (!import_directory_valid()) r.set(Alert::import_directory_invalid);
    if (!entry_point_valid()) r.set(Alert::entry_point_invalid);
    if (!section_bounds_valid()) r.set(Alert::section_bounds_invalid);
    if (!pe_header_valid()) r.set(Alert::pe_header_invalid);
    if (rwx_section_detected()) r.set(Alert::rwx_section_detected);
    if (exec_private_region()) r.set(Alert::exec_private_region);
    if (text_writable()) r.set(Alert::text_writable);
    return r;
}

} // namespace anti_tamper

// iat
namespace iat_guard {
#if SECURE_PLATFORM_WINDOWS
inline uint32_t iat_hash(HMODULE hMod) {
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    uint32_t h = 2166136261u;
    for (; desc->Name; ++desc) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            uintptr_t fn = static_cast<uintptr_t>(thunk->u1.Function);
            h ^= static_cast<uint32_t>(fn);
            h *= 16777619u;
        }
    }
    return h;
}

inline size_t iat_entry_count(HMODULE hMod) {
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    size_t count = 0;
    for (; desc->Name; ++desc) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            ++count;
        }
    }
    return count;
}

inline bool iat_fill_mirror(HMODULE hMod, void** out, size_t out_count) {
    if (!out || out_count == 0) return false;
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    size_t idx = 0;
    for (; desc->Name; ++desc) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            if (idx >= out_count) return false;
            out[idx++] = reinterpret_cast<void*>(static_cast<uintptr_t>(thunk->u1.Function));
        }
    }
    return idx == out_count;
}

inline bool iat_mirror_mismatch(HMODULE hMod, void** mirror, size_t mirror_count) {
    if (!mirror || mirror_count == 0) return false;
    if (!hMod) hMod = ::GetModuleHandleW(nullptr);
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    size_t idx = 0;
    for (; desc->Name; ++desc) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            if (idx >= mirror_count) return true;
            void* now = reinterpret_cast<void*>(static_cast<uintptr_t>(thunk->u1.Function));
            if (now != mirror[idx++]) return true;
        }
    }
    return idx != mirror_count;
}

inline bool iat_pointer_bounds_valid(HMODULE hMod) {
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            void* fn = reinterpret_cast<void*>(static_cast<uintptr_t>(thunk->u1.Function));
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(fn, &mbi, sizeof(mbi)) == 0) return false;
            if (mbi.Type != MEM_IMAGE) return false;
        }
    }
    return true;
}

inline bool iat_enforce_readonly(HMODULE hMod) {
    if (!hMod) return false;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    DWORD oldProt = 0;
    void* iat = base + dir.VirtualAddress;
    if (!::VirtualProtect(iat, dir.Size, PAGE_READONLY, &oldProt)) return false;
    return true;
}

inline uint32_t import_name_hash(HMODULE hMod) {
    if (!hMod) return 0;
    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    uint32_t h = 2166136261u;
    for (; desc->Name; ++desc) {
        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        for (; thunk->u1.AddressOfData; ++thunk) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                uint16_t ord = static_cast<uint16_t>(IMAGE_ORDINAL(thunk->u1.Ordinal));
                h ^= ord & 0xFF;
                h *= 16777619u;
                h ^= (ord >> 8) & 0xFF;
                h *= 16777619u;
            } else {
                auto* name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunk->u1.AddressOfData);
                const char* s = reinterpret_cast<const char*>(name->Name);
                while (*s) {
                    h ^= static_cast<uint8_t>(*s++);
                    h *= 16777619u;
                }
            }
        }
    }
    return h;
}
#else
inline uint32_t iat_hash(void*) { return 0; }
inline size_t iat_entry_count(void*) { return 0; }
inline bool iat_fill_mirror(void*, void**, size_t) { return false; }
inline bool iat_mirror_mismatch(void*, void**, size_t) { return false; }
inline bool iat_pointer_bounds_valid(void*) { return true; }
inline bool iat_enforce_readonly(void*) { return true; }
inline uint32_t import_name_hash(void*) { return 0; }
#endif

#if SECURE_PLATFORM_WINDOWS
inline bool iat_tampered(uint32_t baseline, HMODULE hMod = nullptr) {
    if (baseline == 0) return false;
    if (!hMod) hMod = ::GetModuleHandleW(nullptr);
    uint32_t now = iat_hash(hMod);
    return now != 0 && now != baseline;
}
#else
inline bool iat_tampered(uint32_t, void* = nullptr) { return false; }
#endif

inline Report run() {
    Report r;
#if SECURE_ENABLE_IAT_GUARD
#endif
    return r;
}
} // namespace iat_guard

// process
namespace process_integrity {

#if SECURE_PLATFORM_WINDOWS
inline uint32_t parent_pid() {
    using NtQueryInformationProcess_t = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto* ntq = reinterpret_cast<NtQueryInformationProcess_t>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntq) return 0;
    PROCESS_BASIC_INFORMATION pbi{};
    NTSTATUS st = ntq(::GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    if (st < 0) return 0;
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pbi.Reserved3));
}

inline bool parent_chain_valid(const uint32_t* hashes, size_t count, size_t max_depth = 4) {
    if (!hashes || count == 0) return true;
    uint32_t pid = parent_pid();
    size_t depth = 0;
    while (pid != 0 && depth++ < max_depth) {
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return false;
        wchar_t path[MAX_PATH] = {0};
        if (!::GetProcessImageFileNameW(h, path, MAX_PATH)) {
            ::CloseHandle(h);
            return false;
        }
        ::CloseHandle(h);
        uint32_t hsh = util::fnv1a32_ci_w(path);
        for (size_t i = 0; i < count; ++i) {
            if (hashes[i] == hsh) return true;
        }
        // next parent
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        uint32_t next = 0;
        if (::Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { next = pe.th32ParentProcessID; break; }
            } while (::Process32NextW(snap, &pe));
        }
        ::CloseHandle(snap);
        pid = next;
    }
    return false;
}

inline bool parent_pid_valid(uint32_t expected) {
    if (expected == 0) return true;
    return parent_pid() == expected;
}

inline bool image_path_valid(const wchar_t* expected_path) {
    if (!expected_path || !*expected_path) return true;
    wchar_t buf[MAX_PATH + 1] = {0};
    DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0) return false;
    return _wcsicmp(buf, expected_path) == 0;
}
#else
inline uint32_t parent_pid() { return 0; }
inline bool parent_chain_valid(const uint32_t*, size_t, size_t = 4) { return true; }
inline bool parent_pid_valid(uint32_t) { return true; }
inline bool image_path_valid(const wchar_t*) { return true; }
#endif

inline Report run(uint32_t expected_parent_pid, const wchar_t* expected_image_path) {
    Report r;
    if (!parent_pid_valid(expected_parent_pid)) r.set(Alert::parent_pid_mismatch);
    if (!image_path_valid(expected_image_path)) r.set(Alert::image_path_mismatch);
    return r;
}

} // namespace process_integrity

// modules
namespace anti_injection {

#if SECURE_PLATFORM_WINDOWS
inline bool module_blacklist_detected(const uint32_t* hashes, size_t count) {
    if (!hashes || count == 0) return false;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ::GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool hit = false;
    if (::Module32FirstW(snap, &me)) {
        do {
            char nameA[MAX_PATH] = {0};
            size_t len = 0;
            wcstombs_s(&len, nameA, me.szModule, MAX_PATH - 1);
            uint32_t h = util::fnv1a32_ci(nameA);
            for (size_t i = 0; i < count; ++i) {
                if (hashes[i] == h) { hit = true; break; }
            }
            if (hit) break;
        } while (::Module32NextW(snap, &me));
    }
    ::CloseHandle(snap);
    return hit;
}
#else
inline bool module_blacklist_detected(const uint32_t*, size_t) { return false; }
#endif

inline Report run(const uint32_t* hashes, size_t count) {
    Report r;
    if (module_blacklist_detected(hashes, count)) r.set(Alert::module_blacklist_detected);
    return r;
}

} // namespace anti_injection

// hook guard
namespace anti_hook {

struct PrologueGuard {
    const void* address = nullptr;
    uint32_t hash = 0;
    uint32_t size = 0;
};

inline uint32_t prologue_hash(const void* addr, uint32_t size) {
    if (!addr || size == 0) return 0;
    return util::crc32(addr, size);
}

inline bool prologue_mismatch(const PrologueGuard* items, size_t count) {
    if (!items || count == 0) return false;
    for (size_t i = 0; i < count; ++i) {
        if (!items[i].address || items[i].size == 0 || items[i].hash == 0) continue;
        uint32_t h = prologue_hash(items[i].address, items[i].size);
        if (h != items[i].hash) return true;
    }
    return false;
}

inline Report run(const PrologueGuard* items, size_t count) {
    Report r;
    if (prologue_mismatch(items, count)) r.set(Alert::inline_hook_detected);
    return r;
}

} // namespace anti_hook

// exec/memory anomalies
namespace memory_guard {

#if SECURE_PLATFORM_WINDOWS
struct ExecRegion {
    const void* base = nullptr;
    size_t size = 0;
};

inline bool region_whitelisted(const ExecRegion* whitelist, size_t count, void* addr) {
    if (!whitelist || count == 0) return false;
    auto* p = reinterpret_cast<uint8_t*>(addr);
    for (size_t i = 0; i < count; ++i) {
        if (!whitelist[i].base || whitelist[i].size == 0) continue;
        auto* b = reinterpret_cast<const uint8_t*>(whitelist[i].base);
        if (p >= b && p < b + whitelist[i].size) return true;
    }
    return false;
}
#endif

#if SECURE_PLATFORM_WINDOWS
inline bool exec_region_anomaly() {
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    uint8_t* p = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    uint8_t* end = static_cast<uint8_t*>(si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    while (p < end) {
        if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            if (mbi.Type == MEM_PRIVATE) return true;
        }
        p += mbi.RegionSize;
    }
    return false;
}

inline bool thread_start_anomaly() {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    bool hit = false;
    if (::Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ::GetCurrentProcessId()) continue;
            HANDLE h = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!h) continue;
            PVOID start = nullptr;
            using NtQueryInformationThread_t = NTSTATUS (NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
            auto* ntq = reinterpret_cast<NtQueryInformationThread_t>(
                ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
            if (ntq) {
                NTSTATUS st = ntq(h, (THREADINFOCLASS)9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);
                if (st >= 0 && start) {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (::VirtualQuery(start, &mbi, sizeof(mbi)) != 0) {
                        if (mbi.Type != MEM_IMAGE) { hit = true; }
                    }
                }
            }
            ::CloseHandle(h);
            if (hit) break;
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
    return hit;
}
#else
inline bool exec_region_anomaly() { return false; }
inline bool thread_start_anomaly() { return false; }
#endif

inline Report run(const ExecRegion* whitelist, size_t whitelist_count) {
    Report r;
    if (exec_region_anomaly()) r.set(Alert::exec_region_anomaly);
    if (thread_start_anomaly()) r.set(Alert::thread_start_anomaly);
    if (whitelist && whitelist_count > 0) {
#if SECURE_PLATFORM_WINDOWS
        SYSTEM_INFO si{};
        ::GetSystemInfo(&si);
        uint8_t* p = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
        uint8_t* end = static_cast<uint8_t*>(si.lpMaximumApplicationAddress);
        MEMORY_BASIC_INFORMATION mbi{};
        while (p < end) {
            if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                mbi.Type == MEM_PRIVATE) {
                if (!region_whitelisted(whitelist, whitelist_count, mbi.BaseAddress)) {
                    r.set(Alert::exec_region_whitelist_violation);
                    break;
                }
            }
            p += mbi.RegionSize;
        }
#endif
    }
    return r;
}

} // namespace memory_guard

// runtime
namespace runtime {

struct Config {
    uint32_t expected_parent_pid = 0;
    const wchar_t* expected_image_path = nullptr;
    const uint32_t* parent_chain_hashes = nullptr;
    size_t parent_chain_hash_count = 0;
    size_t parent_chain_max_depth = 4;
    const uint32_t* module_hashes = nullptr;
    size_t module_hash_count = 0;
    const uint32_t* process_hashes = nullptr;
    size_t process_hash_count = 0;
    const uint32_t* window_hashes = nullptr;
    size_t window_hash_count = 0;
    const uint32_t* vm_vendor_hashes = nullptr;
    size_t vm_vendor_hash_count = 0;
    uint32_t iat_baseline = 0;
    uint32_t import_name_hash_baseline = 0;
    uint32_t import_module_hash_baseline = 0;
    bool iat_write_protect = false;
    void** iat_mirror = nullptr;
    size_t iat_mirror_count = 0;
    bool iat_bounds_check = false;
    std::array<uint8_t, 32> text_sha256_baseline{};
    uint32_t text_rolling_crc_baseline = 0;
    uint32_t text_rolling_crc_window = 64;
    uint32_t text_rolling_crc_stride = 16;
    double text_entropy_min = 0.0;
    double text_entropy_max = 0.0;
    uint32_t text_chunk_seed = 0;
    uint32_t text_chunk_size = 64;
    uint32_t text_chunk_count = 32;
    uint32_t text_chunk_baseline = 0;
    uint32_t delay_import_name_hash_baseline = 0;
    uint32_t export_name_hash_baseline = 0;
    size_t tls_callback_expected = 0;
    uint32_t tls_callback_hash_baseline = 0;
    uint32_t entry_prologue_size = 16;
    uint32_t entry_prologue_baseline = 0;
    bool signature_required = false;
    const memory_guard::ExecRegion* exec_private_whitelist = nullptr;
    size_t exec_private_whitelist_count = 0;
    const anti_hook::PrologueGuard* prologue_guards = nullptr;
    size_t prologue_guard_count = 0;
};

inline Report run_all_checks(const Config& cfg = {}) {
    Report r;
    Report s = anti_debug::run_static(cfg.window_hashes, cfg.window_hash_count,
                                      cfg.process_hashes, cfg.process_hash_count);
    Report d = anti_debug::run_dynamic();
    Report v = vm::run(cfg.vm_vendor_hashes, cfg.vm_vendor_hash_count);
    Report t = anti_tamper::run();
    Report i = iat_guard::run();
    Report h = anti_hook::run(cfg.prologue_guards, cfg.prologue_guard_count);
    Report mg = memory_guard::run(cfg.exec_private_whitelist, cfg.exec_private_whitelist_count);
    Report p = process_integrity::run(cfg.expected_parent_pid, cfg.expected_image_path);
    Report m = anti_injection::run(cfg.module_hashes, cfg.module_hash_count);

    r.flags = s.flags | d.flags | v.flags | t.flags | i.flags | h.flags | mg.flags | p.flags | m.flags;
#if SECURE_ENABLE_IAT_GUARD
    if (iat_guard::iat_tampered(cfg.iat_baseline)) r.set(Alert::iat_tamper);
    if (cfg.import_name_hash_baseline != 0) {
        uint32_t h = iat_guard::import_name_hash(::GetModuleHandleW(nullptr));
        if (h != cfg.import_name_hash_baseline) r.set(Alert::import_name_hash_mismatch);
    }
    if (cfg.import_module_hash_baseline != 0) {
        uint32_t h = anti_tamper::import_module_hash();
        if (h != cfg.import_module_hash_baseline) r.set(Alert::import_module_hash_mismatch);
    }
    if (cfg.iat_write_protect) {
        if (!iat_guard::iat_enforce_readonly(::GetModuleHandleW(nullptr))) r.set(Alert::iat_write_protect_fail);
    }
    if (cfg.iat_mirror && cfg.iat_mirror_count > 0) {
        if (iat_guard::iat_mirror_mismatch(::GetModuleHandleW(nullptr), cfg.iat_mirror, cfg.iat_mirror_count)) {
            r.set(Alert::iat_tamper);
        }
    }
    if (cfg.iat_bounds_check) {
        if (!iat_guard::iat_pointer_bounds_valid(::GetModuleHandleW(nullptr))) r.set(Alert::iat_bounds_invalid);
    }
#endif
    if (anti_tamper::text_sha256_mismatch(cfg.text_sha256_baseline)) r.set(Alert::text_sha256_mismatch);
    if (anti_tamper::text_rolling_crc_mismatch(cfg.text_rolling_crc_baseline,
                                               cfg.text_rolling_crc_window,
                                               cfg.text_rolling_crc_stride)) r.set(Alert::text_rolling_crc_mismatch);
    if (anti_tamper::text_entropy_anomaly(cfg.text_entropy_min, cfg.text_entropy_max)) r.set(Alert::text_entropy_anomaly);
    if (cfg.text_chunk_seed != 0 && cfg.text_chunk_baseline != 0) {
        uint32_t ch = anti_tamper::text_chunk_hash_current(cfg.text_chunk_seed, cfg.text_chunk_size, cfg.text_chunk_count);
        if (ch != cfg.text_chunk_baseline) r.set(Alert::text_chunk_hash_mismatch);
    }
    if (cfg.delay_import_name_hash_baseline != 0) {
        uint32_t dh = anti_tamper::delay_import_name_hash();
        if (dh != cfg.delay_import_name_hash_baseline) r.set(Alert::delay_import_name_hash_mismatch);
    }
    if (cfg.export_name_hash_baseline != 0) {
        uint32_t eh = anti_tamper::export_name_hash();
        if (eh != cfg.export_name_hash_baseline) r.set(Alert::export_name_hash_mismatch);
    }
    if (!anti_tamper::delay_import_directory_valid()) r.set(Alert::delay_import_invalid);
    if (cfg.tls_callback_expected != 0) {
        if (anti_tamper::tls_callback_count() != cfg.tls_callback_expected) r.set(Alert::tls_callback_mismatch);
    }
    if (cfg.tls_callback_hash_baseline != 0) {
        if (anti_tamper::tls_callback_hash() != cfg.tls_callback_hash_baseline) r.set(Alert::tls_callback_mismatch);
    }
    if (cfg.entry_prologue_baseline != 0) {
        if (anti_tamper::entry_prologue_mismatch(cfg.entry_prologue_baseline, cfg.entry_prologue_size)) {
            r.set(Alert::entry_prologue_mismatch);
        }
    }
    if (cfg.signature_required && !anti_tamper::signature_present()) r.set(Alert::signature_missing);
    if (cfg.parent_chain_hashes && cfg.parent_chain_hash_count > 0) {
        if (!process_integrity::parent_chain_valid(cfg.parent_chain_hashes, cfg.parent_chain_hash_count,
                                                   cfg.parent_chain_max_depth)) {
            r.set(Alert::parent_chain_mismatch);
        }
    }
    return r;
}

#if SECURE_ENABLE_HEARTBEAT
class Heartbeat {
public:
    using callback_t = void(*)(Report);

    explicit Heartbeat(uint32_t interval_ms = 5000, callback_t cb = nullptr, Config cfg = {})
        : interval(interval_ms), cbk(cb), config(cfg) {
        running.store(true, std::memory_order_release);
#if SECURE_PLATFORM_WINDOWS
        ::CreateThread(nullptr, 0, &Heartbeat::thread_proc, this, 0, nullptr);
#endif
    }

    ~Heartbeat() { running.store(false, std::memory_order_release); }

private:
    uint32_t interval;
    callback_t cbk;
    Config config;
    std::atomic<bool> running{false};

#if SECURE_PLATFORM_WINDOWS
    static DWORD WINAPI thread_proc(LPVOID p) {
        auto* self = reinterpret_cast<Heartbeat*>(p);
        while (self->running.load(std::memory_order_acquire)) {
            Report r = run_all_checks(self->config);
            if (self->cbk) self->cbk(r);
            ::Sleep(self->interval);
        }
        return 0;
    }
#endif
};
#endif

} // namespace runtime

} // namespace secure

#endif // SECURE_RUNTIME_H
