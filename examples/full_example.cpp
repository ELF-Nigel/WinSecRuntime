#include <vector>
#include <cstdio>
#include "WinSecRuntime/WinSecRuntime.h"

static void on_alert(secure::Report r) {
    if (!r.ok()) {
        std::printf("Security alert flags: 0x%llx\n", static_cast<unsigned long long>(r.flags));
    }
}

int main() {
    WinSecRuntime::Policy policy{};

    policy.cfg.expected_parent_pid = 0;
    policy.cfg.expected_image_path = nullptr;

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

    static constexpr uint32_t vm_vendor_hashes[] = {
        secure::util::fnv1a32_ci_literal("kvmkvmkvm"),
        secure::util::fnv1a32_ci_literal("vmwarevmware"),
        secure::util::fnv1a32_ci_literal("microsoft hv"),
        secure::util::fnv1a32_ci_literal("xenvmmxenvmm")
    };
    policy.cfg.vm_vendor_hashes = vm_vendor_hashes;
    policy.cfg.vm_vendor_hash_count = sizeof(vm_vendor_hashes) / sizeof(vm_vendor_hashes[0]);

    policy.cfg.iat_baseline = secure::iat_guard::iat_hash(::GetModuleHandleW(nullptr));
    policy.cfg.iat_bounds_check = true;
    policy.cfg.iat_write_protect = true;
    policy.cfg.import_name_hash_baseline = secure::iat_guard::import_name_hash(::GetModuleHandleW(nullptr));
    policy.cfg.import_module_hash_baseline = secure::anti_tamper::import_module_hash();

    size_t iat_count = secure::iat_guard::iat_entry_count(::GetModuleHandleW(nullptr));
    std::vector<void*> iat_mirror(iat_count);
    if (iat_count > 0) {
        secure::iat_guard::iat_fill_mirror(::GetModuleHandleW(nullptr), iat_mirror.data(), iat_mirror.size());
        policy.cfg.iat_mirror = iat_mirror.data();
        policy.cfg.iat_mirror_count = iat_mirror.size();
    }

    policy.cfg.text_rolling_crc_window = 64;
    policy.cfg.text_rolling_crc_stride = 16;
    policy.cfg.text_rolling_crc_baseline = secure::anti_tamper::text_rolling_crc_current(
        policy.cfg.text_rolling_crc_window,
        policy.cfg.text_rolling_crc_stride);

    policy.cfg.text_sha256_baseline = secure::anti_tamper::text_sha256_current();

    policy.cfg.text_chunk_seed = 0xC0FFEEu;
    policy.cfg.text_chunk_size = 64;
    policy.cfg.text_chunk_count = 32;
    policy.cfg.text_chunk_baseline = secure::anti_tamper::text_chunk_hash_current(
        policy.cfg.text_chunk_seed, policy.cfg.text_chunk_size, policy.cfg.text_chunk_count);

    policy.cfg.delay_import_name_hash_baseline = secure::anti_tamper::delay_import_name_hash();
    policy.cfg.export_name_hash_baseline = secure::anti_tamper::export_name_hash();
    policy.cfg.tls_callback_expected = secure::anti_tamper::tls_callback_count();
    policy.cfg.tls_callback_hash_baseline = secure::anti_tamper::tls_callback_hash();
    policy.cfg.entry_prologue_size = 16;
    policy.cfg.entry_prologue_baseline = secure::anti_tamper::entry_prologue_hash_current(policy.cfg.entry_prologue_size);
    policy.cfg.signature_required = false;

    double entropy = secure::anti_tamper::text_entropy_current();
    policy.cfg.text_entropy_min = entropy - 0.3;
    policy.cfg.text_entropy_max = entropy + 0.3;

    static const secure::anti_hook::PrologueGuard guards[] = {
        { (const void*)&::GetProcAddress, secure::anti_hook::prologue_hash((const void*)&::GetProcAddress, 16), 16 }
    };
    policy.cfg.prologue_guards = guards;
    policy.cfg.prologue_guard_count = sizeof(guards) / sizeof(guards[0]);

    WinSecRuntime::Initialize(WinSecRuntime::Mode::Moderate, policy.cfg);

    secure::runtime::Heartbeat hb(5000, &on_alert, policy.cfg);

    secure::Report r = WinSecRuntime::RunAll(policy);
    if (!r.ok()) {
        return 1;
    }

    return 0;
}
