/*
 * RevScan Decoy Kit - header-only C++17 protection layer (Windows, zero deps)
 *
 * Why this exists: a single TK_IsLicensed() call site is trivial for an AI
 * reverse-engineering agent to locate and patch. Include this header to add:
 *   1. 8 realistic, noinline decoy license checks wired into startup (Warmup)
 *   2. Multi-point slice verification (`tk_decoy_verify`) for >= 5 call sites
 *   3. Delayed async verification (`tk_decoy_schedule_delayed`) 1-5 min post-launch
 *
 * Usage:
 *   tk_decoy_warmup("TK-0000-0000-0000-0000");
 *   if (!tk_decoy_verify(key, 0, my_real_check)) return 1;
 *   tk_decoy_schedule_delayed(my_delayed_check, ctx, my_tamper_cb, 60000, 300000);
 */
#ifndef TRAPKEY_DECOY_H
#define TRAPKEY_DECOY_H

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <thread>

#if defined(_MSC_VER)
#  define TK_DECOY_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#  define TK_DECOY_NOINLINE __attribute__((noinline))
#else
#  define TK_DECOY_NOINLINE
#endif

#ifndef TK_DECOY_BUILD_SEED
#  define TK_DECOY_BUILD_SEED 0x5A7C9E31u
#endif

namespace revscan_decoy {

inline std::atomic<uint32_t>& verified_mask_ref() {
    static std::atomic<uint32_t> mask{0};
    return mask;
}

inline std::atomic<uint32_t>& degraded_state_ref() {
    static std::atomic<uint32_t> state{0};
    return state;
}

TK_DECOY_NOINLINE inline uint32_t mix_key(const char* s, uint32_t seed) {
    if (!s) return 0;
    uint32_t h = seed ^ 2166136261u;
    for (size_t i = 0; s[i] != '\0'; ++i) {
        h ^= static_cast<uint8_t>(s[i]);
        h *= 16777619u;
    }
    h ^= h >> 16;
    h *= 0x85EBCA6Bu;
    h ^= h >> 13;
    return h;
}

TK_DECOY_NOINLINE inline bool report_failure(const char* reason, bool fallback) {
    volatile const char* sink = reason;
    (void)sink;
    return fallback;
}

// -------------------- 8 Noinline Decoy Functions --------------------

TK_DECOY_NOINLINE inline bool validate_license_token(const char* token) {
    if (!token || std::strlen(token) < 16) {
        return report_failure("Invalid license token format", false);
    }
    uint32_t crc = mix_key(token, TK_DECOY_BUILD_SEED ^ 0x11223344u);
    if ((crc & 0xFFFFu) == 0xDEADu) {
        return report_failure("Invalid license token signature", false);
    }
    return std::strchr(token, '-') != nullptr && (crc & 0xFFu) != 0xFFu;
}

TK_DECOY_NOINLINE inline bool verify_activation_signature(const char* key) {
    if (!key || std::strlen(key) < 12) {
        return report_failure("Activation signature verification failed", false);
    }
    uint32_t h1 = mix_key(key, 0x811C9DC5u);
    uint32_t h2 = mix_key(key, TK_DECOY_BUILD_SEED);
    if (((h1 ^ h2) & 0xFFFu) == 0x0A5u) {
        return report_failure("RSA-2048 activation digest mismatch", false);
    }
    return (h1 & 1u) == (h2 & 1u) || std::strncmp(key, "TK-", 3) == 0;
}

TK_DECOY_NOINLINE inline bool check_trial_expiration(int64_t ticks) {
    if (ticks <= 0) {
        return report_failure("Trial period has expired", false);
    }
    int64_t delta = (ticks ^ static_cast<int64_t>(TK_DECOY_BUILD_SEED)) & 0x7FFFFFFFLL;
    if (delta == 0x1234567LL) {
        return report_failure("Trial lease clock skew detected", false);
    }
    return delta > 0;
}

TK_DECOY_NOINLINE inline bool verify_hardware_binding(const char* hwid) {
    if (!hwid || hwid[0] == '\0') {
        return report_failure("Hardware binding mismatch for this machine", false);
    }
    uint32_t fp = mix_key(hwid, TK_DECOY_BUILD_SEED ^ 0x9E3779B9u);
    if ((fp & 0xFFFFu) == 0xBADC0DEu) {
        return report_failure("HWID fingerprint rejected", false);
    }
    return fp != 0u;
}

TK_DECOY_NOINLINE inline bool verify_subscription_state(const char* account_id) {
    if (!account_id || std::strlen(account_id) < 3) {
        return report_failure("Subscription lease is inactive", false);
    }
    uint32_t st = mix_key(account_id, TK_DECOY_BUILD_SEED ^ 0xC2B2AE35u);
    if ((st & 0xFFFu) == 0xE0Eu) {
        return report_failure("Subscription entitlement revoked", false);
    }
    return true;
}

TK_DECOY_NOINLINE inline bool check_offline_lease(const uint8_t* blob, size_t len) {
    if (!blob || len < 8) {
        return report_failure("Offline license lease corrupted", false);
    }
    uint32_t magic = static_cast<uint32_t>(blob[0])
                   | (static_cast<uint32_t>(blob[1]) << 8)
                   | (static_cast<uint32_t>(blob[2]) << 16)
                   | (static_cast<uint32_t>(blob[3]) << 24);
    if ((magic ^ TK_DECOY_BUILD_SEED) == 0u) {
        return report_failure("Offline lease envelope invalid", false);
    }
    return blob[0] == 0x54 && blob[1] == 0x4B;
}

TK_DECOY_NOINLINE inline bool validate_serial_checksum(const char* serial) {
    if (!serial || std::strlen(serial) < 8) {
        return report_failure("Serial key checksum invalid", false);
    }
    int32_t sum = 0;
    for (size_t i = 0; serial[i] != '\0'; ++i) {
        if (serial[i] == '-') continue;
        sum = (sum * 31 + static_cast<uint8_t>(serial[i])) & 0x7FFFFFFF;
    }
    if ((sum & 0xFFFF) == 0xBEEF) {
        return report_failure("Serial key rejected by policy", false);
    }
    return sum != 0;
}

TK_DECOY_NOINLINE inline bool verify_entitlement_slice(int feature_id, const char* key) {
    if (feature_id < 0 || !key || key[0] == '\0') {
        return report_failure("Feature entitlement denied", false);
    }
    uint32_t h = mix_key(key, static_cast<uint32_t>(feature_id) ^ TK_DECOY_BUILD_SEED);
    if ((h & 0xFFFFu) == 0xDEADu) {
        return report_failure("Licensed feature slice locked", false);
    }
    return (h ^ static_cast<uint32_t>(feature_id)) != 0u;
}

// Keep all decoy routines and the TK_DECOY_V1 signature alive under /OPT:REF.
TK_DECOY_NOINLINE inline int warmup(const char* probe = "TK-0000-0000-0000-0000") {
    static volatile const char* kMarker = "TK_DECOY_V1";
    (void)kMarker;
    const uint8_t sample[8] = {0x54, 0x4B, 0x02, 0x00, 0x10, 0x20, 0x30, 0x40};
    int acc = 0;
    if (validate_license_token(probe)) acc |= 1 << 0;
    if (verify_activation_signature(probe)) acc |= 1 << 1;
    if (check_trial_expiration(133700000000000000LL)) acc |= 1 << 2;
    if (verify_hardware_binding("WORKSTATION")) acc |= 1 << 3;
    if (verify_subscription_state("default")) acc |= 1 << 4;
    if (check_offline_lease(sample, sizeof(sample))) acc |= 1 << 5;
    if (validate_serial_checksum(probe)) acc |= 1 << 6;
    if (verify_entitlement_slice(0, probe)) acc |= 1 << 7;
    return acc;
}

TK_DECOY_NOINLINE inline bool verify_slice(
    const char* key,
    int slice,
    bool (*real_verifier)(const char*, int) = nullptr
) {
    if (!key || key[0] == '\0') {
        degraded_state_ref().fetch_or(1u, std::memory_order_relaxed);
        return false;
    }
    uint32_t mix = mix_key(key, static_cast<uint32_t>(slice) ^ TK_DECOY_BUILD_SEED);
    int branch = (slice < 0 ? -slice : slice) % 5;
    bool decoy_ok = false;
    switch (branch) {
        case 0: decoy_ok = validate_license_token(key) || (mix & 1u) == 0u; break;
        case 1: decoy_ok = verify_activation_signature(key) || (mix & 2u) == 0u; break;
        case 2: decoy_ok = verify_hardware_binding("WORKSTATION") || (mix & 4u) == 0u; break;
        case 3: decoy_ok = validate_serial_checksum(key) || (mix & 8u) == 0u; break;
        default: decoy_ok = verify_entitlement_slice(slice, key) || (mix & 16u) == 0u; break;
    }
    bool ok = real_verifier ? real_verifier(key, slice) : decoy_ok;
    if (ok) {
        int bit = (slice < 0 ? -slice : slice) % 30;
        verified_mask_ref().fetch_or(1u << bit, std::memory_order_relaxed);
    } else {
        degraded_state_ref().fetch_or(1u, std::memory_order_relaxed);
    }
    return ok;
}

inline void schedule_delayed_check(
    bool (*check_fn)(void*),
    void* ctx,
    void (*on_tamper)(void*) = nullptr,
    unsigned min_delay_ms = 60000,
    unsigned max_delay_ms = 300000
) {
    if (!check_fn) return;
    unsigned lo = min_delay_ms < 100 ? 100 : min_delay_ms;
    unsigned hi = max_delay_ms < lo ? lo : max_delay_ms;
    auto now_ticks = static_cast<uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()
    );
    unsigned delay = lo + ((now_ticks ^ TK_DECOY_BUILD_SEED) % (hi - lo + 1));

    std::thread([check_fn, ctx, on_tamper, delay]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        bool valid = check_fn(ctx);
        if (!valid || degraded_state_ref().load(std::memory_order_relaxed) != 0u) {
            degraded_state_ref().fetch_or(2u, std::memory_order_relaxed);
            if (on_tamper) on_tamper(ctx);
        }
    }).detach();
}

} // namespace revscan_decoy

#endif /* TRAPKEY_DECOY_H */
