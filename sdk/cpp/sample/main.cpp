// Minimal integration sample. Build it, run it, paste a key.
#include <cstdio>
#include <cstring>

#include "trapkey.h"

// ---- values copied from the TrapKey dashboard (Products -> verifyKey) ----
static const char* kProductId = "prd_REPLACE_ME";
static const char* kModulus   = "REPLACE_WITH_verifyKey_n";
static const char* kExponent  = "010001";
static const char* kServer    = "http://127.0.0.1:7100";

static const char* StatusName(TK_Status st) {
    switch (st) {
        case TK_OK: return "OK";
        case TK_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case TK_ERR_INVALID_ARG: return "INVALID_ARG";
        case TK_ERR_NO_LICENSE: return "NO_LICENSE";
        case TK_ERR_BAD_SIGNATURE: return "BAD_SIGNATURE";
        case TK_ERR_EXPIRED: return "EXPIRED";
        case TK_ERR_HWID_MISMATCH: return "HWID_MISMATCH";
        case TK_ERR_NETWORK: return "NETWORK";
        case TK_ERR_SERVER: return "SERVER";
        case TK_ERR_SEAT_LIMIT: return "SEAT_LIMIT";
        case TK_ERR_KEY_INVALID: return "KEY_INVALID";
        default: return "INTERNAL";
    }
}

int main(int argc, char** argv) {
    TK_Status st = TK_Init(kProductId, kModulus, kExponent, kServer);
    if (st != TK_OK) {
        printf("TK_Init failed: %s (%s)\n", StatusName(st), TK_LastError());
        return 1;
    }
    printf("hwid: %s\n", TK_Hwid());

    st = TK_IsLicensed();
    printf("initial state: %s\n", StatusName(st));

    if (st != TK_OK && argc > 1) {
        st = TK_Activate(argv[1]);
        printf("activate: %s (%s)\n", StatusName(st), st == TK_OK ? "ok" : TK_LastError());
    }

    if (TK_IsLicensed() == TK_OK) {
        printf("licensed, %lld day(s) remaining\n", TK_DaysRemaining());
        // ... unlock your premium features here ...
    } else {
        printf("not licensed: %s\n", TK_LastError());
    }

    TK_Shutdown();
    return 0;
}
