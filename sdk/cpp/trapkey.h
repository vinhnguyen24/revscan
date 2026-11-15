/*
 * TrapKey SDK - public API
 *
 * Vendor integration is three calls:
 *
 *     TK_Init(productId, modulusB64Url, exponentHex, "https://license.vendor.com");
 *     TK_Activate("TK-XXXXX-XXXXX-XXXXX-XXXXX");   // from your activation dialog
 *     if (TK_IsLicensed() == TK_OK) { ... }        // gate your features
 *
 * Nothing here phones home on a normal start: the license blob is verified
 * offline with the embedded public key. TK_Refresh() is optional.
 */
#ifndef TRAPKEY_H
#define TRAPKEY_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TK_API
#  if defined(TK_BUILD_DLL)
#    define TK_API __declspec(dllexport)
#  elif defined(TK_USE_DLL)
#    define TK_API __declspec(dllimport)
#  else
#    define TK_API
#  endif
#endif

typedef enum TK_Status {
    TK_OK = 0,
    TK_ERR_NOT_INITIALIZED = 1,
    TK_ERR_INVALID_ARG = 2,
    TK_ERR_NO_LICENSE = 3,
    TK_ERR_BAD_SIGNATURE = 4,
    TK_ERR_EXPIRED = 5,
    TK_ERR_HWID_MISMATCH = 6,
    TK_ERR_NETWORK = 7,
    TK_ERR_SERVER = 8,
    TK_ERR_SEAT_LIMIT = 9,
    TK_ERR_KEY_INVALID = 10,
    TK_ERR_INTERNAL = 11
} TK_Status;

/* Initialises the SDK and tries to load a cached license.
 *   productId    : "prd_xxxxxxxx" from the TrapKey dashboard
 *   modulusB64Url: verifyKey.n  (base64url)
 *   exponentHex  : verifyKey.e  (hex, usually "010001")
 *   serverUrl    : base URL, e.g. "https://license.vendor.com"; may be NULL for
 *                  offline-only builds (then TK_Activate needs a pre-issued blob)
 * Returns TK_OK even when no license is present; call TK_IsLicensed() next. */
TK_API TK_Status TK_Init(const char* productId,
                         const char* modulusB64Url,
                         const char* exponentHex,
                         const char* serverUrl);

/* TK_OK only when a valid, unexpired, machine-bound license is loaded. */
TK_API TK_Status TK_IsLicensed(void);

/* Activates a key on this machine. Requires TK_Init() with a serverUrl.
 * The resulting blob is verified locally and cached under %APPDATA%\TrapKey. */
TK_API TK_Status TK_Activate(const char* key);

/* Optional: re-validate against the server (picks up revocations early and
 * slides the expiry forward). Safe to call from a background thread. */
TK_API TK_Status TK_Refresh(void);

/* Releases credentials from the server and deletes the local cache. */
TK_API TK_Status TK_Deactivate(void);

/* Stable, privacy-preserving machine id: sha256(machineGuid + ":" + productId)[:32].
 * Same machine yields a different id for every product. Never empty after Init. */
TK_API const char* TK_Hwid(void);

/* Days left on the current license, or -1 when not licensed. */
TK_API long long TK_DaysRemaining(void);

/* Human-readable reason for the last non-OK result. Valid until the next call. */
TK_API const char* TK_LastError(void);

TK_API void TK_Shutdown(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TRAPKEY_H */
