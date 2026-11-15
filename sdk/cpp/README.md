# TrapKey C++ SDK

Windows x64, C++17, **no third-party dependencies** (CNG + WinHTTP, both ship with Windows).

## Build

```bat
:: x64 Native Tools Command Prompt for VS 2022
cd sdk\cpp
build.bat
```

Output: `build\TrapKey.dll`, `build\TrapKey.lib`, `build\sample.exe`.

Static linking instead of a DLL: compile `trapkey.cpp` directly into your project
(no `TK_BUILD_DLL`, no `TK_USE_DLL`) and link `bcrypt.lib winhttp.lib advapi32.lib`.

## Integrate (3 calls)

```c
#include "trapkey.h"

TK_Init("prd_xxxxxxxx", verifyKey_n, "010001", "https://license.yourdomain.com");

if (TK_IsLicensed() != TK_OK) {
    // show your activation dialog
    TK_Activate(userTypedKey);
}

if (TK_IsLicensed() == TK_OK) {
    // unlock paid features
}
```

`TK_Init` returns `TK_OK` even when no licence is cached — ask `TK_IsLicensed()`
for the real state. A return value other than `TK_OK` means the *arguments* are wrong
(bad product id / modulus / exponent), not the licence.

## What happens on disk

| Path | Content |
|---|---|
| `%APPDATA%\TrapKey\<productId>.lic` | signed licence blob (no secret material) |
| `%APPDATA%\TrapKey\hwid.txt` | fallback machine id, only if `MachineGuid` is unreadable |

Deleting them logs the machine out; the server still counts the seat until
`TK_Deactivate` or an admin revoke.

## Calling from a worker thread

Every export takes an internal mutex, so calls are safe from any thread.
Do not call `TK_Refresh()` from inside `DllMain`.

## Publishing checklist

- [ ] Ship `TrapKey.dll` next to the exe (or link statically).
- [ ] Never ship `verifyKey.n` in plaintext **only** — that's fine, it's public. Never
      ship the *private* key (it stays on the server).
- [ ] Run `trapkey protect YourApp.exe --level 2` as the last build step.
- [ ] Call `TK_IsLicensed()` at the feature gate, not just at startup.
- [ ] Test the "revoked while running" flow: revoke in the dashboard, then `TK_Refresh()`.

## Compile status

The code in this folder was written against the documented CNG/WinHTTP APIs but was
**not compiled in the environment that generated this repo** (Linux, no MSVC toolchain).
Treat the first `build.bat` run as part of the work: fix warnings, then add a
`windows-latest` CI job before selling.
