# Electron / Node binding

Status: **not shipped in v0.1.** Read this before wiring RevScan into an Electron app.

## Why there is no `asar` protection

`app.asar` is an archive, not a container with any confidentiality: `npx asar extract`
prints the whole JavaScript bundle. Any licence check, API token or signed URL inside
renderer/main JS is readable in under a second — which is exactly why `revscan score`
subtracts 12 points when it sees `app.asar`.

## Recommended integration (v0.1, works today)

Keep the decision in **native code** and expose a single boolean to JS:

```
your-app/
├─ resources/
│  ├─ RevScan.dll        <- from sdk/cpp/build
│  └─ tk-helper.exe      <- 40 lines: TK_Init + TK_IsLicensed, exit code 0/1
├─ main.js
└─ app.asar
```

`main.js` (main process only — never the renderer):

```js
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function isLicensed() {
  const helper = path.join(process.resourcesPath, 'tk-helper.exe');
  try {
    execFileSync(helper, [], { windowsHide: true, timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}
```

This gives you HWID binding and revocation with a single spawn at startup (~15 ms).
It is not elegant; it is small, it is native, and it survives `asar extract`.

## v2 (not built yet)

A proper `node-addon-api` addon (`sdk/electron/binding.gyp`) that links `RevScan.lib`
statically and exposes `isLicensed(): boolean`. Do this only after the first paying
customer asks for it — a native build toolchain is a maintenance tax.

## What is still exposed

JavaScript that gated a feature can always be patched in the asar. If a feature must be
paid-only, put the *logic* (not the check) in native code. RevScan makes the check
cheap; it does not make JavaScript secret.
