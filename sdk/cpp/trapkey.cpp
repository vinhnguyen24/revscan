/*
 * TrapKey SDK - implementation (Windows, C++17, zero third-party dependencies)
 *
 * Crypto: RSA-2048/PKCS#1 v1.5/SHA-256 via CNG (bcrypt.dll).
 * Network: WinHTTP (only used by Activate/Refresh/Deactivate).
 *
 * Build:
 *   cl /std:c++17 /EHsc /O2 /DTK_BUILD_DLL /LD trapkey.cpp /link bcrypt.lib winhttp.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <vector>

#include "trapkey.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
#endif

namespace {

/* ------------------------------- state -------------------------------- */

std::mutex g_mu;
bool g_initialized = false;
std::string g_productId;
std::string g_serverUrl;
std::string g_license;          // "<claims_b64>.<sig_b64>"
std::string g_lastError;
std::string g_hwid;             // computed once
TK_Status g_status = TK_ERR_NOT_INITIALIZED;
std::vector<BYTE> g_modulus;
std::vector<BYTE> g_exponent;

/* ------------------------------ helpers ------------------------------- */

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

void SetError(TK_Status st, const char* msg) {
    g_status = st;
    g_lastError = msg ? msg : "";
}

int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool FromHex(const std::string& hex, std::vector<BYTE>& out) {
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = HexVal(hex[i]);
        int lo = HexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((BYTE)((hi << 4) | lo));
    }
    return true;
}

std::string ToHexLower(const BYTE* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

/* base64url, no padding required */
bool B64UrlDecode(const std::string& in, std::vector<BYTE>& out) {
    auto map = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    out.clear();
    int acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = map(c);
        if (v < 0) return false;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((BYTE)((acc >> bits) & 0xFF));
        }
    }
    // Reject non-canonical encodings (leftover high bits must be zero), otherwise
    // several strings decode to the same bytes and comparisons get confusing.
    if (bits > 0 && (acc & ((1 << bits) - 1)) != 0) return false;
    return true;
}

/* ------------------------------- crypto ------------------------------- */

bool Sha256(const BYTE* data, size_t len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
            if (BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0) == 0 &&
                BCryptFinishHash(hash, out, 32, 0) == 0) {
                ok = true;
            }
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

bool VerifyRsaPkcs1Sha256(const std::string& body, const std::vector<BYTE>& sig) {
    if (g_modulus.empty() || g_exponent.empty() || sig.empty()) return false;

    BCRYPT_ALG_HANDLE rsaAlg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    BCRYPT_ALG_HANDLE shaAlg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;

    do {
        if (BCryptOpenAlgorithmProvider(&rsaAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0) break;
        if (BCryptOpenAlgorithmProvider(&shaAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) break;

        const size_t total = sizeof(BCRYPT_RSAKEY_BLOB) + g_exponent.size() + g_modulus.size();
        std::vector<BYTE> blob(total, 0);
        BCRYPT_RSAKEY_BLOB* hdr = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
        hdr->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        hdr->BitLength = (ULONG)(g_modulus.size() * 8);
        hdr->cbPublicExp = (ULONG)g_exponent.size();
        hdr->cbModulus = (ULONG)g_modulus.size();
        hdr->cbPrime1 = 0;
        hdr->cbPrime2 = 0;
        BYTE* p = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        memcpy(p, g_exponent.data(), g_exponent.size());
        memcpy(p + g_exponent.size(), g_modulus.data(), g_modulus.size());

        if (BCryptImportKeyPair(rsaAlg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
                                blob.data(), (ULONG)blob.size(), 0) != 0) {
            break;
        }

        BYTE digest[32];
        if (BCryptCreateHash(shaAlg, &hash, nullptr, 0, nullptr, 0, 0) != 0) break;
        if (BCryptHashData(hash, (PUCHAR)body.data(), (ULONG)body.size(), 0) != 0) break;
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) break;

        // CNG requires BCRYPT_PKCS1_PADDING_INFO when BCRYPT_PAD_PKCS1 is passed;
        // a nullptr pPaddingInfo fails with STATUS_INVALID_PARAMETER.
        BCRYPT_PKCS1_PADDING_INFO padInfo = { BCRYPT_SHA256_ALGORITHM };
        NTSTATUS st = BCryptVerifySignature(key, &padInfo, digest, sizeof(digest),
                                            (PUCHAR)sig.data(), (ULONG)sig.size(),
                                            BCRYPT_PAD_PKCS1);
        ok = (st == 0);
    } while (false);

    if (hash) BCryptDestroyHash(hash);
    if (key) BCryptDestroyKey(key);
    if (shaAlg) BCryptCloseAlgorithmProvider(shaAlg, 0);
    if (rsaAlg) BCryptCloseAlgorithmProvider(rsaAlg, 0);
    return ok;
}

/* ------------------------------ claims -------------------------------- */

struct Claims {
    long long exp = 0;
    std::string hwid;
    std::string pid;
    std::string key;
};

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

/* Deliberately minimal JSON reader: the claims object is generated by us and
 * contains only flat scalars (no nesting, no escaped quotes). */
bool JsonFieldStart(const std::string& json, const char* name, size_t& pos) {
    std::string needle = std::string("\"") + name + "\"";
    size_t at = json.find(needle);
    if (at == std::string::npos) return false;
    at = json.find(':', at + needle.size());
    if (at == std::string::npos) return false;
    ++at;
    while (at < json.size() && (json[at] == ' ' || json[at] == '\t' || json[at] == '\n' || json[at] == '\r')) ++at;
    if (at >= json.size()) return false;
    pos = at;
    return true;
}

bool JsonString(const std::string& json, const char* name, std::string& out) {
    size_t pos = 0;
    if (!JsonFieldStart(json, name, pos) || json[pos] != '"') return false;
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return false;
    out = json.substr(pos + 1, end - pos - 1);
    return true;
}

bool JsonNumber(const std::string& json, const char* name, long long& out) {
    size_t pos = 0;
    if (!JsonFieldStart(json, name, pos)) return false;
    size_t end = pos;
    while (end < json.size() && (isdigit((unsigned char)json[end]) || json[end] == '-')) ++end;
    if (end == pos) return false;
    out = strtoll(json.substr(pos, end - pos).c_str(), nullptr, 10);
    return true;
}

/* ------------------------------- machine ------------------------------ */

std::string ReadRegistryString(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    HKEY h = nullptr;
    std::string out;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
        wchar_t buf[512] = {0};
        DWORD size = sizeof(buf) - sizeof(wchar_t);
        DWORD type = 0;
        if (RegQueryValueExW(h, value, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (n > 1) {
                std::string tmp((size_t)n, '\0');
                if (WideCharToMultiByte(CP_UTF8, 0, buf, -1, &tmp[0], n, nullptr, nullptr) == n) {
                    tmp.resize((size_t)n - 1); // drop the terminating NUL
                    out = tmp;
                }
            }
        }
        RegCloseKey(h);
    }
    return out;
}

std::string AppDataDir() {
    char buf[MAX_PATH] = {0};
    std::string base;
    if (GetEnvironmentVariableA("APPDATA", buf, sizeof(buf))) base = buf;
    if (base.empty()) {
        base = ReadRegistryString(HKEY_CURRENT_USER,
                                  L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                                  L"AppData");
        char expanded[MAX_PATH] = {0};
        if (!base.empty() && ExpandEnvironmentStringsA(base.c_str(), expanded, sizeof(expanded))) {
            base = expanded;
        }
    }
    if (base.empty()) base = ".";
    return base + "\\TrapKey";
}

bool ReadFileToString(const std::string& path, std::string& out) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) {
        fclose(f);
        return false;
    }
    out.resize((size_t)len);
    size_t got = fread(&out[0], 1, (size_t)len, f);
    fclose(f);
    out.resize(got);
    return got > 0;
}

bool WriteStringToFile(const std::string& path, const std::string& data) {
    CreateDirectoryA(AppDataDir().c_str(), nullptr);
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    size_t put = fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return put == data.size();
}

std::string CachePath() {
    return AppDataDir() + "\\" + g_productId + ".lic";
}

std::string ComputeHwid(const std::string& guid, const std::string& productId) {
    std::string material = guid + ":" + productId;
    BYTE digest[32] = {0};
    if (!Sha256(reinterpret_cast<const BYTE*>(material.data()), material.size(), digest)) {
        return std::string();
    }
    return ToHexLower(digest, 16); // 32 hex chars
}

std::string ResolveMachineGuid() {
    std::string guid = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    if (!guid.empty()) return guid;

    std::string fallback = AppDataDir() + "\\hwid.txt";
    if (ReadFileToString(fallback, guid) && !guid.empty()) return guid;

    BYTE rnd[16] = {0};
    if (BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        for (size_t i = 0; i < sizeof(rnd); ++i) rnd[i] = (BYTE)(GetTickCount64() >> ((i % 8) * 8));
    }
    guid = ToHexLower(rnd, sizeof(rnd));
    WriteStringToFile(fallback, guid);
    return guid;
}

std::string SanitiseGuid(std::string guid) {
    std::string out;
    out.reserve(guid.size());
    for (char c : guid) {
        if (c == '{' || c == '}' || c == ' ' || c == '-') continue;
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        out.push_back(c);
    }
    return out;
}

/* -------------------------------- token ------------------------------- */

TK_Status ValidateToken(const std::string& token, Claims& claims) {
    size_t dot = token.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= token.size()) {
        SetError(TK_ERR_BAD_SIGNATURE, "malformed license token");
        return TK_ERR_BAD_SIGNATURE;
    }
    std::string body = token.substr(0, dot);
    std::vector<BYTE> sig;
    if (!B64UrlDecode(token.substr(dot + 1), sig)) {
        SetError(TK_ERR_BAD_SIGNATURE, "malformed signature");
        return TK_ERR_BAD_SIGNATURE;
    }
    if (!VerifyRsaPkcs1Sha256(body, sig)) {
        SetError(TK_ERR_BAD_SIGNATURE, "license signature does not match this product");
        return TK_ERR_BAD_SIGNATURE;
    }

    std::vector<BYTE> raw;
    if (!B64UrlDecode(body, raw)) {
        SetError(TK_ERR_BAD_SIGNATURE, "malformed claims");
        return TK_ERR_BAD_SIGNATURE;
    }
    std::string json(raw.begin(), raw.end());

    if (!JsonNumber(json, "exp", claims.exp) || !JsonString(json, "hwid", claims.hwid) ||
        !JsonString(json, "pid", claims.pid)) {
        SetError(TK_ERR_BAD_SIGNATURE, "license is missing required claims");
        return TK_ERR_BAD_SIGNATURE;
    }
    JsonString(json, "key", claims.key);

    if (claims.pid != g_productId) {
        SetError(TK_ERR_KEY_INVALID, "license belongs to a different product");
        return TK_ERR_KEY_INVALID;
    }
    if (claims.exp <= (long long)time(nullptr)) {
        SetError(TK_ERR_EXPIRED, "license expired");
        return TK_ERR_EXPIRED;
    }
    if (claims.hwid != g_hwid) {
        SetError(TK_ERR_HWID_MISMATCH, "license is bound to another machine");
        return TK_ERR_HWID_MISMATCH;
    }

    SetError(TK_OK, "");
    return TK_OK;
}

/* -------------------------------- http -------------------------------- */

struct Url {
    bool https = true;
    std::wstring host;
    INTERNET_PORT port = 443;
    std::wstring path = L"/";
};

bool ParseUrl(const std::string& raw, Url& out) {
    std::string s = raw;
    auto ends = [](const std::string& v, const char* tail) {
        size_t n = strlen(tail);
        return v.size() >= n && v.compare(v.size() - n, n, tail) == 0;
    };
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n')) s.pop_back();
    while (!s.empty() && ends(s, "/")) s.pop_back();

    if (s.rfind("https://", 0) == 0) {
        out.https = true;
        s = s.substr(8);
    } else if (s.rfind("http://", 0) == 0) {
        out.https = false;
        s = s.substr(7);
    } else {
        return false;
    }

    size_t slash = s.find('/');
    std::string hostport = (slash == std::string::npos) ? s : s.substr(0, slash);
    std::string path = (slash == std::string::npos) ? "/" : s.substr(slash);
    if (hostport.empty()) return false;

    std::string host = hostport;
    INTERNET_PORT port = out.https ? 443 : 80;
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(']') == std::string::npos) {
        host = hostport.substr(0, colon);
        port = (INTERNET_PORT)atoi(hostport.c_str() + colon + 1);
    }
    out.host = Utf8ToWide(host);
    out.port = port;
    out.path = Utf8ToWide(path);
    return true;
}

bool HttpPostJson(const std::string& url, const std::string& body, int& statusOut, std::string& responseOut) {
    Url u;
    if (!ParseUrl(url, u)) {
        SetError(TK_ERR_INVALID_ARG, "invalid server url");
        return false;
    }

    HINTERNET session = WinHttpOpen(L"TrapKey/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        SetError(TK_ERR_NETWORK, "WinHttpOpen failed");
        return false;
    }
    WinHttpSetTimeouts(session, 5000, 5000, 5000, 8000);

    bool ok = false;
    HINTERNET conn = nullptr;
    HINTERNET req = nullptr;
    do {
        conn = WinHttpConnect(session, u.host.c_str(), u.port, 0);
        if (!conn) { SetError(TK_ERR_NETWORK, "cannot connect to license server"); break; }

        req = WinHttpOpenRequest(conn, L"POST", u.path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, u.https ? WINHTTP_FLAG_SECURE : 0);
        if (!req) { SetError(TK_ERR_NETWORK, "WinHttpOpenRequest failed"); break; }

        std::wstring headers = L"Content-Type: application/json\r\n";
        if (!WinHttpSendRequest(req, headers.c_str(), (DWORD)-1L, (LPVOID)body.data(),
                                (DWORD)body.size(), (DWORD)body.size(), 0)) {
            SetError(TK_ERR_NETWORK, "request failed (offline?)");
            break;
        }
        if (!WinHttpReceiveResponse(req, nullptr)) {
            SetError(TK_ERR_NETWORK, "no response from license server");
            break;
        }

        DWORD code = 0;
        DWORD len = sizeof(code);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX);
        statusOut = (int)code;

        std::string out;
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(req, &chunk[0], avail, &read) || read == 0) break;
            chunk.resize(read);
            out += chunk;
            if (out.size() > 64 * 1024) break;
        }
        responseOut = out;
        ok = true;
    } while (false);

    if (req) WinHttpCloseHandle(req);
    if (conn) WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok;
}

TK_Status MapHttpError(int status, const std::string& body) {
    std::string code;
    JsonString(body, "code", code);
    if (code == "SEAT_LIMIT") return TK_ERR_SEAT_LIMIT;
    if (code == "KEY_REVOKED" || code == "KEY_EXPIRED" || code == "KEY_NOT_FOUND") return TK_ERR_KEY_INVALID;
    if (status == 409) return TK_ERR_SEAT_LIMIT;
    if (status == 403 || status == 404) return TK_ERR_KEY_INVALID;
    return TK_ERR_SERVER;
}

/* ------------------------------ internals ----------------------------- */

TK_Status IsLicensedLocked() {
    if (!g_initialized) {
        SetError(TK_ERR_NOT_INITIALIZED, "TK_Init was not called");
        return TK_ERR_NOT_INITIALIZED;
    }
    if (g_license.empty()) {
        SetError(TK_ERR_NO_LICENSE, "no license on this machine");
        return TK_ERR_NO_LICENSE;
    }
    Claims claims;
    TK_Status st = ValidateToken(g_license, claims); // re-checks expiry on every call
    if (st != TK_OK) {
        g_license.clear();
        return st;
    }
    return TK_OK;
}

TK_Status LoadCacheLocked() {
    std::string token;
    if (!ReadFileToString(CachePath(), token) || token.empty()) {
        g_license.clear();
        SetError(TK_ERR_NO_LICENSE, "no license on this machine");
        return TK_ERR_NO_LICENSE;
    }
    Claims claims;
    TK_Status st = ValidateToken(token, claims);
    if (st != TK_OK) {
        g_license.clear();
        return st;
    }
    g_license = token;
    return TK_OK;
}

void StoreLicenseLocked(const std::string& token) {
    g_license = token;
    WriteStringToFile(CachePath(), token);
}

void EnsureHwidLocked() {
    if (!g_hwid.empty()) return;
    std::string guid = SanitiseGuid(ResolveMachineGuid());
    if (guid.empty()) guid = "unknown";
    g_hwid = ComputeHwid(guid, g_productId);
}

} // namespace

/* -------------------------------- API --------------------------------- */

extern "C" {

TK_API TK_Status TK_Init(const char* productId, const char* modulusB64Url,
                         const char* exponentHex, const char* serverUrl) {
    std::lock_guard<std::mutex> lock(g_mu);

    if (!productId || !*productId || !modulusB64Url || !*modulusB64Url) {
        SetError(TK_ERR_INVALID_ARG, "TK_Init needs productId and modulus");
        return TK_ERR_INVALID_ARG;
    }

    g_productId = productId;
    g_serverUrl = serverUrl ? serverUrl : "";
    g_modulus.clear();
    g_exponent.clear();

    if (!B64UrlDecode(modulusB64Url, g_modulus) || g_modulus.empty()) {
        SetError(TK_ERR_INVALID_ARG, "modulus is not valid base64url");
        return TK_ERR_INVALID_ARG;
    }
    if (!FromHex(exponentHex ? exponentHex : "010001", g_exponent) || g_exponent.empty()) {
        SetError(TK_ERR_INVALID_ARG, "exponent is not valid hex");
        return TK_ERR_INVALID_ARG;
    }

    g_initialized = true;
    g_hwid = ComputeHwid(SanitiseGuid(ResolveMachineGuid()), g_productId);
    if (g_hwid.empty()) {
        SetError(TK_ERR_INTERNAL, "cannot compute machine id");
        return TK_ERR_INTERNAL;
    }

    LoadCacheLocked();   // TK_OK on success, NO_LICENSE/EXPIRED otherwise -> caller asks IsLicensed
    return TK_OK;
}

TK_API TK_Status TK_IsLicensed(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    return IsLicensedLocked();
}

TK_API TK_Status TK_Activate(const char* key) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_initialized) {
        SetError(TK_ERR_NOT_INITIALIZED, "TK_Init was not called");
        return TK_ERR_NOT_INITIALIZED;
    }
    if (!key || !*key) {
        SetError(TK_ERR_INVALID_ARG, "empty key");
        return TK_ERR_INVALID_ARG;
    }
    if (g_serverUrl.empty()) {
        SetError(TK_ERR_NETWORK, "TK_Init was called without a serverUrl");
        return TK_ERR_NETWORK;
    }

    std::string body = std::string("{\"key\":\"") + JsonEscape(key) +
                       "\",\"productId\":\"" + JsonEscape(g_productId) +
                       "\",\"hwid\":\"" + JsonEscape(g_hwid) +
                       "\",\"appVersion\":\"1.0.0\"}";

    int status = 0;
    std::string response;
    if (!HttpPostJson(g_serverUrl + "/v1/activate", body, status, response)) {
        return g_status; // SetError already called
    }
    if (status != 200) {
        TK_Status st = MapHttpError(status, response);
        SetError(st, "activation refused by server");
        return st;
    }

    std::string token;
    if (!JsonString(response, "license", token) || token.empty()) {
        SetError(TK_ERR_SERVER, "server response has no license");
        return TK_ERR_SERVER;
    }

    Claims claims;
    TK_Status st = ValidateToken(token, claims);
    if (st != TK_OK) return st;

    StoreLicenseLocked(token);
    return TK_OK;
}

TK_API TK_Status TK_Refresh(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_initialized) {
        SetError(TK_ERR_NOT_INITIALIZED, "TK_Init was not called");
        return TK_ERR_NOT_INITIALIZED;
    }
    if (g_license.empty()) {
        return LoadCacheLocked();
    }

    // Offline-first: a network failure must not invalidate a locally valid license.
    if (g_serverUrl.empty()) return IsLicensedLocked();

    std::string body = std::string("{\"license\":\"") + JsonEscape(g_license) +
                       "\",\"hwid\":\"" + JsonEscape(g_hwid) + "\"}";
    int status = 0;
    std::string response;
    if (!HttpPostJson(g_serverUrl + "/v1/validate", body, status, response)) {
        TK_Status local = IsLicensedLocked();   // keeps a valid offline license working
        if (local == TK_OK) SetError(TK_OK, "");
        return local;
    }

    std::string refreshed;
    bool serverSaysValid = response.find("\"valid\":true") != std::string::npos;
    if (serverSaysValid && JsonString(response, "refreshed", refreshed) && !refreshed.empty()) {
        Claims claims;
        if (ValidateToken(refreshed, claims) == TK_OK) {
            StoreLicenseLocked(refreshed);
            return TK_OK;
        }
    }
    if (!serverSaysValid) {
        g_license.clear();
        WriteStringToFile(CachePath(), "");
        SetError(TK_ERR_KEY_INVALID, "license is no longer valid on the server");
        return TK_ERR_KEY_INVALID;
    }
    return IsLicensedLocked();
}

TK_API TK_Status TK_Deactivate(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_initialized) {
        SetError(TK_ERR_NOT_INITIALIZED, "TK_Init was not called");
        return TK_ERR_NOT_INITIALIZED;
    }

    if (!g_license.empty() && !g_serverUrl.empty()) {
        Claims claims;
        if (ValidateToken(g_license, claims) == TK_OK && !claims.key.empty()) {
            std::string body = std::string("{\"key\":\"") + JsonEscape(claims.key) +
                               "\",\"hwid\":\"" + JsonEscape(g_hwid) + "\"}";
            int status = 0;
            std::string response;
            HttpPostJson(g_serverUrl + "/v1/deactivate", body, status, response); // best effort
        }
    }

    g_license.clear();
    WriteStringToFile(CachePath(), "");
    SetError(TK_ERR_NO_LICENSE, "deactivated");
    return TK_OK;
}

TK_API const char* TK_Hwid(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    EnsureHwidLocked();
    return g_hwid.c_str();
}

TK_API long long TK_DaysRemaining(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_license.empty()) return -1;
    size_t dot = g_license.find('.');
    if (dot == std::string::npos) return -1;
    std::vector<BYTE> raw;
    if (!B64UrlDecode(g_license.substr(0, dot), raw)) return -1;
    std::string json(raw.begin(), raw.end());
    long long exp = 0;
    if (!JsonNumber(json, "exp", exp)) return -1;
    long long left = exp - (long long)time(nullptr);
    if (left <= 0) return 0;
    return left / 86400;
}

TK_API const char* TK_LastError(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_lastError.c_str();
}

TK_API void TK_Shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_license.clear();
    g_modulus.clear();
    g_exponent.clear();
    g_productId.clear();
    g_serverUrl.clear();
    g_hwid.clear();
    g_initialized = false;
    g_status = TK_ERR_NOT_INITIALIZED;
    g_lastError.clear();
}

} // extern "C"
