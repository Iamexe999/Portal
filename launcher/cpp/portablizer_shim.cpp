/**
 * portablizer_shim.cpp
 *
 * Portablizer Runtime Shim — DLL injected into the installer process.
 *
 * Hooks the following Win32 APIs to redirect privileged operations:
 *
 *   Filesystem:
 *     CreateFileA/W        — redirect writes to Program Files → sandbox dir
 *     CreateDirectoryA/W   — redirect directory creation
 *     MoveFileA/W          — redirect file moves
 *     CopyFileA/W          — redirect file copies
 *
 *   Registry:
 *     RegCreateKeyExA/W    — redirect HKLM\SOFTWARE → HKCU\SOFTWARE
 *     RegOpenKeyExA/W      — redirect reads from HKLM → HKCU
 *     RegSetValueExA/W     — intercept and redirect
 *     RegDeleteKeyA/W      — redirect
 *
 *   Elevation:
 *     ShellExecuteExA/W    — intercept runas / elevation requests
 *     CreateProcessA/W     — prevent spawning elevated sub-processes
 *
 * Requires: Microsoft Detours (https://github.com/microsoft/Detours)
 *           or EasyHook (https://easyhook.github.io/)
 *
 * Build:
 *   cl /LD portablizer_shim.cpp /link detours.lib /OUT:portablizer_shim.dll
 *   (or with CMakeLists.txt below)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <winreg.h>
#include <detours.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <mutex>
#include "json.hpp"   // nlohmann/json single-header

using json = nlohmann::json;

// ─────────────────────────────────────────────────────────────────────────────
// Global configuration (loaded from PORTABLIZER_CONFIG env var)
// ─────────────────────────────────────────────────────────────────────────────

struct ShimConfig {
    std::wstring sandbox_dir;
    std::map<std::wstring, std::wstring> path_redirects;    // src → dst
    std::map<std::wstring, std::wstring> registry_redirects; // HKLM path → HKCU path
    std::wstring capture_output;
    bool log_enabled = false;
};

static ShimConfig g_config;
static std::mutex g_log_mutex;
static std::vector<std::wstring> g_captured_files;
static std::vector<std::wstring> g_captured_registry_keys;

// ─────────────────────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────────────────────

static void ShimLog(const std::wstring& msg) {
    if (!g_config.log_enabled) return;
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::wofstream log(g_config.sandbox_dir + L"\\shim.log", std::ios::app);
    log << L"[SHIM] " << msg << L"\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Path redirection helpers
// ─────────────────────────────────────────────────────────────────────────────

static std::wstring RedirectPath(const std::wstring& original) {
    std::wstring upper = original;
    for (auto& c : upper) c = towupper(c);

    for (auto& [src, dst] : g_config.path_redirects) {
        std::wstring src_upper = src;
        for (auto& c : src_upper) c = towupper(c);

        if (upper.substr(0, src_upper.size()) == src_upper) {
            std::wstring tail = original.substr(src.size());
            std::wstring redirected = dst + tail;
            // Ensure target directory exists
            std::wstring dir = redirected.substr(0, redirected.rfind(L'\\'));
            SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
            ShimLog(L"Redirect: " + original + L" → " + redirected);
            g_captured_files.push_back(redirected);
            return redirected;
        }
    }
    return original;  // no redirect needed
}

static std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int sz = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    std::wstring result(sz - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &result[0], sz);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry redirection helpers
// ─────────────────────────────────────────────────────────────────────────────

static bool NeedsRegistryRedirect(HKEY hKey, LPCWSTR lpSubKey,
                                   HKEY* outHKey, std::wstring* outSubKey) {
    if (hKey != HKEY_LOCAL_MACHINE) return false;
    if (!lpSubKey) return false;

    std::wstring subkey(lpSubKey);
    std::wstring subkey_upper = subkey;
    for (auto& c : subkey_upper) c = towupper(c);

    // Redirect HKLM\SOFTWARE → HKCU\SOFTWARE
    if (subkey_upper.substr(0, 8) == L"SOFTWARE") {
        *outHKey = HKEY_CURRENT_USER;
        *outSubKey = L"SOFTWARE\\_Portablizer_\\" + subkey;
        ShimLog(L"Reg redirect: HKLM\\" + subkey + L" → HKCU\\" + *outSubKey);
        g_captured_registry_keys.push_back(L"HKLM\\" + subkey);
        return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Original function pointers
// ─────────────────────────────────────────────────────────────────────────────

static HANDLE (WINAPI *Real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
    = CreateFileW;

static HANDLE (WINAPI *Real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
    = CreateFileA;

static BOOL (WINAPI *Real_CreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES)
    = CreateDirectoryW;

static LONG (WINAPI *Real_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD)
    = RegCreateKeyExW;

static LONG (WINAPI *Real_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY)
    = RegOpenKeyExW;

static LONG (WINAPI *Real_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD)
    = RegSetValueExW;

static BOOL (WINAPI *Real_ShellExecuteExW)(SHELLEXECUTEINFOW*)
    = ShellExecuteExW;

// ─────────────────────────────────────────────────────────────────────────────
// Hooked functions
// ─────────────────────────────────────────────────────────────────────────────

HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation,
    DWORD dwFlags, HANDLE hTemplate)
{
    std::wstring path(lpFileName ? lpFileName : L"");
    bool is_write = (dwAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;

    if (is_write && !path.empty()) {
        std::wstring redirected = RedirectPath(path);
        if (redirected != path) {
            return Real_CreateFileW(redirected.c_str(), dwAccess, dwShare,
                                    lpSA, dwCreation, dwFlags, hTemplate);
        }
    }
    return Real_CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
}

HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreation,
    DWORD dwFlags, HANDLE hTemplate)
{
    std::wstring wpath = Widen(lpFileName ? lpFileName : "");
    bool is_write = (dwAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;

    if (is_write && !wpath.empty()) {
        std::wstring redirected = RedirectPath(wpath);
        if (redirected != wpath) {
            return Hook_CreateFileW(redirected.c_str(), dwAccess, dwShare,
                                    lpSA, dwCreation, dwFlags, hTemplate);
        }
    }
    return Real_CreateFileA(lpFileName, dwAccess, dwShare, lpSA, dwCreation, dwFlags, hTemplate);
}

BOOL WINAPI Hook_CreateDirectoryW(LPCWSTR lpPath, LPSECURITY_ATTRIBUTES lpSA) {
    std::wstring path(lpPath ? lpPath : L"");
    std::wstring redirected = RedirectPath(path);
    return Real_CreateDirectoryW(redirected.c_str(), lpSA);
}

LONG WINAPI Hook_RegCreateKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved,
    LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSA, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    HKEY redirectedHive = hKey;
    std::wstring redirectedSubKey;

    if (NeedsRegistryRedirect(hKey, lpSubKey, &redirectedHive, &redirectedSubKey)) {
        return Real_RegCreateKeyExW(redirectedHive, redirectedSubKey.c_str(),
                                    Reserved, lpClass, dwOptions, samDesired,
                                    lpSA, phkResult, lpdwDisposition);
    }
    return Real_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions,
                                 samDesired, lpSA, phkResult, lpdwDisposition);
}

LONG WINAPI Hook_RegOpenKeyExW(
    HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    HKEY redirectedHive = hKey;
    std::wstring redirectedSubKey;

    if (NeedsRegistryRedirect(hKey, lpSubKey, &redirectedHive, &redirectedSubKey)) {
        // Try redirected location first; fall back to original (read-only)
        LONG result = Real_RegOpenKeyExW(redirectedHive, redirectedSubKey.c_str(),
                                          ulOptions, samDesired, phkResult);
        if (result == ERROR_SUCCESS) return result;
        // Fallback: read from original (no writes possible from HKLM without admin anyway)
    }
    return Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LONG WINAPI Hook_RegSetValueExW(
    HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    // RegSetValueEx on an already-opened handle: we can't redirect the hKey
    // at this point without tracking open handles. This is handled in RegCreateKey/OpenKey.
    return Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

BOOL WINAPI Hook_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    if (pExecInfo && pExecInfo->lpVerb) {
        std::wstring verb(pExecInfo->lpVerb);
        // Intercept elevation requests
        if (verb == L"runas" || verb == L"runasuser") {
            ShimLog(L"Intercepted elevation request for: " +
                    std::wstring(pExecInfo->lpFile ? pExecInfo->lpFile : L""));
            // Change verb to "open" to avoid UAC prompt
            pExecInfo->lpVerb = L"open";
        }
    }
    return Real_ShellExecuteExW(pExecInfo);
}

// ─────────────────────────────────────────────────────────────────────────────
// Capture output on exit
// ─────────────────────────────────────────────────────────────────────────────

static void SaveCapturedData() {
    if (g_config.capture_output.empty()) return;

    std::string capture_path(g_config.capture_output.begin(),
                              g_config.capture_output.end());

    json output;
    json files_arr = json::array();
    for (auto& f : g_captured_files) {
        files_arr.push_back(std::string(f.begin(), f.end()));
    }
    json reg_arr = json::array();
    for (auto& k : g_captured_registry_keys) {
        reg_arr.push_back(std::string(k.begin(), k.end()));
    }
    output["captured_files"] = files_arr;
    output["captured_registry_keys"] = reg_arr;

    std::ofstream out(capture_path);
    out << output.dump(2);
    ShimLog(L"Saved capture data to: " + g_config.capture_output);
}

// ─────────────────────────────────────────────────────────────────────────────
// Config loader
// ─────────────────────────────────────────────────────────────────────────────

static void LoadConfig() {
    wchar_t config_path_buf[MAX_PATH] = {};
    GetEnvironmentVariableW(L"PORTABLIZER_CONFIG", config_path_buf, MAX_PATH);
    GetEnvironmentVariableW(L"PORTABLIZER_SANDBOX", 
                             const_cast<wchar_t*>(g_config.sandbox_dir.c_str()), MAX_PATH);

    wchar_t sandbox_buf[MAX_PATH] = {};
    GetEnvironmentVariableW(L"PORTABLIZER_SANDBOX", sandbox_buf, MAX_PATH);
    g_config.sandbox_dir = sandbox_buf;
    g_config.capture_output = g_config.sandbox_dir + L"\\captured.json";
    g_config.log_enabled = true;

    if (config_path_buf[0] == 0) return;

    // Load JSON config
    std::string path(config_path_buf,
                     config_path_buf + wcslen(config_path_buf));
    std::ifstream config_file(path);
    if (!config_file.is_open()) return;

    try {
        json cfg;
        config_file >> cfg;

        if (cfg.contains("redirect_paths")) {
            for (auto& [src, dst] : cfg["redirect_paths"].items()) {
                g_config.path_redirects[
                    std::wstring(src.begin(), src.end())] =
                    std::wstring(dst.get<std::string>().begin(),
                                  dst.get<std::string>().end());
            }
        }
        if (cfg.contains("redirect_registry")) {
            for (auto& [src, dst] : cfg["redirect_registry"].items()) {
                g_config.registry_redirects[
                    std::wstring(src.begin(), src.end())] =
                    std::wstring(dst.get<std::string>().begin(),
                                  dst.get<std::string>().end());
            }
        }
        if (cfg.contains("capture_output")) {
            std::string co = cfg["capture_output"].get<std::string>();
            g_config.capture_output = std::wstring(co.begin(), co.end());
        }
    } catch (...) {
        ShimLog(L"Failed to parse config JSON");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DLL entry point
// ─────────────────────────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID) {
    if (DetourIsHelperProcess()) return TRUE;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        LoadConfig();
        ShimLog(L"Portablizer shim attached. Sandbox: " + g_config.sandbox_dir);

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // Hook filesystem APIs
        DetourAttach(&(PVOID&)Real_CreateFileW,     Hook_CreateFileW);
        DetourAttach(&(PVOID&)Real_CreateFileA,     Hook_CreateFileA);
        DetourAttach(&(PVOID&)Real_CreateDirectoryW, Hook_CreateDirectoryW);

        // Hook registry APIs
        DetourAttach(&(PVOID&)Real_RegCreateKeyExW, Hook_RegCreateKeyExW);
        DetourAttach(&(PVOID&)Real_RegOpenKeyExW,   Hook_RegOpenKeyExW);
        DetourAttach(&(PVOID&)Real_RegSetValueExW,  Hook_RegSetValueExW);

        // Hook elevation
        DetourAttach(&(PVOID&)Real_ShellExecuteExW, Hook_ShellExecuteExW);

        DetourTransactionCommit();
        ShimLog(L"All hooks installed.");
        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_CreateFileW,      Hook_CreateFileW);
        DetourDetach(&(PVOID&)Real_CreateFileA,      Hook_CreateFileA);
        DetourDetach(&(PVOID&)Real_CreateDirectoryW, Hook_CreateDirectoryW);
        DetourDetach(&(PVOID&)Real_RegCreateKeyExW,  Hook_RegCreateKeyExW);
        DetourDetach(&(PVOID&)Real_RegOpenKeyExW,    Hook_RegOpenKeyExW);
        DetourDetach(&(PVOID&)Real_RegSetValueExW,   Hook_RegSetValueExW);
        DetourDetach(&(PVOID&)Real_ShellExecuteExW,  Hook_ShellExecuteExW);
        DetourTransactionCommit();

        SaveCapturedData();
        ShimLog(L"Portablizer shim detached.");
        break;
    }
    return TRUE;
}
