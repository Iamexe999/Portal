# Portablizer

**Convert any Windows `.exe` installer into a portable application that requires no administrator privileges.**

```
portablizer MyApp_Setup.exe
```

---

## How It Works

Most installers require admin because they write to protected locations:

| Installer tries to... | Portablizer does... |
|---|---|
| Write to `C:\Program Files\` | Redirects to `output\app\` |
| Write to `HKEY_LOCAL_MACHINE\SOFTWARE` | Redirects to `HKEY_CURRENT_USER\SOFTWARE` |
| Set `requireAdministrator` in manifest | Patches to `asInvoker` |
| Spawn elevated sub-processes | Intercepts and neutralizes |

The result is a self-contained folder you can run from anywhere — USB drive, network share, or user-writable directory — without ever triggering a UAC prompt.

---

## Quick Start

```bash
# Install
git clone https://github.com/portablizer/portablizer
cd portablizer
pip install -r requirements.txt
python tools/download_tools.py   # Download innounp, lessmsi, etc.

# Convert an installer
python main.py MyApp_Setup.exe

# With options
python main.py MyApp_Setup.exe --output D:\PortableApps\MyApp --method extract

# GUI
python gui.py
```

---

## Conversion Methods

### `auto` (default)
Automatically selects the best method for the detected installer format.

### `extract` — Static Extraction
Unpacks the installer's contents without executing it. Works for:
- **Inno Setup** (`.exe` with embedded archive) — via `innounp` or `innoextract`
- **NSIS** (Nullsoft Scriptable Install System) — via 7-Zip
- **MSI** packages — via `lessmsi` or `msiexec /a`
- **7-Zip SFX**, **WinRAR SFX**, **ZIP SFX** — via 7-Zip
- **Squirrel** (Electron apps like Discord, Slack) — via 7-Zip + NuGet unpack

**Pros:** Fast, no installer execution required, fully offline  
**Cons:** May miss install-time configuration logic

### `sandbox` — Runtime Capture
Runs the installer with API hooks injected (via Microsoft Detours) to intercept all system calls and redirect them to safe locations.

```
portablizer MyApp_Setup.exe --method sandbox
```

**Pros:** Works for any installer format, captures dynamic install logic  
**Cons:** Requires running the installer; needs the Detours shim DLL compiled

---

## Output Structure

```
MyApp_portable/
├── Launch MyApp.bat          ← Double-click to run
├── README.txt                ← Usage instructions
├── registry_import.reg       ← Registry settings (auto-imported on first run)
├── app/                      ← Application files
│   ├── MyApp.exe
│   ├── MyApp.dll
│   └── ...
├── data/                     ← User data (created on first run, stays portable)
│   ├── AppData/
│   └── ...
└── _portablizer/
    ├── launcher.bat          ← Batch launcher with env redirects
    ├── launcher.ps1          ← PowerShell launcher
    ├── launcher_config.json  ← App metadata
    ├── first_run.ps1         ← One-time setup (registry, shortcuts)
    └── conversion_report.md  ← Detailed conversion report (if --report)
```

---

## CLI Reference

```
usage: portablizer [-h] [--output OUTPUT] [--method {auto,extract,sandbox}]
                   [--silent] [--keep-temp] [--patch-manifest]
                   [--no-patch-manifest] [--install-args INSTALL_ARGS]
                   [--verbose] [--report]
                   input

positional arguments:
  input                 Path to the .exe installer

options:
  --output, -o          Output directory (default: <input>_portable/)
  --method, -m          auto | extract | sandbox  (default: auto)
  --silent, -s          Run installer silently (sandbox mode)
  --keep-temp           Keep temp files for debugging
  --patch-manifest      Patch UAC manifest in output .exe files (default: on)
  --no-patch-manifest   Skip UAC manifest patching
  --install-args        Extra args to pass to the installer
  --verbose, -v         Verbose logging
  --report              Generate a Markdown conversion report
```

---

## Supported Installer Formats

| Format | Detection | Extraction | Notes |
|---|---|---|---|
| Inno Setup | ✅ High confidence | ✅ via innounp/innoextract | Most common format |
| NSIS | ✅ High confidence | ✅ via 7-Zip | Nullsoft, used by many apps |
| MSI | ✅ High confidence | ✅ via lessmsi | Microsoft Installer |
| 7-Zip SFX | ✅ | ✅ via 7-Zip | |
| WinRAR SFX | ✅ | ✅ via 7-Zip | |
| ZIP SFX | ✅ | ✅ Python built-in | |
| InstallShield | ✅ | ⚠️ Partial (7-Zip fallback) | Complex formats may fail |
| Squirrel | ✅ | ✅ 7-Zip + NuGet | Electron apps |
| Advanced Installer | ✅ | ⚠️ Partial | |
| Wise Installer | ✅ | ⚠️ Partial | |
| Unknown/Custom | ✅ Low confidence | ✅ sandbox mode | |

---

## Known Limitations

Some features **cannot** be made portable without admin:

- **Kernel drivers** (`.sys` files) — require `NtLoadDriver` which always needs admin
- **Windows services** — `CreateService` and `StartService` require admin; Portablizer detects these and warns you
- **COM server registration** to HKLM — redirected to HKCU where possible
- **Global file associations** — registry writes to `HKLM\SOFTWARE\Classes` are redirected to HKCU
- **Auto-update components** — many update mechanisms require writing to Program Files; Portablizer flags these

Portablizer will always tell you about detected limitations in the output.

---

## Building the Sandbox Shim (Advanced)

The sandbox mode requires compiling a C++ DLL. Requirements:
- Visual Studio 2019 or 2022
- vcpkg with `detours` and `nlohmann-json`

```bash
# Install dependencies via vcpkg
vcpkg install detours nlohmann-json

# Build
cd launcher/cpp
cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg_root>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release

# Copy to tools/bin/
copy build\Release\portablizer_shim.dll ..\..\tools\bin\
```

Without the shim DLL, sandbox mode falls back to filesystem snapshot diffing (less comprehensive but no compilation required).

---

## Architecture

```
main.py / gui.py
      │
      ▼
core/pipeline.py          Orchestrates all stages
      │
      ├── extractor/detector.py     Identify installer format (binary signatures)
      ├── extractor/extractor.py    Static extraction (innounp, 7z, lessmsi, ...)
      │
      ├── sandbox/runner.py         Runtime capture (Detours DLL injection)
      ├── sandbox/differ.py         Filesystem + registry snapshot diff
      │
      ├── patcher/manifest.py       UAC manifest patching (binary in-place)
      ├── patcher/registry.py       HKLM → HKCU registry redirect
      │
      └── packager/packager.py      Output assembly + launcher generation
          packager/reporter.py      Markdown conversion report

launcher/cpp/
  portablizer_shim.cpp    Win32 API hooking DLL (Detours-based)
  CMakeLists.txt

tools/
  bin/                    External tool binaries (innounp, 7z, lessmsi, ...)
  download_tools.py       Tool downloader
```

---

## Requirements

- Python 3.9+
- Windows 7/8/10/11 (for full functionality)
- Linux/macOS: `extract` mode works; `sandbox` mode requires Windows

```
pip install -r requirements.txt
```

---

## License

MIT License. See LICENSE file.

Built with: Microsoft Detours, nlohmann/json, 7-Zip SDK, innounp, lessmsi.
