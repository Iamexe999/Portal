# tools/bin/ — Bundled External Tools

Place third-party tool binaries here. Portablizer will use them automatically.

## Required for best results

### innounp.exe  (Inno Setup unpacker)
- Download: https://sourceforge.net/projects/innounp/
- License: Free
- Used for: Extracting Inno Setup installers (better than 7-Zip for this format)

### innoextract.exe  (Cross-platform Inno Setup extractor)
- Download: https://constexpr.org/innoextract/
- License: MIT
- Used for: Alternative Inno Setup extractor

### 7z.exe  (7-Zip command-line)
- Download: https://www.7-zip.org/download.html  (install, then copy 7z.exe + 7z.dll)
- License: LGPL
- Used for: Fallback extraction for NSIS, ZIP, RAR, 7z SFX, and most other formats

### lessmsi.exe  (MSI extractor)
- Download: https://github.com/activescott/lessmsi/releases
- License: MIT
- Used for: Extracting MSI packages without admin (better directory layout than msiexec /a)

## Required for sandbox mode (runtime capture)

### portablizer_shim.dll  (API hooking DLL)
- Build from: launcher/cpp/portablizer_shim.cpp
- Requires: Microsoft Detours + nlohmann/json
- Build instructions:

    # Install vcpkg dependencies
    vcpkg install detours nlohmann-json

    # Build with CMake (Visual Studio 2019/2022 required)
    cd launcher/cpp
    cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg_root>/scripts/buildsystems/vcpkg.cmake
    cmake --build build --config Release
    copy build\Release\portablizer_shim.dll ..\..\tools\bin\

### withdll.exe  (Detours injector launcher)
- Bundled with Microsoft Detours samples:
  https://github.com/microsoft/Detours/tree/main/samples/withdll
- Build: part of Detours sample build process

## Optional

### ResourceHacker.exe  (PE resource editor)
- Download: https://www.angusj.com/resourcehacker/
- License: Freeware
- Used for: Patching UAC manifests (fallback when mt.exe is unavailable)

### mt.exe  (Windows SDK Manifest Tool)
- Already available if you have the Windows 10/11 SDK installed
- Location: C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\mt.exe
- Portablizer detects it automatically from the SDK install location

## Quick setup script

Run this from the project root to download all free tools automatically:

    python tools/download_tools.py

(requires internet access)
