"""
tools/download_tools.py

Downloads free open-source tools that Portablizer uses.
Run from the project root: python tools/download_tools.py

Downloads:
  - lessmsi    (MSI extractor)
  - innoextract (Inno Setup extractor)
  - 7-Zip      (universal extractor, Windows x64)
"""

import os
import sys
import hashlib
import zipfile
import urllib.request
import urllib.error
from pathlib import Path

BIN_DIR = Path(__file__).parent / "bin"
BIN_DIR.mkdir(exist_ok=True)

TOOLS = [
    {
        "name": "lessmsi.exe",
        "url": "https://github.com/activescott/lessmsi/releases/latest/download/lessmsi.zip",
        "extract": "lessmsi.exe",
        "desc": "MSI extractor",
    },
    {
        "name": "innoextract.exe",
        "url": "https://constexpr.org/innoextract/files/innoextract-1.9-windows.zip",
        "extract": "innoextract.exe",
        "desc": "Inno Setup extractor",
    },
]


def download(url: str, dest: Path, desc: str):
    print(f"  Downloading {desc}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "portablizer/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            dest.write_bytes(resp.read())
        print(f"  Saved: {dest.name} ({dest.stat().st_size // 1024} KB)")
        return True
    except urllib.error.URLError as e:
        print(f"  FAILED: {e}")
        return False


def extract_from_zip(zip_path: Path, member: str, dest: Path):
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        match = next((n for n in names if n.endswith(member)), None)
        if not match:
            print(f"  WARNING: {member} not found in zip (available: {names[:5]})")
            return False
        data = zf.read(match)
        dest.write_bytes(data)
        print(f"  Extracted: {dest.name}")
        return True


def main():
    print("Portablizer Tool Downloader")
    print(f"Installing to: {BIN_DIR}\n")

    for tool in TOOLS:
        target = BIN_DIR / tool["name"]
        if target.exists():
            print(f"  [skip] {tool['name']} already exists")
            continue

        tmp_zip = BIN_DIR / "_download_tmp.zip"
        url = tool["url"]

        if url.endswith(".zip"):
            if download(url, tmp_zip, tool["desc"]):
                extract_from_zip(tmp_zip, tool["extract"], target)
                tmp_zip.unlink(missing_ok=True)
        else:
            download(url, target, tool["desc"])

    # 7-Zip: point to system install if available
    import shutil
    sz = shutil.which("7z")
    if sz:
        print(f"\n  [ok] 7-Zip found in PATH: {sz}")
    else:
        for candidate in [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ]:
            if Path(candidate).exists():
                print(f"\n  [ok] 7-Zip found: {candidate}")
                break
        else:
            print("\n  [info] 7-Zip not found. Download from https://www.7-zip.org/")
            print("         After installing, 7z.exe will be detected automatically.")

    print("\nDone. Run portablizer --help to get started.")


if __name__ == "__main__":
    main()
