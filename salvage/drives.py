"""Enumerate the system's drives for the drive-selector dropdown."""
from __future__ import annotations

import ctypes
import os
import shutil
import string


def _fs_type(vol: str) -> str:
    """Filesystem name (NTFS/FAT32/exFAT/…) for a mounted volume, via the Win32 API."""
    try:
        name = ctypes.create_unicode_buffer(32)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(vol), None, 0, None, None, None,
            ctypes.byref(name), 32)
        return name.value if ok else ""
    except Exception:
        return ""


def list_drives() -> list[dict]:
    drives = []
    # Mounted volumes (lettered drives) — listing needs no admin.
    for letter in string.ascii_uppercase:
        vol = f"{letter}:\\"
        if not os.path.exists(vol):
            continue
        try:
            total, _used, free = shutil.disk_usage(vol)
        except OSError:
            continue
        drives.append({
            "id": f"vol-{letter.lower()}",
            "label": f"{letter}:",
            "fs": _fs_type(vol),
            "path": f"\\\\.\\{letter}:",   # raw volume device (open needs admin)
            "kind": "volume",
            "total": total,
            "free": free,
        })
    # Physical disks — raw open needs admin, so list them best-effort.
    for n in range(16):
        dev = f"\\\\.\\PhysicalDrive{n}"
        try:
            h = os.open(dev, os.O_RDONLY)
            os.close(h)
        except OSError:
            continue
        drives.append({
            "id": f"disk-{n}",
            "label": f"Disk {n}",
            "path": dev,
            "kind": "disk",
            "total": 0,
            "free": 0,
        })
    return drives
