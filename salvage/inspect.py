"""Read-only file inspection: identify a file's true type and peek at its bytes
without ever executing it. Used by the dashboard's "inspect" panel so recovered
files can be checked safely from inside the app."""
from __future__ import annotations

import os
import re

# magic bytes -> human-readable type. Order matters: longest/specific first.
_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\x42\x4d", "BMP image"),
    (b"%PDF", "PDF document"),
    (b"\x50\x4b\x03\x04", "ZIP archive (docx/xlsx/pptx/jar/apk)"),
    (b"\x50\x4b\x05\x06", "ZIP (empty archive)"),
    (b"\x50\x4b\x07\x08", "ZIP (spanned archive)"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"ID3", "MP3 audio"),
    (b"\xff\xfb", "MP3 audio (no ID3)"),
    (b"fLaC", "FLAC audio"),
    (b"OggS", "OGG audio/video"),
    (b"RIFF", "RIFF container (WAV / AVI / WebP)"),
    (b"\x1a\x45\xdf\xa3", "Matroska / WebM video"),
    (b"\x00\x00\x00\x18ftyp", "MP4 / MOV video"),
    (b"\x00\x00\x00\x20ftyp", "MP4 / MOV video"),
    (b"ftyp", "MP4 / MOV video"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Office OLE2 (doc/xls/ppt/msi)"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\x1f\x8b", "gzip compressed"),
    (b"BZh", "bzip2 compressed"),
    (b"\xfd7zXZ\x00", "xz compressed"),
    (b"MZ", "Windows executable (.exe/.dll) — DO NOT RUN"),
    (b"\x7fELF", "ELF executable — DO NOT RUN"),
    # Recovered-data assessment: signatures observed on this machine's deleted files.
    (b"\xdc\x05\x83\x40", "Chrome BrowserMetrics (UMA telemetry)"),
    (b"CMMM", "Chrome metrics record (binary)"),
    (b"H0IMMM", "Chrome metrics record (binary)"),
    (b"\x00\xac\xac\x00", "Windows Start Menu cache (shortcut list)"),
    (b"\x17\xef\xc8\xca", "compressed or encrypted data"),
)


def sniff(head: bytes) -> str:
    for magic, label in _SIGNATURES:
        if head.startswith(magic):
            return label
    return "unknown / raw data"


def _extract_strings(data: bytes, min_len: int = 6, limit: int = 60) -> list[str]:
    return [s.decode("latin1") for s in re.findall(rb"[ -~]{%d,}" % min_len, data)[:limit]]


def inspect(path: str, head_bytes: int = 256, string_limit: int = 60) -> dict:
    """Return size, detected type, hex + ascii of the header, and readable strings."""
    size = os.path.getsize(path)
    head = b""
    with open(path, "rb") as fh:
        head = fh.read(head_bytes)
    sample = head
    # Pull strings from a wider window (first 64 KB) so small text shows up.
    if size > head_bytes:
        with open(path, "rb") as fh:
            sample = fh.read(65536)
    return {
        "path": path,
        "size": size,
        "type": sniff(head),
        "hex": head.hex(" ").upper(),
        "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in head),
        "strings": _extract_strings(sample, limit=string_limit),
        "warning": "Recovered data is untrusted — identify before opening, never execute.",
    }
