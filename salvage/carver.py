"""Signature-based file carving — the core of deleted-file recovery.

When a file is deleted, its bytes remain on the platter/flash until overwritten
(or TRIMmed on an SSD). The bytes still carry a recognizable magic header.
Carving = scan the raw image, find every header, extract the file — and, this is
the part that separates a good carver from a spam generator, VALIDATE THE
STRUCTURE before writing anything.

Naive "find a magic byte, grab 64 MB" carving is why a music library turns into
57 GB of unplayable 64 MB slabs and a photo folder into 160x120 EXIF thumbnails.
Every extractor here therefore parses the format's real structure to find the
TRUE end of the file:

  * JPEG  — walk the marker/segment chain (SOI -> SOF -> SOS -> scan -> EOI),
            skipping the embedded EXIF thumbnail, and sanity-check dimensions.
  * MP3   — skip the ID3v2 tag, then walk MPEG audio frames (bitrate/sample-rate
            tables) until the frame stream breaks.
  * MIDI  — walk MThd + MTrk chunks to the real end.
  * WAV   — honor the RIFF size field and require the "WAVE" form type.
  * PNG/PDF/ZIP — bounded by their end markers (IEND / %%EOF / EOCD).

Works on a disk IMAGE FILE (.dd/.img) or, elevated, a RAW VOLUME (\\\\.\\X:),
using random-access reads so we never load the whole disk into memory.
"""
from __future__ import annotations

import os
import time
from pathlib import Path


class _Stalled(Exception):
    """Raised when a scan runs past its deadline — cleanly aborts the worker."""


MAX_CHUNK = 64 * 1024 * 1024   # safety cap: no recovered file exceeds this
_CHUNK = 64 * 1024 * 1024      # streaming scan granularity (bigger = fewer syscalls)
_MP3_SYNC_FRAMES = 6           # consecutive valid frames required to trust a raw MPEG sync
_MP3_LOOKAHEAD = 24 * 1024     # carry bytes so that frame validation survives chunk boundaries


class _Reader:
    r"""Uniform random-access reader over a regular file OR a raw \\.\ device."""

    def __init__(self, path: str, deadline: float | None = None):
        self._path = path
        self.deadline = deadline
        self.is_device = path.startswith("\\\\.\\")
        if self.is_device:
            import pytsk3
            self._img = pytsk3.Img_Info(path)
            self.size = self._img.get_size()
        else:
            self._fh = open(path, "rb")
            self.size = os.path.getsize(path)

    def read(self, off: int, n: int) -> bytes:
        if self.deadline is not None and time.time() > self.deadline:
            raise _Stalled("scan exceeded its time limit")
        if self.is_device:
            # Retry transient USB/device read errors so a hiccup doesn't truncate the scan.
            for _ in range(3):
                try:
                    return self._img.read(off, n) or b""
                except Exception:
                    time.sleep(0.05)
            return b""
        self._fh.seek(off)
        return self._fh.read(n)

    def close(self) -> None:
        if not self.is_device:
            self._fh.close()


class _MemReader:
    """A _Reader-shaped wrapper over an in-memory buffer (used by tests + carve())."""

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def read(self, off: int, n: int) -> bytes:
        return self.data[off:off + n]


# --------------------------------------------------------------------------
# format extractors: each returns (blob, end_offset) or None on rejection
# --------------------------------------------------------------------------

def _extract_footer(rd, off: int, header: bytes, footer: bytes):
    """Bounded extraction for formats with an end marker (PNG/PDF/ZIP)."""
    size = rd.size
    pos = off + len(header)
    limit = min(off + MAX_CHUNK, size)
    while pos < limit:
        block = rd.read(pos, min(1024 * 1024, limit - pos))
        if not block:
            break
        j = block.find(footer)
        if j >= 0:
            end = pos + j + len(footer)
            return rd.read(off, end - off), end
        pos += len(block)
    return None


def _extract_jpeg(rd, off: int):
    """Walk a JPEG's segment chain to its true EOI. Skips the EXIF thumbnail
    (which lives inside an APP1 segment) and rejects impossible dimensions."""
    size = rd.size
    if off + 2 > size or rd.read(off, 2) != b"\xff\xd8":
        return None
    i = off + 2
    saw_sof = False
    while i + 4 <= size:
        if i - off > MAX_CHUNK:
            return None
        b = rd.read(i, 4)
        if len(b) < 4 or b[0] != 0xFF:
            return None
        marker = b[1]
        if marker == 0xD9:                      # EOI — end of image
            if not saw_sof:
                return None
            end = i + 2
            return rd.read(off, end - off), end
        if marker == 0xDA:                      # SOS — entropy-coded data follows
            if not saw_sof:
                return None
            seglen = (b[2] << 8) | b[3]
            if seglen < 2:
                return None
            j = i + 2 + seglen
            carry = b""
            while j < size and j - off < MAX_CHUNK:
                block = rd.read(j, min(65536, size - j))
                if not block:
                    return None
                window = carry + block
                k = window.find(b"\xff\xd9")     # FF D9 in scan data == true EOI
                if k >= 0:
                    end = j - len(carry) + k + 2
                    return rd.read(off, end - off), end
                carry = window[-1:]
                j += len(block)
            return None
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:   # standalone, no length
            i += 2
            continue
        if marker in (0x00, 0xFF):
            return None
        seglen = (b[2] << 8) | b[3]
        if seglen < 2:
            return None
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            # SOF — record + sanity-check the real image dimensions.
            sof = rd.read(i, 9)
            if len(sof) < 9:
                return None
            h = (sof[5] << 8) | sof[6]
            w = (sof[7] << 8) | sof[8]
            if w <= 0 or h <= 0 or w > 50000 or h > 50000 or w * h > 300_000_000:
                return None
            saw_sof = True
        i += 2 + seglen
    return None


# MPEG audio frame tables (kbps). Index by header bitrate/sample-rate fields.
_L1_BITRATES = [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448]
_L2_V1_BITRATES = [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384]
_L2_V2_BITRATES = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]
_L3_V1_BITRATES = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]
_L3_V2_BITRATES = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]


def _mp3_frame_info(h: bytes):
    """Parse one MPEG audio frame header -> (version, layer, srate_idx, frame_len)
    or None if it is not a valid frame header."""
    if len(h) < 4 or h[0] != 0xFF or (h[1] & 0xE0) != 0xE0:
        return None
    version = (h[1] >> 3) & 0x03   # 0=2.5, 2=2, 3=1, 1=reserved
    layer = (h[1] >> 1) & 0x03     # 1=III, 2=II, 3=I, 0=reserved
    br_idx = (h[2] >> 4) & 0x0F
    sr_idx = (h[2] >> 2) & 0x03
    pad = (h[2] >> 1) & 0x01
    if version == 1 or layer == 0 or br_idx in (0, 15) or sr_idx == 3:
        return None
    srate = [[11025, 12000, 8000], [0, 0, 0], [22050, 24000, 16000], [44100, 48000, 32000]][version][sr_idx]
    if layer == 3:                                  # Layer I
        bitrate = _L1_BITRATES[br_idx]
        flen = (12 * bitrate * 1000 // srate + pad) * 4
    elif layer == 1:                                # Layer III
        bitrate = (_L3_V1_BITRATES if version == 3 else _L3_V2_BITRATES)[br_idx]
        flen = (144 if version == 3 else 72) * bitrate * 1000 // srate + pad
    else:                                           # Layer II
        bitrate = (_L2_V1_BITRATES if version == 3 else _L2_V2_BITRATES)[br_idx]
        flen = 144 * bitrate * 1000 // srate + pad
    return version, layer, sr_idx, flen


def _mp3_frame_len(h: bytes):
    """Length in bytes of one MPEG audio frame given its 4-byte header, or None."""
    info = _mp3_frame_info(h)
    return info[3] if info else None


def _scan_mp3_sync(window: bytes, base: int):
    """Find raw MPEG frame-sync starts (MP3s WITHOUT an ID3 tag) by validating a
    run of consecutive frames with consistent version/layer/sample-rate. Bitrate
    may vary (VBR). This rejects the flood of stray 0xFF E0+ bytes in random data."""
    offs = []
    L = len(window)
    i = 0
    while True:
        i = window.find(b"\xff", i)
        if i < 0 or i + 4 > L:
            break
        if (window[i + 1] & 0xE0) == 0xE0:
            info = _mp3_frame_info(window[i:i + 4])
            if info:
                version, layer, sr_idx, flen = info
                p = i
                ok = True
                for _ in range(_MP3_SYNC_FRAMES - 1):
                    p += flen
                    if p + 4 > L:
                        ok = False          # straddles chunk boundary — carry re-examines
                        break
                    nxt = _mp3_frame_info(window[p:p + 4])
                    if not nxt or nxt[0] != version or nxt[1] != layer or nxt[2] != sr_idx:
                        ok = False
                        break
                    flen = nxt[3]
                if ok:
                    offs.append(base + i)
                    i = p + flen            # skip past the validated run
                    continue
        i += 1
    return offs


def _extract_mp3(rd, off: int):
    """Skip the ID3v2 tag, then walk MPEG frames to the true end of the song."""
    size = rd.size
    pos = off
    if off + 10 <= size:
        t = rd.read(off, 10)
        if len(t) >= 10 and t[:3] == b"ID3":
            ver = t[3]
            if ver in (3, 4):                       # sync-safe 4-byte size
                tsz = ((t[6] & 0x7F) << 21) | ((t[7] & 0x7F) << 14) | ((t[8] & 0x7F) << 7) | (t[9] & 0x7F)
                pos = off + 10 + tsz + (10 if t[5] & 0x10 else 0)
            elif ver == 2:                          # 3-byte big-endian size
                tsz = (t[6] << 16) | (t[7] << 8) | t[8]
                pos = off + 6 + tsz
            else:
                return None
            if tsz < 0 or tsz > MAX_CHUNK:
                return None
    frames = 0
    p = pos
    while p + 4 <= size and p - off < MAX_CHUNK:
        fh = rd.read(p, 4)
        if len(fh) < 4:
            break
        flen = _mp3_frame_len(fh)
        if not flen or flen <= 0:
            break
        frames += 1
        p += flen
    if frames < 2:
        return None
    return rd.read(off, p - off), p


def _extract_midi(rd, off: int):
    """Walk MThd + MTrk chunks to the real end of a MIDI file."""
    size = rd.size
    if off + 14 > size:
        return None
    hdr = rd.read(off, 14)
    if len(hdr) < 14 or hdr[:4] != b"MThd":
        return None
    hlen = int.from_bytes(hdr[4:8], "big")
    if hlen < 6:
        return None
    ntrks = int.from_bytes(hdr[10:12], "big")
    if ntrks <= 0 or ntrks > 100000:
        return None
    pos = off + 8 + hlen
    tracks = 0
    while tracks < ntrks and pos + 8 <= size and pos - off < MAX_CHUNK:
        th = rd.read(pos, 8)
        if len(th) < 8:
            break
        if th[:4] != b"MTrk":
            break
        tlen = int.from_bytes(th[4:8], "big")
        if tlen < 0:
            break
        pos += 8 + tlen
        tracks += 1
    if tracks != ntrks:
        return None
    return rd.read(off, pos - off), pos


def _extract_wav(rd, off: int):
    """Honor the RIFF size field and require the WAVE form type."""
    size = rd.size
    if off + 12 > size:
        return None
    hdr = rd.read(off, 12)
    if len(hdr) < 12 or hdr[:4] != b"RIFF" or hdr[8:12] != b"WAVE":
        return None
    sz = int.from_bytes(hdr[4:8], "little")
    if sz < 4 or sz > MAX_CHUNK:
        return None
    end = min(off + 8 + sz, size)
    return rd.read(off, end - off), end


def _extract_png(rd, off: int):
    return _extract_footer(rd, off, b"\x89PNG\r\n\x1a\n", b"\x49\x45\x4e\x44\xae\x42\x60\x82")


def _extract_pdf(rd, off: int):
    return _extract_footer(rd, off, b"%PDF", b"%%EOF")


def _extract_zip(rd, off: int):
    """Recover a ZIP through its End-Of-Central-Directory record.

    The EOCD is a 22-byte record (plus a variable-length comment), NOT just the
    4-byte PK\\x05\\x06 signature. Truncating at the signature left the archive
    missing its central-directory offset and made it unreadable. We parse the
    full EOCD (including the comment) and VALIDATE that its central-directory
    offset really points at a PK\\x01\\x02 marker, so a stray PK\\x05\\x06 inside
    entry data can't fool us."""
    size = rd.size
    limit = min(off + MAX_CHUNK, size)
    pos = off + 4
    while pos < limit:
        block = rd.read(pos, min(1024 * 1024, limit - pos))
        if not block:
            break
        j = block.find(b"PK\x05\x06")
        while j >= 0:
            eocd = pos + j
            rec = rd.read(eocd, 22)
            if len(rec) == 22:
                comment_len = int.from_bytes(rec[20:22], "little")
                end = min(eocd + 22 + comment_len, size)
                cd_off = int.from_bytes(rec[16:20], "little")
                abs_cd = off + cd_off
                if off <= abs_cd < end and rd.read(abs_cd, 4) == b"PK\x01\x02":
                    return rd.read(off, end - off), end
            j = block.find(b"PK\x05\x06", j + 1)   # false match — try the next
        pos += len(block)
    return None


# label / header(s) / extension / structural extractor
SIGNATURES = [
    {"label": "JPEG", "headers": [b"\xff\xd8\xff"], "ext": ".jpg", "extract": _extract_jpeg},
    {"label": "PNG",  "headers": [b"\x89PNG\r\n\x1a\n"], "ext": ".png", "extract": _extract_png},
    {"label": "PDF",  "headers": [b"%PDF"], "ext": ".pdf", "extract": _extract_pdf},
    {"label": "ZIP",  "headers": [b"PK\x03\x04"], "ext": ".zip", "extract": _extract_zip},
    {"label": "MP3",  "headers": [b"ID3"], "ext": ".mp3", "extract": _extract_mp3, "scan": _scan_mp3_sync},
    {"label": "MIDI", "headers": [b"MThd"], "ext": ".mid", "extract": _extract_midi},
    {"label": "WAV",  "headers": [b"RIFF"], "ext": ".wav", "extract": _extract_wav},
]


def _iter_headers(rd, chunk: int = _CHUNK, progress=None, cancel=None, signatures=None, ranges=None,
                  deadline=None):
    """Yield (offset, signature-index) pairs in scan order, streaming with
    read-ahead double-buffering (a producer thread reads the NEXT chunk on its
    own handle while this thread scans the current one).

    ``ranges`` (optional) is a list of (start, end) byte ranges to scan instead
    of the whole source — used to carve only free space on exFAT.
    ``progress`` is called as progress(bytes_scanned, total_bytes) once per chunk.
    ``cancel`` is a zero-arg callable; return True to stop early."""
    sigs = SIGNATURES if signatures is None else signatures
    max_hdr = max(len(h) for sig in sigs for h in sig["headers"])
    max_keep = max(max_hdr, _MP3_LOOKAHEAD)
    seen: set[int] = set()
    if ranges is None:
        ranges = [(0, rd.size)]
    total = sum(e - s for s, e in ranges)

    import queue
    import threading

    prefetch = queue.Queue(maxsize=1)
    stop = threading.Event()
    reader2 = _Reader(rd._path, deadline)  # separate handle so no two threads touch one device

    def produce() -> None:
        try:
            for rs, re in ranges:
                p = rs
                while p < re and not stop.is_set():
                    b = reader2.read(p, min(chunk, re - p))
                    if not b:
                        break
                    prefetch.put((p, b))
                    p += len(b)
        except _Stalled:
            pass  # deadline hit — fall through and deliver the sentinel
        finally:
            reader2.close()
            if not stop.is_set():
                try:
                    prefetch.put(None)  # sentinel: no more chunks
                except Exception:
                    pass

    threading.Thread(target=produce, daemon=True).start()

    pos = 0
    carry = b""
    carry_start = 0
    expected = ranges[0][0] if ranges else 0

    try:
        while True:
            item = prefetch.get()
            if item is None:
                break
            if cancel is not None and cancel():
                break
            if deadline is not None and time.time() > deadline:
                break
            off, buf = item
            if off != expected:
                # seeked into a new range: the bytes aren't contiguous, drop carry
                carry = b""
                carry_start = off
            expected = off + len(buf)
            window = carry + buf
            hits: list[tuple[int, int]] = []
            for si, sig in enumerate(sigs):
                for header in sig["headers"]:
                    start = 0
                    while True:
                        i = window.find(header, start)
                        if i < 0:
                            break
                        hits.append((carry_start + i, si))
                        start = i + 1
                scan = sig.get("scan")
                if scan is not None:
                    for i in scan(window, carry_start):
                        hits.append((i, si))
            keep = min(len(window), max_keep)
            carry = window[-keep:]
            carry_start += len(window) - keep
            pos += len(buf)
            if progress is not None:
                progress(pos, total)  # bytes_scanned, total_bytes
            for off_h, si in sorted(hits):
                if off_h not in seen:
                    seen.add(off_h)
                    yield off_h, si
    finally:
        stop.set()
        try:
            while True:
                prefetch.get_nowait()
        except Exception:
            pass


def _find_headers(rd, chunk: int = _CHUNK, progress=None, signatures=None, ranges=None):
    """Back-compat: return all (offset, signature-index) pairs as a sorted list."""
    return list(_iter_headers(rd, chunk, progress=progress, signatures=signatures, ranges=ranges))


def carve_file(image_path: str, out_dir: str, min_size: int = 64, progress=None,
               cancel=None, signatures=None, ranges=None, deadline=None) -> list[dict]:
    """Carve one source (disk image file OR raw \\\\.\\ device) into out_dir.
    ``progress`` (optional) is called as progress(bytes_scanned, total, found_count)
    — bytes advance during the scan and ``found_count`` climbs live as files land.
    ``cancel`` (optional) is a zero-arg callable; True stops the carve early.
    ``signatures`` (optional) restricts which signatures to hunt (targeted carve).
    ``ranges`` (optional) is a list of (start, end) byte ranges to carve only
    those regions (e.g. free space on exFAT for a deleted-only carve)."""
    sigs = SIGNATURES if signatures is None else signatures
    rd = _Reader(image_path, deadline)
    try:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        found: list[dict] = []
        extracted: list[tuple[int, int]] = []   # skip nested hits (EXIF thumbnails)

        def on_scan(scanned: int, total: int) -> None:
            if progress is not None:
                progress(scanned, total, len(found))

        n = 0
        for off, si in _iter_headers(rd, progress=on_scan, cancel=cancel, signatures=sigs, ranges=ranges,
                                     deadline=deadline):
            if cancel is not None and cancel():
                break
            if any(s <= off < e for s, e in extracted):
                continue
            sig = sigs[si]
            result = sig["extract"](rd, off)
            if result is None:
                continue
            blob, end = result
            if len(blob) >= min_size:
                name = f"{sig['label'].lower()}-{n:05d}{sig['ext']}"
                (out / name).write_bytes(blob)
                found.append({"file": name, "type": sig["label"], "size": len(blob),
                              "offset": off, "saved": str(out / name)})
                extracted.append((off, end))
                n += 1
        return found
    finally:
        rd.close()


def carve(data: bytes, min_size: int = 64):
    """In-memory carve (tests / small buffers). Yields (offset, label, ext, blob)."""
    rd = _MemReader(data)
    candidates: dict[int, int] = {}
    for si, sig in enumerate(SIGNATURES):
        for header in sig["headers"]:
            start = 0
            while True:
                i = data.find(header, start)
                if i < 0:
                    break
                candidates[i] = si
                start = i + 1
        scan = sig.get("scan")
        if scan is not None:
            for i in scan(data, 0):
                candidates[i] = si
    extracted: list[tuple[int, int]] = []
    for off in sorted(candidates):
        if any(s <= off < e for s, e in extracted):
            continue
        sig = SIGNATURES[candidates[off]]
        result = sig["extract"](rd, off)
        if result is None:
            continue
        blob, end = result
        if len(blob) >= min_size:
            extracted.append((off, end))
            yield off, sig["label"], sig["ext"], blob
