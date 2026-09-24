"""NTFS deleted-file recovery via pytsk3 (The Sleuth Kit bindings).

A deleted file shows up in one of two places:
  1. Still listed in its own directory with ``name.flags & UNALLOC`` (the delete
     freed the MFT record but the name entry hasn't been swept yet), or
  2. As an orphan in the virtual ``/$Extend/$Deleted`` directory (fully-deleted,
     original name lost, exposed under a hex MFT-address name).

Recovery runs in two phases: a FAST sweep of ``/$Extend/$Deleted`` (seconds, the
common fully-flushed case), then an optional DEEP whole-tree walk for deleted
files still listed in their own folders (slow, reports progress). Both open each
entry by its raw MFT address (``fs.open_meta``).  Requires: pip install pytsk3.
"""
from __future__ import annotations

import os
import time

import pytsk3

_META_DIR = getattr(pytsk3, "TSK_FS_META_TYPE_DIR", 2)
_NAME_UNALLOC = getattr(pytsk3, "TSK_FS_NAME_FLAG_UNALLOC", 2)


class _Cancelled(Exception):
    """Raised to unwind a recovery walk when the user cancels mid-scan."""

# Content-signature sniffing so recovered (hex-named) files get a usable
# extension instead of being an unopenable blob.
_SIGNATURES = (
    (b"\xff\xd8\xff", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"%PDF", ".pdf"),
    (b"PK\x03\x04", ".zip"),
    (b"PK\x05\x06", ".zip"),
    (b"ID3", ".mp3"),
    (b"\xff\xfb", ".mp3"),
    (b"OggS", ".ogg"),
    (b"RIFF", ".wav"),
    (b"\x00\x00\x00\x18ftyp", ".mp4"),
    (b"ftyp", ".mp4"),
    (b"\xd0\xcf\x11\xe0", ".doc"),
    (b"MZ", ".exe"),
)


def _sniff_ext(f) -> str:
    try:
        head = f.read_random(0, 16)
    except Exception:
        head = b""
    for magic, ext in _SIGNATURES:
        if head.startswith(magic):
            return ext
    return ".bin"


def open_image(path: str):
    return pytsk3.Img_Info(path)


def recover_deleted(img, out_dir: str, fs_offset: int = 0, max_depth: int = 24,
                    deep: bool = False, progress=None, recover_progress=None,
                    types=None, cancel=None, deadline=None) -> list[dict]:
    """Recover deleted files to out_dir.

    quick (deep=False): a fast sweep of /$Extend/$Deleted only (seconds).

    deep (full/targeted): two passes. First ENUMERATE every recoverable deleted
    file (orphan dir + whole tree) and sum its byte size WITHOUT copying content —
    that yields a real byte total. Then RECOVER, reporting bytes_done/total so the
    caller can compute an accurate rate + time-remaining (the same accounting the
    carve path uses). ``progress(dirs, found)`` fires during the enumeration walk;
    ``recover_progress(bytes_done, total, found)`` fires during the byte copy.
    ``types`` (optional) is a set of extensions to keep — e.g. {'.png', '.jpg'}.
    ``cancel`` (optional) is a zero-arg callable; True aborts the recovery."""
    os.makedirs(out_dir, exist_ok=True)
    fs = pytsk3.FS_Info(img, offset=fs_offset)
    found: list[dict] = []
    if deadline is not None:
        _outer_cancel = cancel

        def cancel():  # noqa: F811 — wrap the cancel callback with a deadline check
            return (_outer_cancel is not None and _outer_cancel()) or time.time() > deadline

    try:
        if deep:
            plan, total = _enumerate_deleted(fs, max_depth, types, progress, cancel)
            _recover_plan(fs, plan, out_dir, found, total, recover_progress, cancel)
        else:
            _scan_orphans(fs, "/$Extend/$Deleted", out_dir, found, 0, max_depth, types, cancel)
    except _Cancelled:
        pass
    return found


def _scan_orphans(fs, path: str, out_dir: str, found: list, depth: int, max_depth: int, types, cancel=None) -> None:
    """Fast phase: recover everything in the virtual $Extend/$Deleted directory."""
    if depth > max_depth:
        return
    if cancel is not None and cancel():
        raise _Cancelled()
    try:
        d = fs.open_dir(path)
    except Exception:
        return
    for entry in d:
        name = entry.info.name.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        if name in (".", ".."):
            continue
        meta = entry.info.meta
        if meta is not None and meta.type == _META_DIR:
            _scan_orphans(fs, path.rstrip("/") + "/" + name, out_dir, found, depth + 1, max_depth, types, cancel)
        else:
            _recover_entry(fs, entry, name, out_dir, found, types)


def _enumerate_deleted(fs, max_depth: int, types, progress, cancel=None):
    """Pass 1 of a deep scan: find every recoverable deleted file (orphan dir +
    whole tree) and sum its byte size WITHOUT copying any content. Returns
    (plan, total_bytes); each plan item is (meta_addr, name, ext, size)."""
    plan: list = []           # raw (meta_addr, name) candidates
    state = {"dirs": 0}
    _collect_orphans(fs, "/$Extend/$Deleted", plan, 0, max_depth, state, progress, cancel)
    _collect_tree(fs, "/", plan, 0, max_depth, state, progress, cancel)
    kept: list = []
    total = 0
    for meta_addr, name in plan:
        try:
            f = fs.open_meta(meta_addr)
        except Exception:
            continue
        meta = f.info.meta
        size = meta.size or 0
        if size <= 0 or meta.type == _META_DIR:
            continue
        ext = _sniff_ext(f)
        if types is not None and ext not in types:
            continue
        kept.append((meta_addr, name, ext, size))
        total += size
    return kept, total


def _collect_orphans(fs, path: str, plan: list, depth: int, max_depth: int,
                     state: dict, progress, cancel=None) -> None:
    """Enumerate-phase walk of the virtual $Extend/$Deleted directory (no reads)."""
    if depth > max_depth:
        return
    if cancel is not None and cancel():
        raise _Cancelled()
    try:
        d = fs.open_dir(path)
    except Exception:
        return
    for entry in d:
        name = entry.info.name.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        if name in (".", ".."):
            continue
        meta = entry.info.meta
        if meta is not None and meta.type == _META_DIR:
            _collect_orphans(fs, path.rstrip("/") + "/" + name, plan, depth + 1,
                             max_depth, state, progress, cancel)
        else:
            plan.append((entry.info.name.meta_addr, name))


def _collect_tree(fs, path: str, plan: list, depth: int, max_depth: int,
                  state: dict, progress, cancel=None) -> None:
    """Enumerate-phase walk of the whole tree for deleted-in-place files (no reads)."""
    if depth > max_depth or path.startswith("/$Extend/$Deleted"):
        return
    try:
        d = fs.open_dir(path)
    except Exception:
        return
    state["dirs"] += 1
    if state["dirs"] % 200 == 0:
        if cancel is not None and cancel():
            raise _Cancelled()
        if progress is not None:
            progress(state["dirs"], 0)
    for entry in d:
        name = entry.info.name.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        if name in (".", ".."):
            continue
        meta = entry.info.meta
        full = path.rstrip("/") + "/" + name
        if entry.info.name.flags & _NAME_UNALLOC:
            plan.append((entry.info.name.meta_addr, name))
        elif meta is not None and meta.type == _META_DIR:
            _collect_tree(fs, full, plan, depth + 1, max_depth, state, progress, cancel)


def _recover_plan(fs, plan: list, out_dir: str, found: list, total: int,
                  recover_progress, cancel=None) -> None:
    """Pass 2 of a deep scan: copy each enumerated file's bytes, reporting
    bytes_done/total so the caller can gauge rate + time-remaining."""
    done = 0
    for meta_addr, name, ext, size in plan:
        if cancel is not None and cancel():
            raise _Cancelled()
        try:
            f = fs.open_meta(meta_addr)
        except Exception:
            continue
        dest_name = name if "." in name else name + ext
        dest = os.path.join(out_dir, dest_name)
        written = 0
        with open(dest, "wb") as fh:
            off = 0
            while off < size:
                chunk = f.read_random(off, min(1024 * 1024, size - off))
                if not chunk:
                    break
                fh.write(chunk)
                off += len(chunk)
        written = off
        if written > 0:
            found.append({"path": name, "type": ext.lstrip("."), "size": written, "saved": dest})
        done += size
        if recover_progress is not None:
            recover_progress(done, total, len(found))
    if recover_progress is not None and total:
        recover_progress(total, total, len(found))


def _recover_entry(fs, entry, name: str, out_dir: str, found: list, types=None) -> None:
    """Recover one deleted entry by its raw MFT address (works when meta is None)."""
    try:
        f = fs.open_meta(entry.info.name.meta_addr)
    except Exception:
        return
    size = f.info.meta.size or 0
    if size <= 0:
        return
    if f.info.meta.type == _META_DIR:
        return  # deleted directory — its files surface as their own deleted entries
    ext = _sniff_ext(f)
    if types is not None and ext not in types:
        return  # filtered out by a targeted scan
    dest_name = name if "." in name else name + ext  # keep an original name's extension
    dest = os.path.join(out_dir, dest_name)
    written = 0
    with open(dest, "wb") as fh:
        off = 0
        while off < size:
            chunk = f.read_random(off, min(1024 * 1024, size - off))
            if not chunk:
                break
            fh.write(chunk)
            off += len(chunk)
    written = off
    found.append({"path": name, "type": ext.lstrip("."), "size": written, "saved": dest})
