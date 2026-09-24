"""exFAT free-space detection for deleted-only carving.

The exFAT filesystem keeps a $ALLOC_BITMAP file: one bit per cluster, 1 = live
(allocated), 0 = free (unallocated). Deleted files' data lives in FREE clusters,
so carving only the free ranges recovers deleted data while skipping every file
still on the drive. Returns byte ranges (start, end) for the unallocated space.
"""
from __future__ import annotations

import pytsk3

_EXFAT_TYPE = getattr(pytsk3, "TSK_FS_TYPE_EXFAT", 10)


def free_ranges(img, fs_offset: int = 0) -> list[tuple[int, int]] | None:
    """Return (start, end) byte ranges of unallocated clusters on an exFAT volume,
    or None if the source is not exFAT (caller should fall back to a full carve)."""
    try:
        fs = pytsk3.FS_Info(img, offset=fs_offset)
    except Exception:
        return None
    if getattr(fs.info, "ftype", None) != _EXFAT_TYPE:
        return None

    boot = img.read(fs_offset, 512)
    if len(boot) < 512 or boot[3:11] != b"EXFAT   ":
        return None
    bps = 1 << boot[108]                     # bytes per sector
    spc = 1 << boot[109]                     # sectors per cluster
    cluster_size = bps * spc
    heap_off = fs_offset + int.from_bytes(boot[88:92], "little") * bps
    cluster_count = int.from_bytes(boot[92:96], "little")

    # find the $ALLOC_BITMAP file in the root directory
    bm_addr = None
    try:
        for entry in fs.open_dir("/"):
            n = entry.info.name.name
            if isinstance(n, bytes):
                n = n.decode("utf-8", "replace")
            if n == "$ALLOC_BITMAP":
                bm_addr = entry.info.meta.addr
                break
    except Exception:
        return None
    if bm_addr is None:
        return None

    try:
        f = fs.open_meta(bm_addr)
        bm = f.read_random(0, f.info.meta.size)
    except Exception:
        return None

    # Build contiguous free runs. Fast path: whole bytes all-free (0x00) or
    # all-allocated (0xFF); expand only the rare mixed bytes.
    ranges: list[tuple[int, int]] = []
    run_start: int | None = None

    def close_run(end_cluster: int) -> None:
        nonlocal run_start
        if run_start is not None:
            ranges.append((heap_off + run_start * cluster_size,
                           heap_off + end_cluster * cluster_size))
            run_start = None

    for bi, byte in enumerate(bm):
        if byte == 0x00:
            if run_start is None:
                run_start = bi * 8
            continue
        if byte == 0xFF:
            close_run(bi * 8)
            continue
        for k in range(8):
            ci = bi * 8 + k
            if ci >= cluster_count:
                break
            if (byte >> k) & 1:
                close_run(ci)
            elif run_start is None:
                run_start = ci
    close_run(cluster_count)
    return ranges
