"""Salvage CLI — recover deleted files.

  py run.py --carve IMAGE --out DIR          # carve files by signature
  py run.py --recover IMAGE --out DIR        # recover deleted files via MFT (pytsk3)
  py run.py --serve                          # open the command-center dashboard
"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="salvage", description="Deleted-file recovery")
    p.add_argument("--carve", metavar="IMAGE", help="carve an image by file signatures")
    p.add_argument("--recover", metavar="IMAGE", help="recover deleted files via MFT (pytsk3)")
    p.add_argument("--out", default="recovered", help="output directory (default: recovered)")
    p.add_argument("--offset", type=int, default=0, help="filesystem offset for --recover")
    p.add_argument("--serve", action="store_true", help="run the dashboard")
    args = p.parse_args(argv)

    if args.serve:
        from salvage.server import serve
        serve()
        return 0

    if args.carve:
        from salvage.carver import carve_file
        try:
            found = carve_file(args.carve, args.out)
        except Exception as exc:
            print(f"carve failed: {exc}")
            return 1
        print(f"carved {len(found)} files into {args.out}")
        for f in found:
            print(f"  {f['file']}  ({f['type']}, {f['size']} bytes @ {f['offset']})")
        return 0

    if args.recover:
        from salvage.engine import open_image, recover_deleted
        try:
            img = open_image(args.recover)
            found = recover_deleted(img, args.out, fs_offset=args.offset)
        except Exception as exc:
            print(f"recover failed: {exc}")
            print("(MFT recovery needs a real NTFS image/volume — and raw disk reads need an elevated shell.)")
            return 1
        print(f"recovered {len(found)} deleted files into {args.out}")
        for f in found:
            print(f"  {f['path']}  ({f['size']} bytes)")
        return 0

    # No explicit command -> open the dashboard (double-click friendly).
    from salvage.server import serve
    print("Starting Salvage — open http://127.0.0.1:8900 in your browser.")
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
