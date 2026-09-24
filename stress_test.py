"""Stress test for Salvage's signature carver.

Generates a REAL file of every supported type (JPEG, PNG, PDF, ZIP, MP3, MIDI,
WAV), concatenates them with junk separators, carves the buffer, and checks each
original is recovered byte-for-byte. Run:  py stress_test.py

This is the "don't find out the hard way during a real carve" guard — run it
after touching any extractor.
"""
import io
import os
import subprocess
import sys
import tempfile

# Locate the 'salvage' package whether this file sits next to it (repo layout:
# salvage-repo/salvage) or inside it (source layout: salvage/stress_test.py).
HERE = os.path.dirname(os.path.abspath(__file__))
for _base in (HERE, os.path.dirname(HERE)):
    if os.path.isdir(os.path.join(_base, "salvage")):
        sys.path.insert(0, _base)
        break
from salvage.carver import carve, SIGNATURES  # noqa: E402

from PIL import Image  # noqa: E402
import zipfile  # noqa: E402
import wave  # noqa: E402


def gen_files():
    files = {}
    # JPEG (real, via Pillow)
    b = io.BytesIO()
    Image.new("RGB", (64, 48), (200, 30, 30)).save(b, "JPEG")
    files["JPEG"] = b.getvalue()
    # PNG (real, via Pillow)
    b = io.BytesIO()
    Image.new("RGB", (64, 48), (30, 200, 30)).save(b, "PNG")
    files["PNG"] = b.getvalue()
    # PDF (real, via Pillow)
    b = io.BytesIO()
    Image.new("RGB", (64, 48), (30, 30, 200)).save(b, "PDF")
    files["PDF"] = b.getvalue()
    # ZIP (real, via zipfile)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("hello.txt", "hello world\n" * 200)
    files["ZIP"] = b.getvalue()
    # WAV (real, via wave)
    b = io.BytesIO()
    with wave.open(b, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(22050)
        w.writeframes(b"\x00\x01\x00\x02" * 4000)
    files["WAV"] = b.getvalue()
    # MIDI (minimal but valid: MThd + one MTrk with a note + end-of-track)
    track = b"\x00\x90\x3c\x64" + b"\x60\x80\x3c\x00" + b"\x00\xff\x2f\x00"
    midi = (
        b"MThd" + (6).to_bytes(4, "big")
        + (0).to_bytes(2, "big") + (1).to_bytes(2, "big") + (480).to_bytes(2, "big")
        + b"MTrk" + len(track).to_bytes(4, "big") + track
    )
    files["MIDI"] = midi
    # MP3 (real, via ffmpeg sine tone)
    with tempfile.TemporaryDirectory() as td:
        mp3 = os.path.join(td, "tone.mp3")
        r = subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
             "sine=frequency=440:duration=1", "-codec:a", "libmp3lame",
             "-b:a", "128k", mp3],
            capture_output=True,
        )
        if r.returncode != 0:
            raise RuntimeError("ffmpeg failed: " + r.stderr.decode(errors="replace"))
        files["MP3"] = open(mp3, "rb").read()
    return files


def main():
    files = gen_files()
    print("generated samples:")
    for label, data in files.items():
        print(f"  {label:6s}: {len(data)} bytes")

    # Build a buffer: [junk][file]... so the carver has to find each header at
    # an arbitrary offset, not just at 0.
    junk = b"\x00" * 256  # no supported signature starts with 0x00
    buffer = b"".join(junk + data for data in files.values())

    recovered = list(carve(buffer, min_size=1))
    print(f"\ncarved {len(recovered)} files from the buffer")

    by_label = {}
    for off, label, ext, blob in recovered:
        by_label.setdefault(label, []).append((off, blob))

    print("\n=== accuracy check (byte-identical) ===")
    all_ok = True
    for label, original in files.items():
        got = by_label.get(label, [])
        match = any(blob == original for _, blob in got)
        if match:
            print(f"  {label:6s}: OK  (recovered byte-identical)")
        else:
            all_ok = False
            if got:
                closest = min(got, key=lambda x: abs(len(x[1]) - len(original)))
                print(f"  {label:6s}: FAIL  {len(got)} candidate(s); "
                      f"closest {len(closest[1])} bytes vs original {len(original)}")
            else:
                print(f"  {label:6s}: FAIL  (not recovered at all)")
    print("\nRESULT: " + ("ALL TYPES RECOVERED ACCURATELY" if all_ok else "SOME TYPES FAILED"))
    edge_ok = test_pdf_edge_cases()
    return 0 if (all_ok and edge_ok) else 1


def build_pdf(body: bytes) -> bytes:
    """Build a minimal valid single-revision PDF whose startxref points at xref."""
    header = b"%PDF-1.4\n"
    xref_offset = len(header) + len(body)
    tail = (b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n"
            + str(xref_offset).encode() + b"\n%%EOF")
    return header + body + tail


def test_pdf_edge_cases() -> bool:
    print("\n=== PDF edge cases ===")
    ok = True

    # 1. stray %%EOF inside a stream: must recover the FULL file (through last %%EOF)
    body = b"1 0 obj\n<< /Length 21 >>\nstream\n(%%EOF inside stream)\nendstream\nendobj\n"
    full = build_pdf(body)
    rec = list(carve(b"\x00" * 16 + full, min_size=1))
    pdfs = [(o, b) for o, l, e, b in rec if l == "PDF"]
    if any(b == full for _, b in pdfs):
        print("  stray-%%EOF-in-stream  : OK (full file recovered through last %%EOF)")
    else:
        print(f"  stray-%%EOF-in-stream  : FAIL ({len(pdfs)} candidate(s), none full)")
        ok = False

    # 2. corrupt fragment with startxref 0: must be REJECTED (not emitted)
    corrupt = (b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n0000000000 65535 f \n"
               b"trailer\n<< /Size 1 /Prev 1594355 >>\nstartxref\n0\n%%EOF\n")
    rec2 = list(carve(b"\x00" * 16 + corrupt, min_size=1))
    pdfs2 = [l for o, l, e, b in rec2 if l == "PDF"]
    if not pdfs2:
        print("  startxref-0 fragment   : OK (rejected, not emitted)")
    else:
        print(f"  startxref-0 fragment   : FAIL (still emitted {len(pdfs2)} time(s))")
        ok = False

    return ok


if __name__ == "__main__":
    sys.exit(main())
