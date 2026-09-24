# Salvage

Deleted-file recovery for Windows disk images. Recovers lost data two ways:

- **Signature carving** (`--carve`) — scans raw sectors for known file signatures and reassembles files even when the filesystem index is gone.
- **MFT recovery** (`--recover`) — parses the NTFS Master File Table (via pytsk3) to reconstruct deleted files still present on disk.

## Usage

```powershell
py run.py --carve disk.img --out recovered      # carve files by signature
py run.py --recover disk.img --out recovered    # recover deleted files via MFT
py run.py --serve                               # open the command-center dashboard
```

## Structure

- `salvage/carver.py` — signature-based carving with stall detection + deadline
- `salvage/engine.py` — NTFS deleted-file recovery (pytsk3)
- `salvage/server.py` — HTTP dashboard with background scan state + watchdog
- `salvage/exfat.py`, `salvage/drives.py`, `salvage/inspect.py` — filesystem helpers
- `run.py` — CLI entry point
- `Salvage.spec` — PyInstaller onefile build (admin-elevated)

Built with AI-assisted development.
