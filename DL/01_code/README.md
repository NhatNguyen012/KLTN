# DARPA OpTC KLTN bootstrap (STEP 00–01)

This scaffold enforces compressed-in-place processing and Markdown handoffs.

## Quick start on Windows

1. Copy the folder contents into `D:\UIT\KLTN`.
2. Replace `E:\DARPA_OpTC` below with the actual external-drive path.

```powershell
cd D:\UIT\KLTN
python scripts\00_inventory_archives.py --input-root "E:\DARPA_OpTC" --output-root "D:\UIT\KLTN"
python scripts\01_build_host_vocab.py --input-root "E:\DARPA_OpTC\ecar" --output-root "D:\UIT\KLTN"
```

Read `PROJECT_STATE.md` and `ROADMAP_KLTN.md` first.
