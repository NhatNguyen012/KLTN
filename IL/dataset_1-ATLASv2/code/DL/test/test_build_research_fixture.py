"""End-to-end fixture: train-only vocabulary, provenance and atomic publication."""
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

DL = Path(__file__).resolve().parents[1]
ROOT = DL.parents[3]


class BuildFixtureTest(unittest.TestCase):
    def test_build_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="atlas_fixture_") as tmp:
            base = Path(tmp); raw = base / "raw/cbc-edr"; raw.mkdir(parents=True)
            gt = base / "labels"; gt.mkdir()
            for sc, timestamp, app in [
                ("s1", "2022-07-19 13:30:00", "train_tool.exe"),
                ("m3", "2022-07-19 20:30:00", "validation_only.exe"),
                ("m6", "2022-07-20 00:12:00", "test_only.exe"),
            ]:
                (gt / f"h1-{sc}.labels").write_text(
                    "id,name,type,process_uuid,label,stage\n"
                    f"1,{app},process,guid-{sc},attack,Execution_Discovery\n")
                rows = []
                for i in range(2):
                    rows.append(dict(type="endpoint.event.netconn", device_timestamp=timestamp + f".{i} +0000 UTC",
                        device_name="win-32-h1", process_guid=f"guid-{sc}", process_path=f"c:\\tools\\{app}",
                        netconn_protocol="TCP", remote_ip="10.193.66.115", remote_port=8080, local_port=50000))
                (raw / f"edr-h1-{sc}.jsonl").write_text("\n".join(map(json.dumps, rows)) + "\n")
            before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in raw.glob("*")}
            output = base / "derived"
            cmd = [sys.executable, str(DL / "preprocess/build_network_shards.py"),
                   "--data-dir", str(base / "raw"), "--reapr-dir", str(gt),
                   "--optc-spec", str(ROOT / "DL/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json"),
                   "--label-policy", "conservative-v2", "--output-dir", str(output)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(output.with_name("derived.building").exists())
            cfg = json.loads((output / "build_config.json").read_text())
            self.assertEqual((cfg["window_size_seconds"], cfg["stride_seconds"]), (180, 30))
            self.assertEqual(len(cfg["source_files"]), 3)
            cats = json.loads((output / "preprocessing/network_category_maps.json").read_text())
            app_map = cats["fields"]["app_family"]["mapping"]
            self.assertIn("train_tool.exe", app_map)
            self.assertNotIn("validation_only.exe", app_map)
            self.assertNotIn("test_only.exe", app_map)
            with (output / "split/network_sample_manifest.csv").open() as f:
                rows = list(csv.DictReader(f))
            self.assertEqual({r["split"] for r in rows}, {"train", "val", "test"})
            self.assertTrue(all(r["attack_stage_set"] == "2" for r in rows))
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in raw.glob("*")})


if __name__ == "__main__": unittest.main()
