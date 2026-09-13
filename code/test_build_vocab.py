"""Sampling and publication regression tests; all corpus fixtures are temporary."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_vocab import HostDay, _scan_host_day, build_parser, discover_host_days, select_vocabulary, main

BUILDER = Path(__file__).with_name("build_vocab.py")


def event(word: str = "repeatword", host: str = "sysclient0001", **extra) -> dict:
    return {"hostname": host + ".systemia.com", "object": "PROCESS", "action": "CREATE",
            "label": 0, "properties": {"image_path": "cmd.exe",
            "command_line": f"cmd.exe /c echo {word} {word}"}, **extra}


def write_gzip(root: Path, rows: list, host: str = "sysclient0001", day: str = "2019-09-16",
               shard: str = "") -> Path:
    path = root / day / f"AIA-1-25.ecar-{day}-{host}{shard}.json.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for row in rows:
            handle.write(row if isinstance(row, str) else json.dumps(row) + "\n")
    return path


class BuildVocabTests(unittest.TestCase):
    def test_training_fit_excludes_validation_and_records_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'input'
            write_gzip(root, [event(), event()])
            write_gzip(root, [event('heldoutonly')] * 2, day='2019-09-21')
            result = self.run_builder(root, base / 'out', 1, '--fit-purpose', 'training')
            self.assertEqual(result.returncode, 0, result.stderr)
            vocab = json.loads((base / 'out/vocab.json').read_text())
            meta = json.loads((base / 'out/vocab_metadata.json').read_text())
            self.assertFalse(any('heldoutonly' in token for token in vocab))
            self.assertEqual(meta['fit_purpose'], 'training')
            self.assertEqual(set(meta['scan']['days']), {'2019-09-16'})
            self.assertIn('command_syntax.py', meta['source_sha256'])
            self.assertIn('anchor', meta['selected_tokens_by_layer'])
            before = (base / 'out/vocab.json').read_bytes()
            reused = self.run_builder(root, base / 'out', 1, '--reuse-existing')
            self.assertEqual(reused.returncode, 0, reused.stderr)
            after_meta = json.loads((base / 'out/vocab_metadata.json').read_text())
            self.assertIn('single_document_only', after_meta['weird_token_hints'])
            self.assertEqual(meta['source_sha256'], after_meta['source_sha256'])
            self.assertEqual(before, (base / 'out/vocab.json').read_bytes())
            bad = self.run_builder(root, base / 'bad', 1, '--fit-purpose', 'training', '--days', '2019-09-21')
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse((base / 'bad/vocab.json').exists())

    def test_other_protected_roots_and_reuse_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as tmp, patch('pipeline_contract.PROJECT_ROOT', Path(tmp)):
            base = Path(tmp)
            for name in ('host-begnin', 'host-malicious', 'ecar-bro', 'bro'):
                output = base / name / 'vocab_metadata.json'
                args = ['--roots', str(base / 'input'), '--output', str(base / 'vocab.json'), '--metadata-output', str(output)]
                for mode in ([], ['--reuse-existing']):
                    with self.assertRaisesRegex(ValueError, 'outside source'):
                        main(args + mode)
                    self.assertFalse(output.exists())
            with self.assertRaisesRegex(ValueError, 'outside source'):
                main(['--roots', str(base / 'input'), '--output', str(base / 'vocab.json'),
                      '--metadata-output', str(base / 'metadata.json'), '--checkpoint-dir', str(base / 'bro/cache')])

    def test_defaults_are_benign_bounded_and_ten_workers(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.workers, 10)
        self.assertEqual(args.lines_per_host_day, 100_000)
        self.assertEqual(args.min_frequency, 2)
        self.assertEqual([root.name for root in args.roots], ["host-begnin"])
        self.assertFalse(args.no_resume)
        self.assertFalse(args.no_checkpoint)

    def test_grouping_deduplicates_overlapping_roots_and_combines_shards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_gzip(root, [event()], shard=".part1")
            write_gzip(root, [event()], shard=".part2")
            write_gzip(root, [event(host="sysclient0002")], host="sysclient0002")
            groups = discover_host_days([root, root / "2019-09-16"])
            self.assertEqual(len(groups), 2)
            self.assertEqual(len(groups[0].files), 2)
            self.assertEqual(groups[0].host, "sysclient0001")

    def test_discovery_rejects_attack_day_unknown_filename_and_day_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = write_gzip(root, [], day="2019-09-23")
            with self.assertRaisesRegex(ValueError, "non-benign"):
                discover_host_days([root])
            p.unlink()
            p = write_gzip(root, [])
            p.rename(p.with_name("unknown.json.gz"))
            with self.assertRaisesRegex(ValueError, "cannot identify"):
                discover_host_days([root])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = write_gzip(root, [])
            wrong = root / "2019-09-17" / p.name
            wrong.parent.mkdir()
            p.rename(wrong)
            with self.assertRaisesRegex(ValueError, "disagrees"):
                discover_host_days([root])

    def test_day_filter_is_applied_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_gzip(root, [])
            write_gzip(root, [], day="2019-09-17")
            groups = discover_host_days([root], ["2019-09-17"])
            self.assertEqual([g.day for g in groups], ["2019-09-17"])
            with self.assertRaises(ValueError):
                discover_host_days([root], ["2019-09-25"])

    def test_raw_budget_includes_blank_flow_and_positive_rows_and_stops_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = ["\n", event(object="FLOW"), event("maliciousonly", label=1), event(),
                    "THIS IS INVALID JSON BEYOND THE BUDGET\n"]
            write_gzip(root, rows)
            result = _scan_host_day(discover_host_days([root])[0], 4)
            self.assertEqual(result["host_day"]["lines_read"], 4)
            self.assertEqual(result["host_day"]["records"], 3)
            self.assertEqual(result["host_day"]["host_records"], 1)
            self.assertEqual(result["host_day"]["blank_lines"], 1)
            self.assertEqual(result["stats"]["excluded_records"], {"network_flow": 1, "label_1": 1})
            vocab, _ = select_vocabulary(result["document_frequency"], result["term_frequency"])
            self.assertIn("command_line::cmd::repeatword", vocab)
            self.assertFalse(any("maliciousonly" in token for token in vocab))
            self.assertEqual(result["term_frequency"]["command_line"]["command_line::cmd::repeatword"], 2)
            self.assertEqual(result["document_frequency"]["command_line"]["command_line::cmd::repeatword"], 1)

    def test_quota_is_shared_by_shards_and_short_shard_budget_carries_forward(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_gzip(root, [event()], shard=".part1")
            write_gzip(root, [event()] * 9 + ["bad\n"], shard=".part2")
            result = _scan_host_day(discover_host_days([root])[0], 6)
            self.assertEqual([f["lines_read"] for f in result["host_day"]["files"]], [1, 5])
            self.assertEqual(result["host_day"]["lines_read"], 6)
            self.assertEqual(result["host_day"]["host_records"], 6)
            self.assertTrue(result["host_day"]["files"][0]["eof_observed"])

    def test_quota_smaller_than_shard_count_never_opens_extra_shards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(3):
                write_gzip(root, [event()], shard=f".part{i}")
            result = _scan_host_day(discover_host_days([root])[0], 1)
            self.assertEqual(result["host_day"]["lines_read"], 1)
            self.assertEqual(len(result["host_day"]["files"]), 1)

    def test_empty_gzip_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_gzip(root, [])
            result = _scan_host_day(discover_host_days([root])[0], 20)
            self.assertEqual(result["host_day"]["lines_read"], 0)
            self.assertTrue(result["host_day"]["files"][0]["eof_observed"])

    def test_invalid_json_record_host_label_and_truncated_gzip_fail(self):
        fixtures = [(["bad\n"], "invalid JSON"), (["[]\n"], "event object"),
                    ([event(host="sysclient0999")], "hostname"), ([event(label="0")], "label must")]
        for rows, error in fixtures:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_gzip(root, rows)
                with self.assertRaisesRegex(ValueError, error):
                    _scan_host_day(discover_host_days([root])[0], 20)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_gzip(root, [event()])
            path.write_bytes(path.read_bytes()[:-8])
            with self.assertRaisesRegex(RuntimeError, "cannot read"):
                _scan_host_day(discover_host_days([root])[0], 20)

    def test_missing_label_uses_trusted_benign_partition_and_is_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = event()
            del row["label"]
            write_gzip(root, [row])
            result = _scan_host_day(discover_host_days([root])[0], 2)
            self.assertEqual(result["host_day"]["host_records"], 1)
            self.assertEqual(result["stats"]["labels_read"], {"missing": 1})

    def run_builder(self, root: Path, output: Path, workers: int = 1, *extra: str):
        return subprocess.run([sys.executable, str(BUILDER), "--roots", str(root),
                               "--lines-per-host-day", "3", "--workers", str(workers),
                               "--output", str(output / "vocab.json"),
                               "--metadata-output", str(output / "vocab_metadata.json"), *extra],
                              capture_output=True, text=True, timeout=30)

    def test_parallel_worker_counts_produce_identical_vocabulary_and_frequencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "input"
            for i in range(12):
                host = f"sysclient{i + 1:04d}"
                write_gzip(root, [event(host=host), event(host=host), event(host=host, object="FLOW"),
                                  event("beyondbudget", host=host)], host=host)
            snapshots = {p: p.read_bytes() for p in root.rglob("*.gz")}
            outputs = []
            for workers in (1, 10):
                target = base / f"out{workers}"
                run = self.run_builder(root, target, workers)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual({p.name for p in target.iterdir()}, {"vocab.json", "vocab_metadata.json"})
                vocab = json.loads((target / "vocab.json").read_text())
                meta = json.loads((target / "vocab_metadata.json").read_text())
                self.assertEqual(sorted(vocab.values()), list(range(len(vocab))))
                self.assertFalse(any("beyondbudget" in t or t.startswith("principal::") for t in vocab))
                self.assertEqual(meta["vocabulary_sha256"], hashlib.sha256((target / "vocab.json").read_bytes()).hexdigest())
                self.assertEqual(meta["scan"]["workers"], workers)
                self.assertEqual(meta["aggregate"]["source_lines"], 36)
                self.assertEqual(meta["aggregate"]["host_records"], 24)
                self.assertEqual(meta["schema_version"], 5)
                self.assertFalse(meta["scan"]["read_to_eof"])
                outputs.append((vocab, meta["selected_token_statistics"], meta["aggregate"]))
            self.assertEqual(outputs[0], outputs[1])
            self.assertTrue(all(p.read_bytes() == data for p, data in snapshots.items()))

    def test_failed_build_keeps_existing_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_gzip(base / "input", ["bad json\n"])
            target = base / "out"
            target.mkdir()
            for name in ("vocab.json", "vocab_metadata.json"):
                (target / name).write_text("previous-artifact")
            run = self.run_builder(base / "input", target)
            self.assertNotEqual(run.returncode, 0)
            for path in target.iterdir():
                self.assertEqual(path.read_text(), "previous-artifact")

    def test_dry_run_never_reads_invalid_gzip_or_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            path = write_gzip(base / "input", [])
            path.write_bytes(b"not gzip")
            run = self.run_builder(base / "input", base / "out", 10, "--dry-run")
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["host_days"], 1)
            self.assertFalse((base / "out").exists())

    def test_outputs_inside_unselected_source_day_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            write_gzip(root, [event()])
            source = write_gzip(root, [event()], day="2019-09-17")
            before = source.read_bytes()
            run = self.run_builder(root, root / "2019-09-17", 1, "--days", "2019-09-16")
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("outside source dataset roots", run.stderr)
            self.assertEqual(source.read_bytes(), before)
            self.assertFalse((source.parent / "vocab.json").exists())

    def test_flow_only_prefix_does_not_extend_budget_or_publish_empty_vocab(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            write_gzip(base / "input", [event(object="FLOW")] * 3 + [event()])
            run = self.run_builder(base / "input", base / "out")
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("no tokens meet the threshold", run.stderr)
            self.assertFalse((base / "out" / "vocab.json").exists())
            self.assertFalse((base / "out" / "vocab_metadata.json").exists())
            self.assertEqual(len(list((base / "out" / ".vocab.checkpoints").rglob("*.json.gz"))), 1)

    def test_interrupted_build_resumes_completed_host_days(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "input"
            target = base / "out"
            write_gzip(root, [event(host="sysclient0001")] * 2, host="sysclient0001")
            broken = write_gzip(root, ["bad json\n"], host="sysclient0002")

            first = self.run_builder(root, target)
            self.assertNotEqual(first.returncode, 0)
            checkpoints = list((target / ".vocab.checkpoints").rglob("*.json.gz"))
            self.assertEqual(len(checkpoints), 1)

            write_gzip(root, [event(host="sysclient0002")] * 2, host="sysclient0002")
            second = self.run_builder(root, target)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("Checkpoint resume: reused 1/2 host/days; 1 left to scan", second.stderr)
            meta = json.loads((target / "vocab_metadata.json").read_text())
            self.assertEqual(meta["scan"]["checkpoint"]["resumed_host_days"], 1)
            self.assertEqual(meta["scan"]["checkpoint"]["scanned_host_days_this_run"], 1)
            self.assertFalse((target / ".vocab.checkpoints").exists())

            clean_target = base / "clean"
            clean = self.run_builder(root, clean_target, 1, "--no-checkpoint")
            self.assertEqual(clean.returncode, 0, clean.stderr)
            clean_meta = json.loads((clean_target / "vocab_metadata.json").read_text())
            self.assertEqual(json.loads((target / "vocab.json").read_text()),
                             json.loads((clean_target / "vocab.json").read_text()))
            self.assertEqual(meta["selected_token_statistics"],
                             clean_meta["selected_token_statistics"])
            self.assertEqual(meta["aggregate"], clean_meta["aggregate"])

    def test_read_to_eof_reads_all_rows_and_flags_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "input"
            write_gzip(root, [event(host="sysclient0001")] * 10, host="sysclient0001")
            target = base / "out"
            run = subprocess.run([sys.executable, str(BUILDER), "--roots", str(root),
                                 "--read-to-eof", "--workers", "1",
                                 "--output", str(target / "vocab.json"),
                                 "--metadata-output", str(target / "vocab_metadata.json")],
                                capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            meta = json.loads((target / "vocab_metadata.json").read_text())
            self.assertTrue(meta["scan"]["read_to_eof"])
            self.assertEqual(meta["scan"]["mode"], "full")
            self.assertEqual(meta["aggregate"]["source_lines"], 10)


if __name__ == "__main__":
    unittest.main()
