#!/usr/bin/env python3
"""Unit tests for Deep Learning Tokenizer and Vocabulary Builder (Host + Network)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

# Add project root
import sys
PROJECT_ROOT = next((p for p in Path(__file__).resolve().parents if (p / "AGENTS.md").is_file()), Path("/mnt/SSD_Data/optc"))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from DL.code.preprocess.dl_ecar_tokenizer import (
    classify_ip_endpoint,
    classify_network_scope,
    classify_port_role,
    classify_proto,
    classify_bytes,
    tokenize_network_flow,
    tokenize_dl_record,
    get_all_bounded_network_tokens,
)
from DL.code.preprocess.build_dl_vocab import build_dl_vocabulary
from DL.code.preprocess.causal_dataset import TokenVocabulary, CausalTripletDataset, collate_causal_batch
from ML.code.preprocess.ecar_tokenizer import tokenize_record as host_tokenize_record


class TestDLEcarTokenizer(unittest.TestCase):
    """Test suite for dl_ecar_tokenizer."""

    def test_ip_classification(self):
        # Enterprise internal (OpTC 142.20.0.0/16)
        self.assertEqual(classify_ip_endpoint("142.20.56.252"), "enterprise_internal")
        self.assertEqual(classify_ip_endpoint("142.20.1.1"), "enterprise_internal")
        # Private internal (RFC 1918)
        self.assertEqual(classify_ip_endpoint("10.20.2.66"), "private_internal")
        self.assertEqual(classify_ip_endpoint("192.168.1.100"), "private_internal")
        self.assertEqual(classify_ip_endpoint("172.16.5.1"), "private_internal")
        # Loopback
        self.assertEqual(classify_ip_endpoint("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip_endpoint("::1"), "loopback")
        # Multicast / Broadcast
        self.assertEqual(classify_ip_endpoint("224.0.0.1"), "multicast")
        self.assertEqual(classify_ip_endpoint("225.0.0.1"), "multicast")
        self.assertEqual(classify_ip_endpoint("255.255.255.255"), "broadcast")
        # Public external
        self.assertEqual(classify_ip_endpoint("8.8.8.8"), "external_public")
        self.assertEqual(classify_ip_endpoint("104.244.42.1"), "external_public")
        # Unspecified
        self.assertEqual(classify_ip_endpoint("::"), "unspecified")
        self.assertEqual(classify_ip_endpoint("0.0.0.0"), "unspecified")
        self.assertEqual(classify_ip_endpoint(""), "unspecified")

    def test_scope_classification(self):
        self.assertEqual(classify_network_scope("enterprise_internal", "enterprise_internal"), "internal_to_internal")
        self.assertEqual(classify_network_scope("private_internal", "enterprise_internal"), "internal_to_internal")
        self.assertEqual(classify_network_scope("enterprise_internal", "external_public"), "internal_to_external")
        self.assertEqual(classify_network_scope("external_public", "enterprise_internal"), "external_to_internal")
        self.assertEqual(classify_network_scope("loopback", "loopback"), "loopback")
        self.assertEqual(classify_network_scope("enterprise_internal", "multicast"), "multicast_broadcast")

    def test_port_classification(self):
        self.assertEqual(classify_port_role(80), "http_web")
        self.assertEqual(classify_port_role("443"), "https_web")
        self.assertEqual(classify_port_role("53"), "dns")
        self.assertEqual(classify_port_role(445), "smb_cifs")
        self.assertEqual(classify_port_role(135), "rpc_endpoint")
        self.assertEqual(classify_port_role(3389), "remote_desktop")
        self.assertEqual(classify_port_role(5985), "winrm_http")
        self.assertEqual(classify_port_role(88), "kerberos")
        self.assertEqual(classify_port_role(389), "ldap")
        self.assertEqual(classify_port_role(50889), "ephemeral_high")
        self.assertEqual(classify_port_role(8081), "registered_mid")
        self.assertEqual(classify_port_role(7), "well_known_other")

    def test_bytes_quantization(self):
        self.assertEqual(classify_bytes("0"), "zero")
        self.assertEqual(classify_bytes(None), "zero")
        self.assertEqual(classify_bytes(76), "tiny_beacon")
        self.assertEqual(classify_bytes(1024), "tiny_beacon")
        self.assertEqual(classify_bytes(4096), "small_payload")
        self.assertEqual(classify_bytes(500000), "medium_transfer")
        self.assertEqual(classify_bytes(5000000), "bulk_exfil")

    def test_host_equivalence(self):
        """Ensure Host records produce identical tokens in both tokenizers."""
        host_record = {
            "object": "PROCESS",
            "action": "CREATE",
            "principal": "NT AUTHORITY\\SYSTEM",
            "properties": {
                "image_path": "C:\\Windows\\System32\\cmd.exe",
                "parent_image_path": "C:\\Windows\\System32\\services.exe",
                "command_line": "cmd.exe /c whoami /all",
            }
        }
        res_host, audit_host = host_tokenize_record(host_record)
        res_dl, audit_dl = tokenize_dl_record(host_record)

        self.assertEqual(audit_host["eligible"], audit_dl["eligible"])
        self.assertEqual(res_host, res_dl)

    def test_flow_tokenization_and_no_leakage(self):
        """Ensure OpTC FLOW events are tokenized properly without leaking raw dynamic values."""
        flow_record = {
            "action": "MESSAGE",
            "object": "FLOW",
            "principal": "NT AUTHORITY\\NETWORK SERVICE",
            "properties": {
                "direction": "inbound",
                "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\svchost.exe",
                "l4protocol": "17",
                "size": "76",
                "src_ip": "142.20.61.130",
                "src_port": "53",
                "dest_ip": "142.20.56.252",
                "dest_port": "50889"
            }
        }
        grouped, audit = tokenize_dl_record(flow_record)
        self.assertTrue(audit["eligible"])
        self.assertIn("object::flow", grouped["object"])
        self.assertIn("action::message", grouped["action"])
        self.assertIn("principal::nt_authority", grouped["principal"])

        prop_vals = set(grouped["property_value"])
        self.assertIn("net::direction=inbound", prop_vals)
        self.assertIn("net::proto=udp", prop_vals)
        self.assertIn("net::src_scope=enterprise_internal", prop_vals)
        self.assertIn("net::dest_scope=enterprise_internal", prop_vals)
        self.assertIn("net::scope=internal_to_internal", prop_vals)
        self.assertIn("net::src_port_role=dns", prop_vals)
        self.assertIn("net::dest_port_role=ephemeral_high", prop_vals)
        self.assertIn("net::bytes=tiny_beacon", prop_vals)
        self.assertIn("net::proc=svchost.exe", prop_vals)

        # Critical: Verify no raw IP or port string in ANY emitted token
        all_emitted = [tok for group in grouped.values() for tok in group]
        for tok in all_emitted:
            self.assertNotIn("142.20.61.130", tok)
            self.assertNotIn("142.20.56.252", tok)
            self.assertNotIn("50889", tok)


class TestDLVocabularyBuilder(unittest.TestCase):
    """Test suite for build_dl_vocab."""

    def test_vocabulary_construction(self):
        dl_vocab = build_dl_vocabulary()
        self.assertGreaterEqual(len(dl_vocab), 10490)

        # Check existing base token intact
        self.assertIn("principal::nt_system", dl_vocab)
        self.assertIsInstance(dl_vocab["principal::nt_system"], int)

        # Check newly appended network tokens
        self.assertIn("object::flow", dl_vocab)
        self.assertIn("net::direction=inbound", dl_vocab)
        self.assertIn("net::direction=outbound", dl_vocab)
        self.assertIn("net::proto=tcp", dl_vocab)
        self.assertIn("net::proto=udp", dl_vocab)
        self.assertIn("net::scope=internal_to_internal", dl_vocab)
        self.assertIn("net::scope=internal_to_external", dl_vocab)
        self.assertIn("net::dest_port_role=http_web", dl_vocab)
        self.assertIn("net::dest_port_role=https_web", dl_vocab)
        self.assertIn("net::dest_port_role=smb_cifs", dl_vocab)
        self.assertIn("net::bytes=tiny_beacon", dl_vocab)
        self.assertIn("net::bytes=bulk_exfil", dl_vocab)

        # Verify metadata file
        meta_path = PROJECT_ROOT / "DL/code/output/dl_vocab_metadata.json"
        self.assertTrue(meta_path.is_file())
        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["format"], "dl_host_and_network_vocabulary")
        self.assertEqual(meta["total_tokens"], len(dl_vocab))
        self.assertGreater(meta["network_extension"]["new_network_tokens_count"], 150)


class TestTokenVocabularyIntegration(unittest.TestCase):
    """Test TokenVocabulary and CausalTripletDataset with FLOW events."""

    def test_vocab_loading_and_collate(self):
        vocab_path = PROJECT_ROOT / "DL/code/output/dl_vocab.json"
        vocab = TokenVocabulary.from_vocab_file(vocab_path)
        self.assertTrue(vocab.frozen)
        self.assertEqual(vocab.get("<pad>"), 0)
        self.assertEqual(vocab.get("<unk>"), 1)
        self.assertEqual(vocab.get("<none>"), 2)

        # Check that network token returns a valid shifted ID > 2
        tok_id = vocab.get("net::scope=internal_to_external")
        self.assertGreater(tok_id, 2)

        # Check non-existent token returns 1 (<unk>)
        unk_id = vocab.get("totally_unknown_gibberish_token_999")
        self.assertEqual(unk_id, 1)

        # Mock sample batch with flow token IDs
        sample_batch = [
            {
                "incoming_ids": [2],
                "parent_ids": [vocab.get("principal::nt_system")],
                "current_ids": [vocab.get("object::flow"), vocab.get("net::direction=outbound")],
                "is_malicious": 1,
                "scenario_id": 2,
                "stage_id": 3,
            }
        ]
        batch_tensor = collate_causal_batch(sample_batch)
        self.assertEqual(batch_tensor["batch_size"], 1)
        self.assertEqual(batch_tensor["offsets"].shape[0], 3)
        self.assertEqual(batch_tensor["target_binary"][0].item(), 1.0)
        self.assertEqual(batch_tensor["target_scenario"][0].item(), 2)
        self.assertEqual(batch_tensor["target_stage"][0].item(), 3)


if __name__ == "__main__":
    unittest.main()
