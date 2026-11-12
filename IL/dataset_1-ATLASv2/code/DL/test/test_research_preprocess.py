import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

DL = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(DL / "model"), str(DL / "preprocess"), str(DL.parent)]
from build_network_shards import keep_window_in_split, get_split_from_event
from preprocess.common_schema import parse_timestamp_micros


class WindowTests(unittest.TestCase):
    def test_benign_midnight_embargo(self):
        events = [SimpleNamespace(timestamp=parse_timestamp_micros(t)) for t in
                  ["2022-07-16 23:59:50", "2022-07-17 00:00:10"]]
        self.assertFalse(keep_window_in_split("benign", events))

    def test_scenario_is_preserved_across_midnight(self):
        events = [SimpleNamespace(timestamp=parse_timestamp_micros(t)) for t in
                  ["2022-07-19 23:59:50", "2022-07-20 00:00:10"]]
        self.assertTrue(keep_window_in_split("m6", events))
        self.assertEqual(get_split_from_event("m6", events[0].timestamp), "test")


if __name__ == "__main__": unittest.main()
