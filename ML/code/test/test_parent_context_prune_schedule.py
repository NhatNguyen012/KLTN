"""Differential TTL scheduling tests against the frozen v3 full-scan algorithm."""
import importlib.util
import random
import tempfile
import unittest
from pathlib import Path
from ML.code.preprocess.process_context_tracker import HostProcessContextTracker, ProcessContextConfig

spec = importlib.util.spec_from_file_location('prune_reference', Path(__file__).parent / 'fixtures/parent_context_v3_prune_reference.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)

class ReferenceTracker(HostProcessContextTracker):
    _prune_if_needed = reference._prune_if_needed

class PruneScheduleTests(unittest.TestCase):
    def test_differential_ties_expiry_capacity_pid_and_resume(self):
        rng = random.Random(2)
        cfg = ProcessContextConfig(enabled=True, max_processes_per_host=13, ttl_seconds=0.00003)
        old, new = ReferenceTracker(cfg), HostProcessContextTracker(cfg)
        t = 100
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(1200):
                t += rng.choice([0, 0, 1, 2, 30, 31])
                event = dict(hostname='sysclient'+str(i % 2), actorID='u'+str(rng.randrange(25)),
                             objectID='u'+str(rng.randrange(25)), timestamp=t,
                             object='PROCESS' if i % 3 else 'FILE',
                             action='CREATE' if i % 3 else 'READ',
                             properties={'pid': rng.randrange(17), 'image_path': 'C:\\Windows\\cmd.exe'})
                self.assertEqual(old.get_context_tokens(event, query_t=t), new.get_context_tokens(event, query_t=t))
                old.observe(event, event_t=t); new.observe(event, event_t=t)
                self.assertEqual(old.hosts, new.hosts)
                self.assertEqual(old.pid_tracker, new.pid_tracker)
                self.assertEqual(old.evicted_uuids, new.evicted_uuids)
                self.assertEqual(old.stats, new.stats)
                if i % 97 == 0:
                    checkpoint = Path(tmp)/'tracker.json'
                    new.save_checkpoint(checkpoint)
                    new = HostProcessContextTracker(cfg)
                    new.load_checkpoint(checkpoint)

if __name__ == '__main__':
    unittest.main()
