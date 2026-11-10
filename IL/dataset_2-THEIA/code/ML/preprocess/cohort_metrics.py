"""Aligned provenance audits; identity fields never enter the model matrix."""
from collections import defaultdict
from pathlib import Path
import hashlib
import numpy as np


def load_provenance(root, part, lines):
    root = Path(root).resolve()
    path = (root / part['provenance_path']).resolve()
    if root not in path.parents:
        raise ValueError('Provenance escapes input root')
    if hashlib.sha256(path.read_bytes()).hexdigest() != part['provenance_sha256']:
        raise ValueError('Provenance checksum mismatch')
    with np.load(path, allow_pickle=False) as z:
        values = {k: z[k] for k in z.files}
    if not np.array_equal(values['source_line'], lines):
        raise ValueError('Provenance rows are not aligned with feature rows')
    return values


def grouped_metrics(root, parts, width, decode, predict, threshold):
    """Any-hit process recall, positive-event campaign recall, and sampled FP/day.

    No real-time alert claims: counts refer to retained/sampled events. A process
    is detected only if at least one of its labeled-positive events is detected.
    """
    processes = defaultdict(lambda: [0, 0])
    campaigns = defaultdict(lambda: [0, 0])
    days = defaultdict(lambda: [0, 0])
    for part in parts:
        if 'provenance_path' not in part:
            raise ValueError('Rebuild input with aligned process/campaign provenance')
        X, y, lines = decode(Path(root) / part['path'], width, part)
        context = load_provenance(root, part, lines)
        pred = np.asarray(predict(X)).reshape(-1) >= threshold
        for i in range(len(y)):
            day = str(np.datetime64(int(context['timestamp'][i]), 'us').astype('datetime64[D]'))
            days[day][0] += int(y[i] == 0)
            days[day][1] += int(y[i] == 0 and pred[i])
            if y[i]:
                processes[str(context['process_guid'][i])][0] += 1
                processes[str(context['process_guid'][i])][1] += int(pred[i])
                campaigns[str(context['scenario'][i])][0] += 1
                campaigns[str(context['scenario'][i])][1] += int(pred[i])
    return dict(
        positive_processes=len(processes),
        detected_positive_processes=sum(hit > 0 for _, hit in processes.values()),
        process_recall=sum(hit > 0 for _, hit in processes.values()) / max(1, len(processes)),
        campaigns={k: dict(positive_events=n, tp=hit, recall=hit/n, detected=hit > 0)
                   for k, (n, hit) in sorted(campaigns.items())},
        sampled_fp_by_utc_day={k: dict(negative_events=n, fp=fp, fpr=fp/max(n, 1))
                               for k, (n, fp) in sorted(days.items())},
        caveat='Retained cohort with benign sampling and positive caps; not full-telemetry FP/day.')


def collision_metrics(root, parts, width, decode):
    vectors = defaultdict(lambda: [0, 0])
    for part in parts:
        X, y, _ = decode(Path(root) / part['path'], width, part)
        for i, label in enumerate(y):
            # Store exact sparse index bytes: no hash collisions in this audit.
            key = X.indices[X.indptr[i]:X.indptr[i+1]].astype('<i4').tobytes()
            vectors[key][int(label)] += 1
    mixed = [n for n in vectors.values() if n[0] and n[1]]
    return dict(unique_vectors=len(vectors), mixed_label_vectors=len(mixed),
                positives_in_mixed_vectors=sum(n[1] for n in mixed),
                negatives_in_mixed_vectors=sum(n[0] for n in mixed))
