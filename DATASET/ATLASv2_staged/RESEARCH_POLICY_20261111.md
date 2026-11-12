# Stage label status and research policy — 11 November 2026

Existing `.labels` files and raw telemetry are preserved. Their added `stage`
column is weak process-level supervision generated from executable names and
host rules in `add_stage_column.py`, not an independent event/tactic annotation.
A process can participate in several stages.

Keep the original REAPr process-involvement labels, the local heuristic event
refinement, and the local process-stage labels separate. The last positive
event's heuristic stage is currently used as the window's single target.

Raw audit: `IL/dataset_1-ATLASv2/code/DL/output/research_20261111/raw_audit/`.
Revised sensitivity shards: `IL/dataset_1-ATLASv2/code/DL/output/research_20261111/data_v2/`.

- Seed endpoint membership alone no longer makes a connection positive.
  Treating such unverified events as negative is a sensitivity assumption,
  not independently verified benign truth.
- S3 is excluded because its configured attack start follows all its telemetry.
  No replacement timestamp is invented.
- Windows crossing a benign day split boundary are excluded.
- New manifests preserve start/end times and all positive process-stage IDs.

The test target changes from 38 to 24 positive windows. Its scores cannot be
presented as improvements on the original benchmark. Its last-event test target
has no stage-1 or stage-3 windows, so it cannot validate all four attack stages.
These actions can still occur inside mixed windows.

A publishable replacement needs reviewed event/action evidence, time intervals,
multi-stage or unknown annotations and label-version provenance. Do not infer
gold labels from which model predictions would improve F1.
