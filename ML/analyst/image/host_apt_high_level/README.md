# High-level architecture — target design

Updated 2026-10-14 to match the [target ontology](../host_multisource_ontology_v2/README.md). This figure describes functional modules and data/control flow, not ontology layers. Deployment, fusion, novelty detection and the integrated learning lifecycle are proposed.

- [PNG](high_level_design.png)
- [SVG](high_level_design.svg)
- [Editable draw.io](high_level_design.drawio)
- [Generator](render.py)
- [Separate code-grounded Lam benchmark](../host_apt_high_level_lam_verified/README.md)

The endpoint collects OS/security, application/service and available orchestration/audit logs, including host-observed communication events. Lightweight ML and a separately validated novelty/OOD policy support triage. Unknown/suspicious is not confirmed malicious. An agent coordinator forwards logs, scores and evidence; agentic investigation is optional.

One Central VM can run multiple services/containers for ingestion, correlation, provenance GraphSAGE/cascade, temporal DL, contextual fusion and analyst review. BiLSTM and Mixed-Type Self-Attention are independently trained alternatives. Model outputs require an explicit common target and leakage-safe alignment before fusion. The vertical ingestion-to-fusion link carries local scores and availability masks.

Learning services can share that VM. Sustained drift, reviewed degradation or sufficient confirmed new data can trigger a request. The controller checks data/label quality, the trainer uses new TRAIN data plus replay, and the validator checks old/new domains before registry approval and rollout. Validation supports selection; independent TEST remains held out. Drift and predictions do not create ground-truth labels automatically.

Persistent storage contains raw and processed observations, evidence, verified datasets, replay and versioned model artifacts/metadata. Store access is summarized in the storage block; it is not a separate VM. No storage technology is mandated. Offline research datasets require adapters and label mapping before training.

Current Lam code uses Zeek conn joined with eCAR-Bro, fixed 15-minute windows and chunks of at most 512 flows. Those are benchmark details, not guaranteed endpoint log capabilities. Moving to this endpoint-oriented target requires compatible source adapters, retraining and evaluation. The separate Lam figure remains unchanged. Existing model experiments do not prove deployment, agentic behavior, fusion or OOD performance.

Regenerate with `python3 analyst/image/host_apt_high_level/render.py`. The renderer checks text bounds, XML validity and draw.io references. It writes only this diagram directory and does not read or modify telemetry/model artifacts.
