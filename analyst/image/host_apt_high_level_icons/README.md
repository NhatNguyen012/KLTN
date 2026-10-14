# Illustrated high-level framework

Icon-based illustration of the proposed multi-source host APT architecture, using the MORPH-IDS reference only for visual style. Generated with the built-in imagegen tool.

The technical design is documented in [the editable high-level architecture](../host_apt_high_level/README.md) and [target ontology](../host_multisource_ontology_v2/README.md). The separate [Lam benchmark](../host_apt_high_level_lam_verified/README.md) records verified implementation details.

Endpoint deployment, novelty detection, integrated fusion and model lifecycle are proposed. Unknown/suspicious does not mean confirmed malicious. Drift can trigger a training request but does not generate labels. Model updates require verified training data, replay, validation and promotion. Current Lam inputs include Zeek-derived fields; endpoint-only collection requires compatible adapters, training and evaluation.

This illustration is a raster asset; use the existing SVG/draw.io architecture for precise structural edits. Its module grouping does not require one container per service or multiple VMs.

- [Illustrated framework PNG](high_level_design.png)
- [Generation prompt](generation_prompt.txt)

Final illustration uses labeled feedback connectors and standalone storage icons to keep routing legible. Storage access relationships and dataset adapters are specified in the editable technical diagram; the database icons do not imply that unadapted external data can train current checkpoints. The Windows icon is illustrative, not an OS restriction.

- [Refinement prompts](refinement_prompts.txt)
