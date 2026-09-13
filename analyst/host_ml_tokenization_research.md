# OpTC Host ML: structure-aware semantic tokenization and vocabulary selection

## Decision

This is the canonical concise research note for the Host ML vocabulary. It
merges the earlier structure-aware-tokenization synthesis and vocabulary
selection review.

The project uses **deterministic structure-aware semantic tokenization** for
human-auditable sparse columns. It is inspired by Toolscaler's principle that
related items should share meaningful components, but it is **not** an
implementation of Toolscaler's learned gist embeddings, residual-k-means
codebooks, or post-guided generative training.

The teacher's Structure/Anchor/Syntax requirement is adopted as an explicit
feature contract. Here **Anchor** means a stable name observed in a grammar role,
such as a launcher, command, module, or API name. It is a project definition,
not a claim that those three words name a particular published algorithm.

For one eCAR event, retain complementary kinds of evidence:

```text
lexical command evidence
  + stable anchors identified in command/code roles
  + launcher-specific syntax and operators
  + semantic roles of dynamic values
  + selected eCAR and command/provenance relations
```

The current compact implementation is [`code/ecar_tokenizer.py`](../code/ecar_tokenizer.py);
the builder is [`code/build_vocab.py`](../code/build_vocab.py). The operational
policy is summarized in
[`host_ml_command_line_vocabulary.md`](host_ml_command_line_vocabulary.md).

The current policy is `host_ml_structure_anchor_syntax`. Its bounded lexer is
[`command_syntax.py`](../code/command_syntax.py). One vocabulary still maps all
tokens to sparse columns. `token_layers()` adds overlapping metadata tags for
audit and ablation; the tags do not create duplicate columns.

| Requirement | Observable evidence | Example emitted by the tokenizer |
|---|---|---|
| Structure | Clause-local roles and selected directed relationships | `command_line::relation::pipeline=get-process->select-object` |
| Anchor | A complete normalized name in an observed command/code role | `command_line::anchor::command=get-process` |
| Syntax | Family-specific options/operators, quote evidence and safe AST types | `command_line::syntax::operator=pipe` |
| Semantic normalization | Parameter roles before variable text is abstracted | `command_line::relation::switch_value=/p->password` for `schtasks.exe` |

The layers overlap: an operator is syntax and contributes to structure. Keep
compound anchors alongside lexical pieces; a quoted data string containing a
command name is not automatically a command anchor. These rules express observed
syntax, not inferred execution or malicious intent.

## What the evidence supports

| Question | Most relevant evidence | Project interpretation |
|---|---|---|
| What does the phrase mean? | Toolscaler | Factor an item into shareable components rather than assigning one opaque ID. |
| How is structure represented? | StructCoder, POSH, DONAPI, PowerShell AST work | Preserve safe syntax/edge types, option-value roles, and operators; retain a fallback when parsing fails. |
| How are variables normalized? | SemanticLog, Lograph, AMIDES | Preserve semantic type or join role while suppressing high-cardinality surface values. |
| What eCAR context matters? | FLASH, KAIROS | Keep action/object/executable/path context and relations; reserve execution IDs for later graph joins. |
| What is a strong command baseline? | AMIDES, QuasarNix, CmdCaliper, LOLAL, ShellCore | Use robust lexical sparse features; treat semantic similarity and sequence structure as complementary, not automatically solved. |

No cited paper proves that a particular cutoff, vocabulary size, or feature layer
is optimal for OpTC. Those are experiment choices, not literature facts.

## Feature-design rationale

### Structure

An invocation is modeled as a shallow tree: launcher, switches, typed operands, operators,
and positional arguments. A relation such as `-File → script` carries more meaning
than two unrelated words. Emit bounded, non-executing structure tokens for known
switches, role transitions, operators, and family-specific conventions. For
Python interpreter-level `-c`, AST node/edge types and selected observed API/module
names are extracted without evaluation. Preserve original source whitespace for
parsing; normalize only emitted features. Full PowerShell AST parsing is future
work. Balanced PowerShell groups are opaque and receive an explicit status.

### Semantics and normalization

Do not replace every variable with an undifferentiated wildcard. Context can
distinguish a port, version, status, duration, task name, path, script, encoded
payload, or identifier. The raw PID/UUID/account/path-user segment is usually a
poor sparse feature, but its type can remain useful. The parser suppresses
known account/password/task-name operands before lexical emission and scopes
option meanings to a family/utility table. For example, `schtasks /p` is a password;
an unknown utility's `/p` is not guessed to be a port. Arbitrary custom commands
and embedded program literals still require conservative fallback and auditing.
Recurring execution IDs may
later join provenance records, so excluding them from `X` does not mean deleting
them from the source data.

### Lexical fallback

Telemetry can be malformed, truncated, nested, or obfuscated. Retain normalized,
field- and family-namespaced lexical pieces alongside the structured layer. This
is essential for both coverage and an honest ablation: structure should improve a
lexical baseline, not silently replace it.

### Sparse-tree representation

`vocab.json` maps a token to a column. For an event, deduplicate known token
indices and set those CSR columns to one. Never feed token IDs as a padded numeric
sequence to XGBoost, LightGBM, or Random Forest: arbitrary IDs would create false
numeric distance. Binary presence is the baseline; count/log-count/TF-IDF use the
same fit boundary and are ablations.

## Vocabulary fitting and evaluation

Vocabulary construction is a learned preprocessing step whenever token retention
depends on TF, DF, top-K, or a label-aware score. Therefore its fit boundary must
match the experiment.

| Use case | Permitted fit corpus |
|---|---|
| Current benign discovery build | `host-begnin/` under the explicitly recorded scan configuration; descriptive only |
| Current supervised benchmark preprocessing | both benign and malicious assigned to TRAIN in the shared 75/10/15 split (seed 1) |
| Cross-validation | training portion of each fold independently |
| Possible future final refit | requires an explicit experiment revision; retain an untouched test set |
| Transductive design | any pre-known unlabeled inputs only if declared; do not describe it as future prediction |

The active pipeline is full Host label indexing → persisted stratified random
75/10/15 split (seed 1, file/label strata) → `build_vocab.py --split` →
`build_matrix.py --split`. Both classes in TRAIN contribute to vocabulary fit.
RF, XGBoost and LightGBM reuse the exact split and vocabulary, bound by SHA256.
See [the operating procedure](xu_li_host_data.md#9-pipeline-supervised-một-split-chung-751015-seed-01)
for complete commands. The historical benign date-scan mode is not this experiment.

The present builder's default is total **TF ≥ 2** with no cap. TF counts repeated
occurrences in one event; DF counts documents/events containing a token. Neither
is universally superior. `DF_train ≥ 2`, other low thresholds and vocabulary caps
should be compared on validation rather than selected from test statistics.
Label-aware ranking remains an optional TRAIN-only ablation, not the current
frequency-based selection rule. Syntax/anchor tokens also face TF filtering. A future reserved
finite schema is an ablation, not an implicit exception to the present rule.

Avoid a misleading binary split in which the training set contains only benign
records but the stated goal is a supervised benign/malicious tree classifier. That
is an anomaly-detection setup unless the training objective is changed and
reported accordingly. Directory membership alone also does not establish a valid
event-level target; document the label rule and prediction unit.

The current random-event baseline does not establish process/host/campaign or
temporal generalization; those require separate evaluations.
Fit vocabulary, TF-IDF, feature selection, scaling, and class weights on train;
freeze them before validation/test. Report precision-recall behavior, alert/FPR
budgets, and false alerts per host/day where applicable—not accuracy alone.

## Minimal experiment plan

Use one baseline model to screen the following on the same leakage-safe split,
then validate the promising settings across XGBoost, LightGBM, and Random Forest:

1. Lexical-only baseline.
2. Add complete grammar-identified anchors.
3. Add launcher/switch/operator syntax and semantic parameter types.
4. Add directed command and parent-child/eCAR relations.
5. Add safe family-native AST features where available.

For the leading configurations, compare TF and DF cutoffs, binary/count/TF-IDF,
and feasible vocabulary sizes. Record feature count, non-zeros per event, peak
RAM, build/train/inference time, out-of-vocabulary rate by field/family, PR-AUC
or average precision, and recall at the chosen false-positive budget. Do not
oversample before fitting TF/DF; it changes token statistics without adding new
observations.

## Operational status and limitations

`build_vocab.py` can scan benign partitions to EOF and checkpoint each completed
host/day. Checkpoints make a long discovery scan resumable, but not a substitute
for a train-only vocabulary in a later benchmark. Metadata records source code
hashes, scan scope, TF/DF, tokenizer policy, and checkpoint/resume information;
record the split and label policy when supervised training begins. Source-code
hashes cover the tokenizer, lexer, builder and shared contract. Dataset identity
uses resolved path, size and modification time; it is not a dataset-content SHA256.

The local matrix builder now preserves counts before binary projection, writes
bounded chunks, resumes complete input files and assembles final CSR through
disk-backed arrays. It publishes a new directory and rejects incompatible fits.
The existing attack-day host-range split remains a prototype; it does not prove
campaign isolation. Evaluation selects a validation threshold once and freezes
it for test. Both classes are required before supervised evaluation/packaging.

The tokenizer is deliberately bounded (32,768 command characters, 1,024 lexemes
per parse, and nesting depth 4). It does not emulate all CMD/PowerShell
quoting, aliases, escaping, environment expansion, or nested-language semantics.
Semantic categories are rule assigned, not learned intent embeddings. WScript and
CScript command lines reveal invocation structure but not script bodies. These
are reasons to preserve lexical fallbacks and to measure every proposed layer.

For the first run, fit `code/output/vocab.json` and write its metadata to
`code/output/vocab_metadata.json`, then build matrices in `code/output/matrix/`.
Vocabulary size and corpus counts must come from that run's metadata.
Passing regression tests establishes
the tested behavior, not full-corpus coverage or better APT detection.

## Selected sources

- Yunyue Su et al., [*Toolscaler*](https://aclanthology.org/2025.findings-emnlp.30/), Findings of EMNLP 2025 — exact phrase and compositional shared-code principle.
- Sindhu Tipirneni et al., [*StructCoder*](https://doi.org/10.1145/3636430), ACM TKDD 2024 — syntax/semantic relations.
- Chenbo Zhang et al., [*SemanticLog*](https://doi.org/10.1109/TSE.2025.3625121), IEEE TSE 2026 — semantic parameter categories.
- Guojun Chu et al., [*Lograph*](https://doi.org/10.1109/TSE.2025.3527856), IEEE TSE 2025 — recurring entities as log joins.
- Sian-Yao Huang et al., [*CmdCaliper*](https://aclanthology.org/2024.emnlp-main.1126/), EMNLP 2024 — intent beyond lexical overlap.
- Raphael Uetz et al., [*AMIDES*](https://www.usenix.org/conference/usenixsecurity24/presentation/uetz), USENIX Security 2024; Dmitrijs Trizna et al., [*QuasarNix*](https://doi.org/10.1145/3807450), ACM TOPS 2026 — robust lexical sparse baselines.
- Jihyeon Song et al., [PowerShell feature optimization](https://onlinelibrary.wiley.com/doi/full/10.4218/etrij.2020-0215), ETRI Journal 2021 — parser-aware PowerShell evidence.
- Mati Ur Rehman et al., [*FLASH*](https://ieeexplore.ieee.org/document/10646725/) and Zijun Cheng et al., [*KAIROS*](https://doi.org/10.1109/SP54263.2024.00005), IEEE S&P 2024 — OpTC provenance fields and relations.
- Daniel Arp et al., [*Dos and Don'ts of ML in Computer Security*](https://www.usenix.org/conference/usenixsecurity22/presentation/arp), USENIX Security 2022; and [scikit-learn leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html) — fit boundaries and evaluation discipline.

The local PDFs and released-code notes are in `paper-token/`, `paper-general/`,
and their `code/README.md` manifests.
