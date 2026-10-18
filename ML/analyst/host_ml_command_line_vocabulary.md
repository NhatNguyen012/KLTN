# OpTC Host ML: command-line processing and vocabulary

## Purpose and boundary

This is the canonical concise specification for turning an eCAR record into
interpretable sparse features for the Host ML branch (XGBoost, LightGBM, and
Random Forest). It merges the former command-family walkthrough and vocabulary
design notes.

The current target is a benign eCAR vocabulary from `host-begnin/`, using
[`code/ecar_tokenizer.py`](../code/ecar_tokenizer.py) and
[`code/build_vocab.py`](../code/build_vocab.py). Source datasets are read-only.
The tokenizer treats every command as data: it never executes a command, imports
a module, loads a DLL, opens a referenced script/response file, or expands an
environment variable.

Current tokenizer policy: **`host_ml_structure_anchor_syntax`**. Grammar spans
come from [`command_syntax.py`](../code/command_syntax.py); output-path and frozen
vocabulary checks come from [`pipeline_contract.py`](../code/pipeline_contract.py).

`command_line` is an eCAR string, not an official enumeration of seven types.
The seven **launcher/grammar families** below are a project convention for
choosing a safe, useful parser.

## Input and output contract

The compact Host ML profile retains only an allowlisted subset of non-FLOW host
objects. It emits field-namespaced tokens, then maps known tokens to zero-based
columns in `vocab.json`. The integers are column indices, not ordinal values or a
sequence to feed directly to a tree.

| eCAR object | Retained properties | Feature intent |
|---|---|---|
| `PROCESS` | `image_path`, `parent_image_path`, `command_line` | executable context, command structure, parent → child relation |
| `FILE` | `image_path`, `file_path`, `new_path` | executable plus finite path category/extension |
| `MODULE` | `image_path`, `module_path` | executable/module identity and extension |
| `REGISTRY` | `image_path`, `key`, `registry_key`, `registry_path` | registry root/category, never raw key/value data |
| `TASK` | `image_path`, `path` | executable and task path category/extension |
| `SHELL` | `image_path`, `payload` | recognized invocation/parameter evidence, without raw parameter values |
| `THREAD`, `USER_SESSION`, `SERVICE`, `HOST` | no properties | action/object and their relation only |

`FLOW`, account/principal values, generic property inventories, network values,
raw registry data, labels, timestamps, PIDs/TIDs, UUIDs, SIDs, memory addresses,
and eCAR identifiers are not vocabulary features. IDs remain in the untouched
source data for a future graph/eCAR-Bro stage.

The resulting event row is normally a binary sparse CSR vector: each known token
sets one column to `1`. Counts are an implemented ablation; TF-IDF remains a future
ablation. Unknown tokens create no new column. Family, role and relation context
is available only when those tokens also survived vocabulary fitting.

## Token layers

| Layer | What is retained | Example |
|---|---|---|
| Lexical | normalized words, executable basename, extension, placeholders | `command_line::native::whoami` |
| Anchor | complete normalized names in launcher/command/module/API roles | `command_line::anchor::command=get-process` |
| Syntax | family-specific grammar evidence, options, operators, quotes, AST types | `command_line::syntax::operator=pipe` |
| Structure | family, switches, quoted-argument/segment buckets, shell operators | `command_line::structure::operator=pipe` |
| Semantic | role/type before a dynamic literal is abstracted | `command_line::semantic::role=script` |
| Relation | selected directed relations unavailable to a bag of words | `command_line::relation::switch_value=/tn->task_name` |
| Host context | eCAR action/object and parent executable → child executable | `structure::action_object=create->process` |

Structure, Anchor and Syntax are explicit requirements; semantics and lexical
fallback complement them. Layer tags overlap and are recorded per selected token
in metadata. They are not separate vocabularies. Existing `structure::switch` and
`structure::operator` columns coexist with explicit syntax columns; this
redundancy is documented and can be measured by ablation.

Parse command/payload source with its original whitespace and case. After role
assignment, normalize emitted lexical features with NFKC, NUL removal, whitespace
collapse and case-folding. The lexical layer replaces high-cardinality literals such as user
path components, numbered hosts, UUIDs/SIDs, long hex/Base64 strings, standalone
numbers, and exact IPs. The semantic fact is retained where context supports it:
for example, a port, version, encoded command, script, task name, or path.
Known credential/account/task-name switch values are abstracted before lexical
emission, including attached values. Meaning is utility-specific: `schtasks /p`
is a password and `ssh -p` is a port; unknown native `/p` is not given either
meaning. The small audited table does not resolve every custom command's values.

## Family recognition and handling

Classify from the final basename of `properties.image_path`; only when it is
missing, fall back to the first executable-like token in `command_line`. Do not
use a parent process or a word inside an argument to infer the family. Missing or
unknown launchers become `native` rather than a guessed special family. An absent
launcher emits a parse-status marker. Quoted executable paths with spaces are
recognized by the bounded argv lexer.

| Family | Recognized launcher | Handling that must survive tokenization |
|---|---|---|
| `cmd` | `cmd(.exe)` | `/c` vs `/k`, nested command after either switch, quotes, pipe/redirect/sequence operators |
| `powershell` | `powershell(.exe)`, `pwsh(.exe)` | `-File`, `-Command`, policy/window switches, encoded-command aliases and safe Base64 decoding |
| `python` | `python(.exe)`, `pythonw(.exe)`, versioned forms | script versus interpreter `-m`/`-c`; AST node/edge types for valid `-c` only |
| `wscript` | `wscript(.exe)` | `//` host options, script extension, subsequent script arguments |
| `cscript` | `cscript(.exe)` | console-host identity, `//` options, attached option values such as transport |
| `rundll32` | `rundll32(.exe)` | `/d` and `DLL,EntryPoint` as a library → entry-point relation |
| `native` | everything else | executable basename, `/`/`-` switches, response files, paths, registry/URL forms, and conservative option-value bindings |

Examples in [`sample/command_line_sample.json`](sample/command_line_sample.json)
cover all seven families. In particular, a PowerShell fragment without a launcher
can still be recognized from `image_path`; a Python `-m` after a script is an
argument, not automatically interpreter module mode; and a WScript/CScript
invocation reveals paths/arguments, not the referenced script body.

### Safe special cases

- CMD extracts the remainder after `/c` or `/k`, removes one whole outer payload
  quote and parses child clauses. Caret-escaped operators remain data. Relations
  reset at clause/operator boundaries. This is not complete CMD escaping/emulation.
- PowerShell `-Command` parses inline clauses with command anchors, pipes,
  semicolon/newline separators, backtick escapes and call-operator evidence.
  Strings containing operator characters stay data. Balanced nested groups stay
  opaque, with a parse-status marker; comments are recognized conservatively.
- PowerShell may decode up to two strict Base64 layers as UTF-16LE or UTF-8 with
  explicit size limits. It records success/partial/failure status and never
  lowercases the payload before decoding. A portable PowerShell AST is not
  claimed. Encoded operands are extracted before validating their Base64 alphabet;
  malformed and missing operands receive failure markers and raw encoded operands
  are suppressed from lexical features.
- Python `-c` uses `ast.parse` on the string as data and emits capped AST
  node/edge types. It never evaluates or imports code; parse failure is itself a
  token. Script/module boundaries prevent later `-c`/`-m` arguments from becoming
  interpreter modes. Source newlines/indentation survive parsing. Selected Python
  module/API anchors describe observed source spelling, not resolved runtime calls.
- Unknown switches remain lexical/structural evidence. The implementation does
  not invent a utility-specific meaning outside its small audited switch table.
- Native/WSH/Rundll32 argv does not become shell clauses merely because an
  argument contains `&` or `|`. WSH script bodies remain unavailable. Rundll32
  handles a quoted DLL path and a launcher-omitted argument fragment using
  authoritative `image_path` context.

For `powershell.exe -Command "Get-Process | Select-Object Name"`, the tokenizer emits:

```text
command_line::anchor::launcher=powershell.exe
command_line::anchor::command=get-process
command_line::anchor::command=select-object
command_line::syntax::switch=-command
command_line::syntax::operator=pipe
command_line::relation::pipeline=get-process->select-object
command_line::relation::launcher_payload=powershell->inline_command
```

Reversing the pipeline changes its directed relation. A quoted data string such
as `'Get-Process | Select-Object'` does not itself supply those command anchors
or a pipe operator. Tokens describe observed structure, not a malicious label.

## Vocabulary build and use

The current builder scans benign host/day gzip partitions, skips unsupported
objects and `label=1` records, and keeps every candidate whose **total term
frequency** meets `--min-frequency` (default `2`). Repetition within one event
counts toward TF. There is no vocabulary cap, host/day coverage gate, or reserved
marker exception in the current implementation.

The supervised pipeline uses both corrected Host roots (16–25 September).
Run `build_host_index.py`, then `build_split.py` with seed 1 to persist a shared
75% TRAIN / 10% validation / 15% test random event split. The implementation
stratifies by source file and class, with exact global class quotas after rounding.

Fit `build_vocab.py --split` from BOTH benign and malicious TRAIN rows only.
Transform all three partitions with `build_matrix.py --split`; TF filtering never
uses held-out events. Both artifacts record split identity and vocabulary checksum.
All three supervised models use these same matrices. This does not establish
process/host/campaign isolation and does not deduplicate event IDs across files.

The default representation is binary CSR; `--representation both` also preserves
counts. Index, split, vocabulary and matrix stages resume per completed file;
source identity, configuration/code and intermediate checksums are validated.
Source datasets remain read-only. The quick `build_malicious_index.py` inventory
samples prefixes and cannot replace the full Host label index.

Complete absolute-path commands with nohup/logs are in
[xu_li_host_data.md, section 9](xu_li_host_data.md#9-pipeline-supervised-một-split-chung-751015-seed-01).
Historical benign-only vocabulary and scenario pilot outputs do not satisfy this
shared-split contract and must not be used for this baseline.

## Limits and checks

The parser is intentionally shallow and deterministic, not execution-equivalent.
Malformed, truncated, nested, or obfuscated telemetry must retain lexical
fallback tokens. Feature value comes from measurement, not the terminology:
compare lexical-only against successive additions of structure, semantic roles,
relations, and safe AST features on a leakage-safe split.

Bounds: 32,768 command characters, 1,024 lexemes per parse, nesting depth 4 and
256 visited Python AST nodes. Emit parse-limit/failure markers. Unsupported shell
grouping, expansion, aliases, unusual option forms and arbitrary language nesting
remain limitations; no full Paragraph/Sentence object graph or shell execution is
claimed. Lexical fallback is also bounded and cannot guarantee intent recovery.

Run the focused checks after a tokenizer or builder change:

```bash
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp python3 -m unittest discover -s code -p 'test_*.py'
python3 code/build_vocab.py --roots host-begnin --read-to-eof --workers 12 --dry-run
```

Generate the walkthrough from the current tokenizer, without fitting sample data:

```bash
python3 code/explain_sample_tokenization.py --output code/output/sample_tokenization.md
```

## Evidence in brief

Toolscaler supplies the shared-component idea but does not tokenize eCAR or
Windows command lines. SemanticLog supports preserving a parameter's semantic
type while abstracting its raw value. AMIDES and QuasarNix support a robust
lexical sparse baseline. CmdCaliper shows that command intent is not merely word
overlap. FLASH and KAIROS motivate retaining action/object/executable context and
keeping volatile identities for provenance joins rather than tree features.

The fuller research and vocabulary-selection rationale is in
[`host_ml_tokenization_research.md`](host_ml_tokenization_research.md).
