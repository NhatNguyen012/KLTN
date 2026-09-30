# Two-stage cascade: matched raw-event FP/FN analysis

## Scope and comparison rule

This report examines the measured LightGBM + GraphSAGE run on the frozen seed02 test split: 1,249,689 events, 568 FP, 656 FN, F1 0.984801. The policy was chosen on validation: LightGBM score below 0.30 → benign, score at least 0.96 → malicious, and the middle band → GraphSAGE at 0.95. These numbers come from `code/output/provenace_graph/kaggle_output/optc-two-stage-cascade-results/`.

A useful *comparison event* is one with the opposite label but closely matched observable behavior. The strongest comparison has the **same binary Host ML feature vector**. In such a pair, the tree model must return the same score. Comparing raw fields then reveals information lost in the vector or evidence that can only live in surrounding process/host context. We use the verified TEST-error versus TRAIN-event pairs in `code/output/host_ml_seed02/fp_fn_casebook/cases.json`; their raw records and source-line hashes were checked in the original casebook. Here each graph score is recomputed from the frozen `model_numpy.npz` and `graph.sqlite`. Scoring a TRAIN comparator explains the learned decision boundary; it is not a second test result. The pair is a controlled illustration, not a population-level causal effect.

The original dataset's **event label** is the evaluation target. A `label=0` event can occur inside `host-malicious/` and inside suspicious activity; this does not license calling the annotation wrong. Raw commands and payloads below were read as data and never executed.

## Error accounting

The previous LightGBM error export contains all 446 FP and 3,189 FN. Reapplying the frozen cascade policy to those source lines gives:

| Cascade outcome from prior LightGBM errors | Direct ML | Graph | Total |
| --- | ---: | ---: | ---: |
| FP remaining | 379 | 28 | 407 |
| FP corrected | 0 | 39 | 39 |
| FN remaining | 269 | 356 | 625 |
| FN corrected | 0 | 2,564 | 2,564 |

The measured cascade totals are 568 FP and 656 FN, so 161 new FP and 31 new FN came from previously correct LightGBM events. The result ZIP lacks per-event scores/source lines for those newly broken cases. Their **counts** follow exactly from the two measured confusion matrices; their specific raw events cannot be claimed from this export.

The strongest population-level finding among old errors is routing: 379/568 cascade FP are old FP with LightGBM score ≥0.96, and 269/656 cascade FN are old FN with score <0.30. No graph score is consulted for them. Among the 356 old FN that were routed and still missed, 188 have no `creates` ancestry edge in the extracted ego graph; none of the 2,564 old FN that graph rescued lacked such an edge. This is an association within this error subset, not proof that adding a CREATE edge alone fixes classification. The `truncated` and `unresolved_relation` flags occur in both correct and wrong subsets and do not independently explain the errors.

## Matched raw events and actual model decisions

Scores are risk rankings, not calibrated event probabilities. The score comparisons below use the exact selected thresholds, including the direct-routing rule.

### Pair 1 — benign Chrome font read becomes FP; same Host vector as a malicious read

- Failed TEST event: `host-malicious/2019-09-24/AIA-1-25/AIA-1-25.ecar-2019-09-24-sysclient0005.json.gz`, decompressed line **2,380,855**, `label=0`. Raw action/object: `READ FILE`; Chrome reads `WINDOWS\FONTS\COMICBD.TTF`.
- Correctly positive TRAIN comparator: `host-malicious/2019-09-24/AIA-501-525/AIA-501-525.ecar-2019-09-24-sysclient0501.json.gz`, line **2,335,212**, `label=1`. Chrome reads `Windows\fonts\sylfaen.ttf`.
- Both events have the **same 10-column binary vector**. LightGBM scores both **0.971660**, over the cascade's 0.96 direct-positive threshold. Their separately inspected graph scores are **0.997730** and **0.994231**. The model therefore predicts both positive, making the first FP and the second TP. The raw font names and `size` differ, but font names collapse to path category and `.ttf`; `size` is not a feature. The graph's broad browser/host context also rates both highly. The exact vector collision proves the tree cannot separate this pair using its current input. It does not prove which font read is intrinsically malicious.

### Pair 2 — benign PowerShell Start-Sleep becomes FP because the graph veto is bypassed

- Failed TEST event: `host-malicious/2019-09-24/AIA-1-25/AIA-1-25.ecar-2019-09-24-sysclient0005.json.gz`, line **2,813,533**, `label=0`. Raw `COMMAND SHELL` invokes `Start-Sleep`; `context_info` says the host application ran `powershell.exe -File c:\autoupdate\updater.ps1`.
- Correctly positive TRAIN comparator: `host-malicious/2019-09-25/AIA-501-525/AIA-501-525.ecar-2019-09-25-sysclient0501.json.gz`, line **1,687,226**, `label=1`. The same cmdlet appears within a hidden, encoded PowerShell host application.
- Their sparse vectors are **identical** and LightGBM scores both **0.989433**. The raw `context_info` distinction is absent from the Host ML vector. GraphSAGE *does* separate the process contexts: **0.086251** benign versus **0.999743** malicious. The malicious actor graph has `launch=encoded`, `launch=hidden` and web/public network facts; the benign graph lacks those actor facts. Yet 0.989433 ≥0.96 sends both directly to positive, so the available graph signal cannot veto this FP. This pair isolates a routing limitation, alongside the vector collision.

### Pair 3 — malicious loopback PING becomes FN; same Host vector and low graph risk as benign PING

- Failed TEST event: `host-malicious/2019-09-23/AIA-401-425/AIA-401-425.ecar-2019-09-23-sysclient0402.json.gz`, line **2,977,354**, `label=1`. Raw action/object: `TERMINATE PROCESS`, command `ping -w 2000 -n 2 127.0.0.1`.
- Correctly negative TRAIN comparator: `host-begnin/2019-09-21/AIA-51-75/AIA-51-75.ecar-2019-09-21-sysclient0051.json.gz`, line **1,915,449**, `label=0`, with the same action and command. The archived original path is under `/mnt/HDD_Data/host-begnin/`; the local source manifest gives its exact location.
- Their binary vectors are **identical**, and LightGBM scores both **0.142003**, below the 0.30 graph-routing threshold. Graph scores inspected separately are **0.003315** and **0.001095**, both well below 0.95. Thus the same visible action receives the same negative decision, correct for one label and wrong for the other. Different principal/host/time or campaign context are not represented in the tree vector, and the graph's finite prior facts do not recover a high-risk distinction here. This pair shows an evidence/label ambiguity at the event level; changing the threshold alone is unlikely to make both decisions correct.

### Pair 4 — malicious Edge partial download remains FN after graph review

- Failed TEST event: `host-malicious/2019-09-24/AIA-1-25/AIA-1-25.ecar-2019-09-24-sysclient0005.json.gz`, line **2,653,068**, `label=1`. `MicrosoftEdgeCP.exe` creates `Downloads\movingonup.exe.0t30cdt.partial`.
- Correctly negative TRAIN comparator: `host-malicious/2019-09-25/AIA-351-375/AIA-351-375.ecar-2019-09-25-sysclient0351.json.gz`, line **2,221,325**, `label=0`. The same executable creates `Downloads\update.exe.0wddy3y.partial`.
- Vectors are **similar, not identical** (Jaccard 0.90). LightGBM distinguishes them somewhat, 0.932255 versus 0.093840, yet 0.932255 is below both the old 0.94016 ML threshold and the cascade's 0.96 direct-positive threshold. Graph review returns **0.853858** versus **0.893848**, both below 0.95, so the malicious event remains FN. The graph is built from prior process/host facts; it does not directly encode this target FILE CREATE or its download filename. The raw filename and principal differences are not sufficient in the learned decision to cross either threshold. One cannot attribute this miss to a single dropped column without an ablation.

### Pair 5 — counterexample where graph context resolves an identical-vector collision

- Previously missed TEST event: `host-malicious/2019-09-25/AIA-351-375/AIA-351-375.ecar-2019-09-25-sysclient0351.json.gz`, line **1,816,073**, `label=1`. `lwabeat.exe` performs `OPEN PROCESS`.
- Correctly negative TRAIN comparator: original benign source `/mnt/HDD_Data/host-begnin/2019-09-21/AIA-51-75/AIA-51-75.ecar-2019-09-21-sysclient0051.json.gz`, line **1,915,101**, `label=0`; the raw command line is the same.
- The Host vectors and LightGBM scores are identical (**0.339562**), so both enter the graph band. Graph scores differ: **0.968561** for the malicious event versus **0.041357** for the benign one. The malicious ego graph has two observed CREATE ancestry edges and a prior `launch=inline` actor fact; the benign graph has no CREATE ancestry edge. The cascade now predicts TP/TN. This is the concrete comparison showing what the graph adds when the gate actually routes the event and the causal context differs.

### Additional graph-only ambiguity

The original casebook's C13 pair compares two Chrome renderer `OPEN PROCESS` events with the **same Host vector** but opposite labels (TEST benign line 2,394,489 on sysclient0005; TRAIN malicious line 2,386,419 on sysclient0501). Both enter GraphSAGE because their LightGBM score is 0.912526. Their graph scores are **0.997730** and **0.994231**, so both become positive; the benign event remains FP. The raw renderer channel/cache identifiers differ but are normalized away. Both ego graphs contain a browser actor and two CREATE edges, which illustrates a case where the available graph context also fails to separate event labels.

## What this analysis can and cannot establish

The "thing" to compare against is a correctly predicted, opposite-label event that matches the failure as closely as possible: exact sparse vector first, then action/object/executable and graph structure. Exact-vector pairs prove identical tree scores are unavoidable for those two events. Different graph scores demonstrate that learned context can separate some pairs, while identical high or low graph scores show where it does not. The raw comparison and model inputs support *mechanistic explanations*; they do not prove an underlying malicious root cause or that a single feature change would repair all errors.

To trace the 161 newly introduced FP and 31 newly introduced FN, a future Kaggle result must export each final error's `(source_id, source_line, label, ML score, graph score, route)` and the matching source-index provenance. Aggregate confusion counts alone cannot identify their raw source lines.
