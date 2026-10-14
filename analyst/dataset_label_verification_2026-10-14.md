# Dataset label verification — 14/10/2026

Decision: retain CICAPT-IIoT2024 provenance and AIT-LDS V2.1. Prefer SAGA v2.0 as the Windows choice when published ground truth is required; keep Windows-APT V4 conditional, not categorically unlabeled.

| Dataset | Label evidence | Qualification |
|---|---|---|
| CICAPT-IIoT2024 provenance | Official UNB release describes labelled CSVs. Paper Table 3 defines node `label` (attack/benign), `subLabel` (attack category); `Attack_info.csv` is supplementary. | Node targets need explicit mapping if used for event/window classification. Download form currently reports server error; archive not inspected. |
| AIT Log Data Set V2.1 | Published `labels/` mirrors `gather/`; annotation references original line numbers, attack-step labels and rules. | Preserve raw line numbering; scope benign defaults to covered logs/simulation interval. Multi-label/hierarchical attack steps are not automatically independent MITRE techniques. |
| Windows-APT 2025 V4 | Public release + Data in Brief paper; Wazuh/MITRE annotations and scenario metadata. | Paper acknowledges benign MITRE-tagged activity. This audit did not verify a separate per-record binary ground-truth column/file. Do not equate a nonempty MITRE tag with maliciousness. V4 lists `scenario_mapping_supplement`, but its content could not be read; cannot assert it lacks additional labels. |
| SAGA v2.0 | Public author download page; paper explains event-level technique labeling using Caldera reports, process lineage and expert rules. | Windows/Procmon-derived synthetic audit logs, not observed enterprise traffic. Label richness does not itself establish multi-label prevalence. Archive not downloaded in this audit. |

Primary sources:

- CIC release: https://www.unb.ca/cic/datasets/iiot-dataset-2024.html
- CIC paper / Table 3: https://arxiv.org/html/2407.11278v1
- CIC expanded paper: https://www.cs.unb.ca/~sray/papers/CICAPT_IIoT_paper_Mobiquitous24_author_copy.pdf
- CIC download form: https://cicresearch.ca/IOTDataset/CICAPT-IIoT-Dataset/
- AIT release + label example + paper citation: https://zenodo.org/records/19483937
- AIT paper DOI: https://doi.org/10.1109/TDSC.2022.3201582
- Windows release: https://data.mendeley.com/datasets/b8fmtzvpy8/4
- Windows paper: https://pmc.ncbi.nlm.nih.gov/articles/PMC12950481/ ; https://doi.org/10.1016/j.dib.2026.112569
- SAGA release: https://saga-tw.github.io/dataset/v2
- SAGA paper labeling section III-A: https://arxiv.org/html/2411.13138v2
- SAGA publication status / TDSC DOI: https://arxiv.org/abs/2411.13138 ; https://doi.org/10.1109/TDSC.2025.3640696

Verification scope: official release documentation and primary papers, not a full-corpus label-quality audit. Windows paper text retrieved through indexed primary-source search; direct PMC rendering challenged the browser. Mendeley direct HTTP returned 403 and public API attempts failed. No forms submitted, no emails sent, no full dataset downloads or training.

For Lam's current model, published labels do not establish feature compatibility: its inputs still depend on Zeek connection statistics and process context. Label-grounded host datasets need adapters/new training; their annotations must stay outside predictor features. Keep baseline artifacts unchanged.
