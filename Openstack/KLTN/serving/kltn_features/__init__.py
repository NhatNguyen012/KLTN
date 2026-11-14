"""KLTN serving features for the IL models (OpTC -> ATLASv2 -> AInception SL700).

_vendor/ holds the training-time preprocessing copied byte-for-byte from the research code (scripts/vendor_features.py,
_vendor/PROVENANCE.json). The modules here only add what serving needs on top of it: online grouping of auditd
records, the Sysmon adapter, per-host featurizers with vocabulary lookup / OOV accounting, and the DL window builder.
"""
VERSION = "kltn-features-il3-v1"
