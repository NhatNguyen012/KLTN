"""Name-masking ablation for the host-ML token pipeline (2026-11-20).

IL_MASK_NAMES=names        drop every token that states the identity of an executable, module or file
                           (image/parent/module basenames, process lineage, launcher/command anchors, argv0, ...)
IL_MASK_NAMES=names_words  additionally drop the lexical command-line word tokens (command_line::native::<word>, ...)
unset / empty              no masking (published behaviour)

What stays: action and object types, directory/path classes, switches, principal/uid classes, parent/session context
classes, ages, structural command-line relations without names. The mask is applied to the rows of the new domain
(train, val and test alike) before the vocabulary is built, so masked tokens get no column.
"""
import os
import re

LEVEL = os.environ.get("IL_MASK_NAMES", "")
_NAME_KEY = re.compile(
    r"(basename|system_stem|process_lineage|launcher|anchor::command|command_switch|source_exe|argv0|"
    r"(::|:)exe|lx:ctx:lineage|lx:exe)$")
_WORD = re.compile(r"^command_line::(native|cmd|python|powershell|wscript|cscript|rundll32|powershell_decoded)::[^=]*$")


def is_name_token(tok: str) -> bool:
    if "=" in tok:
        key, val = tok.split("=", 1)
        if _NAME_KEY.search(key):
            return True
        return key.endswith(":recent") and val.startswith("spawn:")
    return False


def mask(tokens):
    if not LEVEL:
        return tokens
    out = [t for t in tokens if not is_name_token(t)]
    if LEVEL == "names_words":
        out = [t for t in out if not _WORD.match(t)]
    return out
