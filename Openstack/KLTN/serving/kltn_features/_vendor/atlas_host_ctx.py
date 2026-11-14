# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_1-ATLASv2/code/ML/preprocess/build_host_shards.py
# source sha256 869dcae06216ba25b9d9079e2a9b9244a58dddd05ad5afaa3f2da069eb0bb3d8; do not edit (re-run the vendoring script instead).
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from typing import Any

from .common_schema import CanonicalEvent, classify_image_dir, extract_basename


DIR_CATEGORIES = (
    "SYSTEM32",
    "PROGRAM_FILES",
    "TEMP_OR_APPDATA",
    "WINDOWS_OTHER",
    "USERS_OTHER",
    "OTHER",
)


def get_command_family(basename: str) -> str:
    """Classify executable basename into OpTC command family."""
    b = basename.lower()
    for fam in ("powershell", "cmd", "cscript", "wscript", "rundll32", "python"):
        if fam in b:
            return fam
    return "native"


def dir_to_role(dir_cat: str) -> str:
    """Map directory category to OpTC path role."""
    d = dir_cat.upper()
    if d == "SYSTEM32":
        return "system"
    if d == "PROGRAM_FILES":
        return "program_files"
    if d == "TEMP_OR_APPDATA":
        return "temp"
    if d == "WINDOWS_OTHER":
        return "windows"
    if d == "USERS_OTHER":
        return "user_profile"
    return "other_path"


PREDEFINED_DOMAIN_TOKENS = [
    # 1. Browser self-cache structural indicator
    "temp_context::app_own_cache",
    # 2. File Extension Structural Categorization
    "file_ext::type=exe",
    "file_ext::type=zip",
    "file_ext::type=hta",
    "file_ext::type=vbs",
    "file_ext::type=ps1",
    "file_ext::type=bat",
    "file_ext::type=tmp",
    "file_ext::type=sqlite",
    "file_ext::type=none_or_dir",
    "file_ext::type=other",
    "file_ext::office_autosave_tmp",
    # 3. Causal Typed Incoming Interaction Context (Past-only [ts - 30s/300s, ts])
    "proc_context::has_netconn",
    # 4. Cross-Process Structural Directory Transitions (Actor_Dir and Actor_Dir -> Target_Dir)
    *[f"crossproc::actor_dir={d}" for d in DIR_CATEGORIES],
    *[f"crossproc::dir={d1}->{d2}" for d1 in DIR_CATEGORIES for d2 in DIR_CATEGORIES],
]


class FileSessionIndex:
    """Strictly causal (past-only, t' <= t) index for Parent Lineage, Grandparent, and Typed Incoming Interactions."""

    def __init__(self) -> None:
        self.netconns: dict[str, list[int]] = defaultdict(list)
        # parent_map: guid -> (parent_guid, parent_basename, parent_dir_category, parent_path)
        self.parent_map: dict[str, tuple[str, str, str, str]] = {}
        # incoming_crossproc: target_guid -> list of (ts, actor_dir_category, actor_basename)
        self.incoming_crossproc: dict[str, list[tuple[int, str, str]]] = defaultdict(list)

    def add_event(self, event: CanonicalEvent) -> None:
        """Update session state causally at current event timestamp ts."""
        et = event.event_type
        guid = event.process_guid
        ts = event.timestamp

        # Record 1-hop parent mapping from current event
        if guid and event.parent_path:
            p_base = extract_basename(event.parent_path).lower()
            p_dir = classify_image_dir(event.parent_path)
            if p_base:
                self.parent_map[guid] = (event.parent_guid, p_base, p_dir, event.parent_path)

        if et == "PROCESS_START":
            if event.target_guid and event.target_path:
                self.parent_map[event.target_guid] = (
                    guid,
                    extract_basename(event.process_path).lower(),
                    classify_image_dir(event.process_path),
                    event.process_path,
                )
        elif et == "FLOW_START":
            # Record network activity timestamp in monotonic order
            if guid:
                self.netconns[guid].append(ts)
            if event.parent_guid:
                self.netconns[event.parent_guid].append(ts)
        elif et == "CROSS_PROCESS":
            # Record typed incoming cross-process interaction onto target_guid
            if event.target_guid:
                actor_dir = classify_image_dir(event.process_path)
                actor_base = extract_basename(event.process_path).lower()
                self.incoming_crossproc[event.target_guid].append((ts, actor_dir, actor_base))

    def get_ancestors(self, guid: str, max_depth: int = 3) -> list[tuple[str, str, str]]:
        """Return list of (basename, dir_category, path) for up to max_depth ancestors."""
        ancestors: list[tuple[str, str, str]] = []
        curr = guid
        depth = 0
        while curr in self.parent_map and depth < max_depth:
            p_guid, p_base, p_dir, p_path = self.parent_map[curr]
            if p_base:
                ancestors.append((p_base, p_dir, p_path))
            if not p_guid or p_guid == curr:
                break
            curr = p_guid
            depth += 1
        return ancestors

    def has_netconn(self, guid: str, ts: int, window_micros: int = 30_000_000) -> bool:
        """Strictly causal check [ts - window, ts] on current process_guid (no 2-hop sibling leak)."""
        if not guid or guid not in self.netconns:
            return False
        n_list = self.netconns[guid]
        left = bisect_left(n_list, ts - window_micros)
        right = bisect_right(n_list, ts)
        return right > left

    def get_incoming_crossproc(self, guid: str, ts: int, window_micros: int = 30_000_000) -> list[tuple[str, str]]:
        """Return distinct (actor_dir, actor_base) that opened `guid` within [ts - window, ts]."""
        if not guid or guid not in self.incoming_crossproc:
            return []
        low = ts - window_micros
        res: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for ev_ts, actor_dir, actor_base in reversed(self.incoming_crossproc[guid]):
            if ev_ts < low:
                break
            if ev_ts <= ts and (actor_dir, actor_base) not in seen:
                seen.add((actor_dir, actor_base))
                res.append((actor_dir, actor_base))
        return res

    def get_incoming_crossproc_dirs(self, guid: str, ts: int, window_micros: int = 30_000_000) -> set[str]:
        """Return distinct actor directory categories that opened `guid` within [ts - window, ts]."""
        inc = self.get_incoming_crossproc(guid, ts, window_micros)
        return {d for d, _ in inc}


def extract_domain_shift_tokens(event: CanonicalEvent, session: FileSessionIndex, optc_vocab: set[str] | None = None) -> list[str]:
    tokens: list[str] = []
    proc_base = extract_basename(event.process_path).lower()
    self_dir = classify_image_dir(event.process_path)
    actor_fam = get_command_family(proc_base)
    actor_role = dir_to_role(self_dir)
    target_raw = event.target_path or ""
    target_norm = target_raw.strip().strip('"\'').replace("/", "\\").lower()
    target_base = extract_basename(target_raw).lower()
    et = event.event_type

    # 1. Intrinsic Event Structure: Browser local cache
    if proc_base == "firefox.exe" and ("mozilla" in target_norm or "firefox" in target_norm):
        tokens.append("temp_context::app_own_cache")

    # 2. Intrinsic Event Structure: File extension classification
    if et in ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE"):
        ext = ("." + target_base.rsplit(".", 1)[-1]) if "." in target_base else ""
        if ext in (".exe", ".com", ".scr", ".pif"):
            tokens.append("file_ext::type=exe")
        elif ext in (".zip", ".7z", ".tar", ".gz", ".rar", ".cab"):
            tokens.append("file_ext::type=zip")
        elif ext in (".hta", ".sct"):
            tokens.append("file_ext::type=hta")
        elif ext in (".vbs", ".vbe"):
            tokens.append("file_ext::type=vbs")
        elif ext in (".ps1", ".psm1", ".psd1"):
            tokens.append("file_ext::type=ps1")
        elif ext in (".bat", ".cmd"):
            tokens.append("file_ext::type=bat")
        elif ext in (".tmp",):
            tokens.append("file_ext::type=tmp")
        elif ext in (".sqlite", ".db", ".dat"):
            tokens.append("file_ext::type=sqlite")
        elif not ext or ext == "." or target_norm.endswith("\\"):
            tokens.append("file_ext::type=none_or_dir")
        else:
            tokens.append("file_ext::type=other")

        if proc_base in ("winword.exe", "excel.exe", "powerpnt.exe"):
            if "~" in target_base or ext in (".tmp", ".asd", ".wbk"):
                tokens.append("file_ext::office_autosave_tmp")

    # 3. Intrinsic Event Structure: Cross-Process structural directory transition
    if et == "CROSS_PROCESS":
        tokens.append(f"crossproc::actor_dir={self_dir}")
        if target_raw:
            target_dir = classify_image_dir(target_raw)
            tokens.append(f"crossproc::dir={self_dir}->{target_dir}")

    # 4. Typed Incoming Interaction Context (Strictly causal: [ts - W, ts])
    net_win = 30_000_000 if proc_base == "firefox.exe" else 300_000_000
    if session.has_netconn(event.process_guid, event.timestamp, window_micros=net_win):
        tokens.append("proc_context::has_netconn")

    # Causal Incoming Cross-Process Interactions onto current process
    incoming = session.get_incoming_crossproc(event.process_guid, event.timestamp, window_micros=30_000_000)
    if incoming:
        tokens.append("ctx::incoming::process_open::present=true")
        tokens.append("ctx::incoming::process_open::direction=incoming")
        for inc_dir, inc_base in incoming:
            inc_fam = get_command_family(inc_base)
            inc_role = dir_to_role(inc_dir)
            tokens.append(f"ctx::incoming::process_open::source_family={inc_fam}")
            tokens.append(f"ctx::incoming::process_open::source_path_role={inc_role}")
            tok_exe = f"ctx::incoming::process_open::source_exe={inc_base}"
            if optc_vocab and tok_exe in optc_vocab:
                tokens.append(tok_exe)

    # 5. Immediate Parent Process Lineage (1-Hop) & OpTC Base Alignment
    ancestors = session.get_ancestors(event.process_guid, max_depth=1)
    p_base = ""
    p_dir = "OTHER"
    if event.parent_path:
        p_base = extract_basename(event.parent_path).lower()
        p_dir = classify_image_dir(event.parent_path)
    elif len(ancestors) >= 1:
        p_base, p_dir, _ = ancestors[0]

    if p_base:
        # OpTC Base name and backwards compatibility name
        tokens.append(f"parent_image_path::basename={p_base}")
        tokens.append(f"parent_image::basename={p_base}")
        tokens.append("ctx::status::has_parent")

        p_fam = get_command_family(p_base)
        p_role = dir_to_role(p_dir)
        tokens.append(f"ctx::parent::family={p_fam}")
        tokens.append(f"ctx::relation::lineage={p_fam}->{actor_fam}")
        tokens.append(f"ctx::parent::path_role={p_role}")
        tokens.append(f"ctx::relation::path={p_role}->{actor_role}")

    return tokens


def canonical_ecar_record(event: CanonicalEvent, session: FileSessionIndex | None = None) -> dict[str, Any]:
    """Convert CanonicalEvent into standard eCAR dictionary for tokenize_record."""
    et = event.event_type
    props = {}
    obj = "process"
    act = "start"

    # Resolve parent image path
    p_path = event.parent_path
    if not p_path and session:
        anc = session.get_ancestors(event.process_guid, max_depth=1)
        if anc and anc[0][2]:
            p_path = anc[0][2]
    if p_path:
        props["parent_image_path"] = p_path

    if et == "PROCESS_START":
        obj = "process"
        act = "start"
        props = {
            "image_path": event.target_path or event.process_path,
            "parent_image_path": event.process_path or p_path,
            "command_line": event.process_cmdline,
        }
    elif et == "PROCESS_END":
        obj = "process"
        act = "terminate"
        props["image_path"] = event.process_path
    elif et == "FILE_WRITE":
        obj = "file"
        act = "write"
        props.update({"image_path": event.process_path, "file_path": event.target_path})
    elif et == "FILE_CREATE":
        obj = "file"
        act = "create"
        props.update({"image_path": event.process_path, "file_path": event.target_path})
    elif et == "FILE_DELETE":
        obj = "file"
        act = "delete"
        props.update({"image_path": event.process_path, "file_path": event.target_path})
    elif et == "REGISTRY_WRITE":
        obj = "registry"
        act = "modify"
        props.update({"image_path": event.process_path, "key": event.target_path})
    elif et == "MODULE_LOAD":
        obj = "module"
        act = "load"
        props.update({"image_path": event.process_path, "module_path": event.target_path})
    elif et == "CROSS_PROCESS":
        obj = "process"
        act = "open"
        props.update({"image_path": event.process_path})
    elif et == "FLOW_START":
        # Network flow events on host
        obj = "flow"
        act = "start"
        props.update({"image_path": event.process_path})

    return {
        "object": obj,
        "action": act,
        "principal": event.username,
        "properties": props,
    }
