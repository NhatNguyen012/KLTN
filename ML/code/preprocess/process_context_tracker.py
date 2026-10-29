#!/usr/bin/env python3
"""Host Process & Parent Context Tracker for OpTC Host ML Feature Enrichment.

Maintains bounded in-memory causal process state per host, resolving actor and
parent context with strict temporal anti-leakage (evidence strictly < event t).
Supports deterministic LRU and TTL eviction, strict UUID identity, and opt-in
PID lifecycle tracking.

Zero label leakage: does not use ground-truth labels, future descendants,
or author propagation windows.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping

from ML.code.preprocess.command_syntax import Lexeme, MAX_LEXEMES, inline_remainder, lex
from ML.code.preprocess.ecar_tokenizer import (
    COMMAND_FAMILIES,
    _basename_windows,
    _command_tokens,
    _compact_path_tokens,
    normalize_literals,
    token_rejection_reason,
    tokenize_principal,
    tokenize_record,
)
from ML.code.preprocess.pipeline_contract import validate_output_path

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def canonical_host(value: Any) -> str:
    """Normalize event hostname to canonical lowercase host stem."""
    if not isinstance(value, str) or not value.strip():
        return ""
    host = value.strip().casefold().rstrip(".")
    return host.split(".")[0]


def canonical_uuid(value: Any) -> str:
    """Normalize process UUID, returning empty string if missing or invalid."""
    if not isinstance(value, str):
        return ""
    val = value.strip().lower()
    if val in {"", "null", "none", "00000000-0000-0000-0000-000000000000"}:
        return ""
    return val


def parse_timestamp(value: Any) -> int | None:
    """Parse ISO 8601 string or numeric timestamp to integer microseconds since UTC epoch."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        s = str(value).replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            return None
        delta = d.astimezone(timezone.utc) - EPOCH
        return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    except (TypeError, ValueError, OverflowError):
        return None


def age_bucket(delta_seconds: float) -> str:
    """Map elapsed seconds into finite non-linear buckets."""
    if delta_seconds < 0:
        return "negative"
    if delta_seconds < 1.0:
        return "lt_1s"
    if delta_seconds < 10.0:
        return "lt_10s"
    if delta_seconds < 60.0:
        return "lt_1m"
    if delta_seconds < 300.0:
        return "lt_5m"
    if delta_seconds < 900.0:
        return "lt_15m"
    if delta_seconds < 3600.0:
        return "lt_1h"
    return "gt_1h"


@dataclass
class ProcessNode:
    uuid: str
    host: str
    created_t: int | None = None
    image_path: str = ""
    image_t: int | None = None
    command_line: str = ""
    command_t: int | None = None
    principal: str = ""
    principal_t: int | None = None
    last_seen_t: int = 0
    recent_actions: list[tuple[str, int]] = field(default_factory=list)
    parent_edges: list[tuple[str, int]] = field(default_factory=list)
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "host": self.host,
            "created_t": self.created_t,
            "image_path": self.image_path,
            "image_t": self.image_t,
            "command_line": self.command_line,
            "command_t": self.command_t,
            "principal": self.principal,
            "principal_t": self.principal_t,
            "last_seen_t": self.last_seen_t,
            "recent_actions": list(self.recent_actions),
            "parent_edges": list(self.parent_edges),
            "pid": self.pid,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProcessNode:
        edges = data.get("parent_edges")
        if edges is None:
            edges = []
            if data.get("parent_uuid") and data.get("parent_edge_t") is not None:
                edges.append((data["parent_uuid"], data["parent_edge_t"]))
        return cls(
            uuid=data["uuid"],
            host=data["host"],
            created_t=data.get("created_t"),
            image_path=data.get("image_path", ""),
            image_t=data.get("image_t"),
            command_line=data.get("command_line", ""),
            command_t=data.get("command_t"),
            principal=data.get("principal", ""),
            principal_t=data.get("principal_t"),
            last_seen_t=data.get("last_seen_t", 0),
            recent_actions=[(item[0], item[1]) for item in data.get("recent_actions", [])],
            parent_edges=[(item[0], item[1]) for item in edges],
            pid=data.get("pid"),
        )


@dataclass
class ProcessContextConfig:
    enabled: bool = True
    max_processes_per_host: int = 10_000
    ttl_seconds: float = 86_400.0
    enable_pid_fallback: bool = False
    max_recent_actions: int = 8
    time_policy: str = "strictly_before_t"
    identity_policy: str = "canonical_hostname_plus_uuid"
    field_ownership: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.max_processes_per_host < 1:
            raise ValueError("max_processes_per_host must be positive")
        if not math.isfinite(self.ttl_seconds) or self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a finite positive number")
        if self.max_recent_actions < 1:
            raise ValueError("max_recent_actions must be positive")
        if self.enable_pid_fallback:
            raise ValueError("PID fallback is not supported under strict UUID policy; omit flag or pass False")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> ProcessContextConfig:
        if not data:
            return cls(enabled=False)
        from dataclasses import fields as dc_fields
        field_names = {f.name for f in dc_fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in field_names}
        return cls(**kwargs)


MAX_COMMAND_LINE_LEN = 4096
MAX_IMAGE_PATH_LEN = 1024
MAX_PRINCIPAL_LEN = 256
MAX_PARENT_EDGES = 8

CONTEXT_PIPELINE_FILES = (
    'process_context_tracker.py',
    'stratified_pipeline.py',
    'ecar_tokenizer.py',
    'command_syntax.py',
    'pipeline_contract.py',
)


class HostProcessContextTracker:
    """Maintains bounded, causally safe process and ancestry state per host."""

    def __init__(self, config: ProcessContextConfig | None = None):
        self.config = config or ProcessContextConfig()
        # host -> {proc_uuid -> ProcessNode}
        self.hosts: dict[str, dict[str, ProcessNode]] = {}
        # host -> deque of evicted UUIDs (capped at 2000) for distinguishing expired vs never seen
        self.evicted_uuids: dict[str, deque[str]] = {}
        # host -> {pid -> (proc_uuid, create_t)} for opt-in PID fallback tracking
        self.pid_tracker: dict[str, dict[int, tuple[str, int]]] = {}
        # host -> last event timestamp in microseconds for cross-file temporal boundary monotonicity
        self.host_watermarks: dict[str, int] = {}
        # Conservative lower bound on the next possible TTL expiry, not canonical state.
        # It may be stale EARLY after touches/eviction, never late. Rebuilt after load.
        self._expiry_floor: dict[str, int | None] = {}

        # Statistical counters for audits and manifests
        self.stats: dict[str, int] = {
            "query_count": 0,
            "has_actor_metadata": 0,
            "actor_metadata_missing": 0,
            "actor_uuid_missing": 0,
            "has_parent": 0,
            "parent_missing": 0,
            "parent_conflict": 0,
            "actor_expired": 0,
            "evicted_count": 0,
            "pid_reuse_conflict_count": 0,
        }

    def get_watermark(self, host: str) -> int | None:
        """Return the latest causal event timestamp recorded for host, or None."""
        h = canonical_host(host)
        return self.host_watermarks.get(h)

    def set_watermark(self, host: str, t: int) -> None:
        """Update the causal temporal watermark for host to monotonic timestamp t."""
        h = canonical_host(host)
        if h and t is not None:
            self.host_watermarks[h] = int(t)

    def _get_host_processes(self, host: str) -> dict[str, ProcessNode]:
        if host not in self.hosts:
            self.hosts[host] = {}
            self.evicted_uuids[host] = deque(maxlen=2000)
            self.pid_tracker[host] = {}
        return self.hosts[host]

    def _prune_if_needed(self, host: str, current_t: int | None = None) -> None:
        procs = self._get_host_processes(host)
        ttl_us = int(self.config.ttl_seconds * 1_000_000)

        # 1. Prune by TTL if current_t is available
        floor = self._expiry_floor.get(host)
        if current_t is not None and ttl_us > 0 and (floor is None or current_t > floor):
            cutoff = current_t - ttl_us
            expired_keys = [
                uuid for uuid, node in procs.items()
                if node.last_seen_t < cutoff
            ]
            for key in expired_keys:
                del procs[key]
                self.evicted_uuids[host].append(key)
                self.stats["evicted_count"] += 1

            # Prune pid_tracker by TTL based on process creation timestamp (create_t)
            # Semantics distinction:
            # - ProcessNode TTL: Pruned based on `last_seen_t` (activity window). As long as a process
            #   remains active, its context node is preserved.
            # - PID Tracker TTL: Pruned based on `create_t` (creation timestamp). The pid_tracker maps
            #   `pid -> (proc_uuid, create_t)` to detect OS PID recycling across processes.
            #   It expires `ttl_seconds` after the CREATE event, bounding memory for historical PIDs.
            #   Audit limit: If the OS reassigns a PID after a duration greater than `ttl_seconds`
            #   since the initial CREATE, the tracker will not detect the collision (pid_reuse_conflict_count
            #   will not increment) because the old binding was pruned by TTL.
            if host in self.pid_tracker:
                expired_pids = [
                    pid for pid, (_, pt) in self.pid_tracker[host].items()
                    if pt < cutoff
                ]
                for pid in expired_pids:
                    del self.pid_tracker[host][pid]

            next_times = [node.last_seen_t for node in procs.values()]
            next_times.extend(t for _, t in self.pid_tracker.get(host, {}).values())
            self._expiry_floor[host] = min(next_times) + ttl_us if next_times else None

        # 2. Prune by capacity (LRU by last_seen_t)
        max_cap = self.config.max_processes_per_host
        if len(procs) > max_cap:
            over = len(procs) - max_cap
            sorted_keys = sorted(procs.keys(), key=lambda k: procs[k].last_seen_t)
            to_evict = sorted_keys[:over]
            for key in to_evict:
                del procs[key]
                self.evicted_uuids[host].append(key)
                self.stats["evicted_count"] += 1

        # Prune pid_tracker by capacity consistently
        if host in self.pid_tracker and len(self.pid_tracker[host]) > max_cap:
            over = len(self.pid_tracker[host]) - max_cap
            sorted_pids = sorted(self.pid_tracker[host].keys(), key=lambda p: self.pid_tracker[host][p][1])
            for pid in sorted_pids[:over]:
                del self.pid_tracker[host][pid]

    def _finalize_tokens(self, tokens: list[str]) -> list[str]:
        valid_tokens: list[str] = []
        for t in tokens:
            reason = token_rejection_reason(t)
            if not reason:
                valid_tokens.append(t)
        return valid_tokens

    def get_context_tokens(self, record: Mapping[str, Any], query_t: int | None = None) -> list[str]:
        """Extract actor and parent context tokens strictly earlier than query_t (< query_t)."""
        if not self.config.enabled:
            return []

        self.stats["query_count"] += 1
        host = canonical_host(record.get("hostname"))
        actor_uuid = canonical_uuid(record.get("actorID"))

        if query_t is None:
            query_t = parse_timestamp(record.get("timestamp"))

        if query_t is None:
            return ["ctx::status::missing_timestamp"]

        if not host or not actor_uuid:
            self.stats["actor_uuid_missing"] += 1
            self.stats["parent_missing"] += 1
            return ["ctx::status::actor_uuid_missing", "ctx::status::parent_missing"]

        procs = self._get_host_processes(host)
        actor_node = procs.get(actor_uuid)

        raw_object = record.get("object")
        object_type = raw_object.strip().casefold() if isinstance(raw_object, str) else ""
        raw_action = record.get("action")
        action = raw_action.strip().casefold() if isinstance(raw_action, str) else ""
        is_create = (object_type == "process" and action == "create")

        tokens: list[str] = []

        # 1. Resolve Actor Process
        if actor_node is None:
            if actor_uuid in self.evicted_uuids[host]:
                tokens.append("ctx::status::actor_expired")
                self.stats["actor_expired"] += 1
            tokens.append("ctx::status::actor_metadata_missing")
            tokens.append("ctx::status::parent_missing")
            self.stats["actor_metadata_missing"] += 1
            self.stats["parent_missing"] += 1
            if is_create:
                tokens.append("ctx::relation::actor_is_parent_of_target=true")
            return self._finalize_tokens(tokens)

        # Active TTL check at query time
        ttl_us = int(self.config.ttl_seconds * 1_000_000)
        if ttl_us > 0 and actor_node.last_seen_t > 0 and (query_t - actor_node.last_seen_t) > ttl_us:
            tokens.append("ctx::status::actor_expired")
            tokens.append("ctx::status::parent_missing")
            self.stats["actor_expired"] += 1
            self.stats["parent_missing"] += 1
            if is_create:
                tokens.append("ctx::relation::actor_is_parent_of_target=true")
            return self._finalize_tokens(tokens)

        # Actor exists in tracker. Check if any metadata existed strictly before query_t
        has_prior_actor_evidence = False
        actor_exe = ""
        actor_path_role = ""
        actor_family = ""
        actor_principal_class = ""

        # Image evidence < query_t
        if actor_node.image_path and actor_node.image_t is not None and actor_node.image_t < query_t:
            has_prior_actor_evidence = True
            for path_tok in _compact_path_tokens("image_path", actor_node.image_path, True):
                if "::basename=" in path_tok:
                    actor_exe = path_tok.split("::basename=")[-1]
                    tokens.append(f"ctx::actor::exe={actor_exe}")
                elif "::category=" in path_tok:
                    actor_path_role = path_tok.split("::category=")[-1]
                    tokens.append(f"ctx::actor::path_role={actor_path_role}")
            base = normalize_literals(_basename_windows(actor_node.image_path))
            for fam in COMMAND_FAMILIES:
                if fam in base:
                    actor_family = fam
                    break
            if not actor_family:
                actor_family = "native"
            tokens.append(f"ctx::actor::family={actor_family}")

        # Command-line evidence < query_t
        if actor_node.command_line and actor_node.command_t is not None and actor_node.command_t < query_t:
            has_prior_actor_evidence = True
            family, cmd_tokens, _ = _command_tokens(actor_node.command_line, actor_node.image_path)
            tokens.append(f"ctx::actor::cmd_family={family}")
            for cmd_tok in cmd_tokens:
                if "::switch=" in cmd_tok:
                    switch_name = cmd_tok.split("::switch=")[-1]
                    tokens.append(f"ctx::actor::switch={switch_name}")
                elif "::anchor::launcher=" in cmd_tok:
                    launcher_name = cmd_tok.split("::anchor::launcher=")[-1]
                    tokens.append(f"ctx::actor::launcher={launcher_name}")
                elif "::cmd::mode=" in cmd_tok:
                    mode_val = cmd_tok.split("::cmd::mode=")[-1]
                    tokens.append(f"ctx::actor::cmd_mode={mode_val}")

        # Principal evidence < query_t
        if actor_node.principal and actor_node.principal_t is not None and actor_node.principal_t < query_t:
            has_prior_actor_evidence = True
            p_tokens = tokenize_principal(actor_node.principal)
            for p_tok in p_tokens:
                if p_tok.startswith("principal::"):
                    actor_principal_class = p_tok.split("principal::")[-1]
                    tokens.append(f"ctx::actor::principal={actor_principal_class}")

        # Age < query_t
        if actor_node.created_t is not None and actor_node.created_t < query_t:
            has_prior_actor_evidence = True
            delta_s = (query_t - actor_node.created_t) / 1_000_000.0
            tokens.append(f"ctx::actor::age={age_bucket(delta_s)}")

        # Recent actions < query_t
        valid_actions = [act for act, act_t in actor_node.recent_actions if act_t < query_t]
        for act in valid_actions[-self.config.max_recent_actions:]:
            has_prior_actor_evidence = True
            tokens.append(f"ctx::actor::recent_action={act}")

        if has_prior_actor_evidence:
            tokens.append("ctx::status::has_actor_metadata")
            self.stats["has_actor_metadata"] += 1
        else:
            tokens.append("ctx::status::actor_metadata_missing")
            self.stats["actor_metadata_missing"] += 1

        # 2. Resolve Parent Process of Actor strictly before query_t
        valid_parent_edges = [(p_uuid, edge_t) for p_uuid, edge_t in actor_node.parent_edges if edge_t < query_t]
        unique_parents = sorted(set(p_uuid for p_uuid, edge_t in valid_parent_edges))

        if len(unique_parents) > 1:
            # Causal Parent Conflict as of query_t: fail-closed, suppress parent metadata
            tokens.append("ctx::status::parent_conflict")
            self.stats["parent_conflict"] += 1
        elif len(unique_parents) == 1:
            parent_uuid = unique_parents[0]
            parent_edge_t = min(edge_t for p_uuid, edge_t in valid_parent_edges if p_uuid == parent_uuid)
            parent_node = procs.get(parent_uuid)
            if parent_node is None:
                if parent_uuid in self.evicted_uuids[host]:
                    tokens.append("ctx::status::parent_expired")
                tokens.append("ctx::status::parent_missing")
                self.stats["parent_missing"] += 1
            elif ttl_us > 0 and parent_node.last_seen_t > 0 and (query_t - parent_node.last_seen_t) > ttl_us:
                tokens.append("ctx::status::parent_missing")
                self.stats["parent_missing"] += 1
            else:
                has_prior_parent_evidence = False
                parent_exe = ""
                parent_path_role = ""
                parent_family = ""
                parent_principal_class = ""

                # Parent Image < query_t
                if parent_node.image_path and parent_node.image_t is not None and parent_node.image_t < query_t:
                    has_prior_parent_evidence = True
                    for path_tok in _compact_path_tokens("image_path", parent_node.image_path, True):
                        if "::basename=" in path_tok:
                            parent_exe = path_tok.split("::basename=")[-1]
                            tokens.append(f"ctx::parent::exe={parent_exe}")
                        elif "::category=" in path_tok:
                            parent_path_role = path_tok.split("::category=")[-1]
                            tokens.append(f"ctx::parent::path_role={parent_path_role}")
                    base = normalize_literals(_basename_windows(parent_node.image_path))
                    for fam in COMMAND_FAMILIES:
                        if fam in base:
                            parent_family = fam
                            break
                    if not parent_family:
                        parent_family = "native"
                    tokens.append(f"ctx::parent::family={parent_family}")

                # Parent Command Line < query_t
                if parent_node.command_line and parent_node.command_t is not None and parent_node.command_t < query_t:
                    has_prior_parent_evidence = True
                    p_family, p_cmd_tokens, _ = _command_tokens(parent_node.command_line, parent_node.image_path)
                    tokens.append(f"ctx::parent::cmd_family={p_family}")
                    for cmd_tok in p_cmd_tokens:
                        if "::switch=" in cmd_tok:
                            switch_name = cmd_tok.split("::switch=")[-1]
                            tokens.append(f"ctx::parent::switch={switch_name}")
                        elif "::anchor::launcher=" in cmd_tok:
                            launcher_name = cmd_tok.split("::anchor::launcher=")[-1]
                            tokens.append(f"ctx::parent::launcher={launcher_name}")
                        elif "::cmd::mode=" in cmd_tok:
                            mode_val = cmd_tok.split("::cmd::mode=")[-1]
                            tokens.append(f"ctx::parent::cmd_mode={mode_val}")

                # Parent Principal < query_t
                if parent_node.principal and parent_node.principal_t is not None and parent_node.principal_t < query_t:
                    has_prior_parent_evidence = True
                    p_tokens = tokenize_principal(parent_node.principal)
                    for p_tok in p_tokens:
                        if p_tok.startswith("principal::"):
                            parent_principal_class = p_tok.split("principal::")[-1]
                            tokens.append(f"ctx::parent::principal={parent_principal_class}")

                # Parent Age < query_t
                if parent_node.created_t is not None and parent_node.created_t < query_t:
                    has_prior_parent_evidence = True
                    delta_s = (query_t - parent_node.created_t) / 1_000_000.0
                    tokens.append(f"ctx::parent::age={age_bucket(delta_s)}")

                # Parent Recent Actions < query_t
                parent_valid_actions = [act for act, act_t in parent_node.recent_actions if act_t < query_t]
                for act in parent_valid_actions[-self.config.max_recent_actions:]:
                    has_prior_parent_evidence = True
                    tokens.append(f"ctx::parent::recent_action={act}")

                if has_prior_parent_evidence or (parent_edge_t < query_t):
                    tokens.append("ctx::status::has_parent")
                    self.stats["has_parent"] += 1
                else:
                    tokens.append("ctx::status::parent_missing")
                    self.stats["parent_missing"] += 1

                # 3. Inter-process Lineage & Relations
                if parent_family and actor_family:
                    tokens.append(f"ctx::relation::lineage={parent_family}->{actor_family}")
                if parent_path_role and actor_path_role:
                    tokens.append(f"ctx::relation::path={parent_path_role}->{actor_path_role}")
                if parent_principal_class and actor_principal_class:
                    same = "true" if parent_principal_class == actor_principal_class else "false"
                    tokens.append(f"ctx::relation::same_principal_class={same}")

                if parent_edge_t is not None and parent_edge_t < query_t:
                    delta_spawn = (query_t - parent_edge_t) / 1_000_000.0
                    tokens.append(f"ctx::relation::spawn_recency={age_bucket(delta_spawn)}")
        else:
            tokens.append("ctx::status::parent_missing")
            self.stats["parent_missing"] += 1

        # 4. Target Event Semantics
        if is_create:
            tokens.append("ctx::relation::actor_is_parent_of_target=true")

        return self._finalize_tokens(tokens)

    def observe(self, record: Mapping[str, Any], event_t: int | None = None) -> None:
        """Update tracker state with evidence from the current event, strictly after feature generation."""
        if not self.config.enabled:
            return

        host = canonical_host(record.get("hostname"))
        actor_uuid = canonical_uuid(record.get("actorID"))

        if event_t is None:
            event_t = parse_timestamp(record.get("timestamp"))

        if not host or event_t is None:
            return

        procs = self._get_host_processes(host)
        # Prune expired nodes before updating state using causal clock
        self._prune_if_needed(host, event_t)
        ttl_us = int(self.config.ttl_seconds * 1_000_000)

        raw_object = record.get("object")
        object_type = raw_object.strip().casefold() if isinstance(raw_object, str) else ""
        raw_action = record.get("action")
        action = raw_action.strip().casefold() if isinstance(raw_action, str) else ""

        raw_props = record.get("properties")
        props = raw_props if isinstance(raw_props, Mapping) else {}

        # 1. PROCESS CREATE:
        # actorID is the parent creating the child.
        # objectID is the newly created child process.
        if object_type == "process" and action == "create":
            child_uuid = canonical_uuid(record.get("objectID"))

            # Update Parent Actor
            if actor_uuid:
                parent_node = procs.get(actor_uuid)
                if parent_node is not None and ttl_us > 0 and (event_t - parent_node.last_seen_t) > ttl_us:
                    del procs[actor_uuid]
                    self.evicted_uuids[host].append(actor_uuid)
                    self.stats["evicted_count"] += 1
                    parent_node = None
                if parent_node is None:
                    parent_node = ProcessNode(uuid=actor_uuid, host=host, last_seen_t=event_t)
                    procs[actor_uuid] = parent_node
                else:
                    parent_node.last_seen_t = max(parent_node.last_seen_t, event_t)

                # Parent image from parent_image_path on CREATE (bounded length)
                parent_img = props.get("parent_image_path")
                if isinstance(parent_img, str) and parent_img.strip():
                    img_clean = parent_img.strip()[:MAX_IMAGE_PATH_LEN]
                    if not parent_node.image_path or (parent_node.image_t is None or event_t < parent_node.image_t):
                        parent_node.image_path = img_clean
                        parent_node.image_t = event_t

                # Add to recent actions (bounded length)
                parent_node.recent_actions.append(("PROCESS_CREATE", event_t))
                if len(parent_node.recent_actions) > self.config.max_recent_actions * 2:
                    parent_node.recent_actions.pop(0)

            # Update Child Node
            if child_uuid:
                child_node = procs.get(child_uuid)
                if child_node is not None and ttl_us > 0 and (event_t - child_node.last_seen_t) > ttl_us:
                    del procs[child_uuid]
                    self.evicted_uuids[host].append(child_uuid)
                    self.stats["evicted_count"] += 1
                    child_node = None
                if child_node is None:
                    child_node = ProcessNode(
                        uuid=child_uuid,
                        host=host,
                        created_t=event_t,
                        last_seen_t=event_t,
                        parent_edges=[(actor_uuid, event_t)] if actor_uuid else [],
                    )
                    procs[child_uuid] = child_node
                else:
                    child_node.last_seen_t = max(child_node.last_seen_t, event_t)
                    if child_node.created_t is None or event_t < child_node.created_t:
                        child_node.created_t = event_t
                    if actor_uuid:
                        existing = next((pe for pe in child_node.parent_edges if pe[0] == actor_uuid), None)
                        if existing is None:
                            if len(child_node.parent_edges) < MAX_PARENT_EDGES:
                                child_node.parent_edges.append((actor_uuid, event_t))
                        elif event_t < existing[1]:
                            child_node.parent_edges.remove(existing)
                            child_node.parent_edges.append((actor_uuid, event_t))

                # Set child launch metadata from properties (bounded length)
                child_img = props.get("image_path")
                if isinstance(child_img, str) and child_img.strip():
                    img_clean = child_img.strip()[:MAX_IMAGE_PATH_LEN]
                    if not child_node.image_path or (child_node.image_t is None or event_t < child_node.image_t):
                        child_node.image_path = img_clean
                        child_node.image_t = event_t

                child_cmd = props.get("command_line")
                if isinstance(child_cmd, str) and child_cmd.strip():
                    cmd_clean = child_cmd.strip()[:MAX_COMMAND_LINE_LEN]
                    if not child_node.command_line or (child_node.command_t is None or event_t < child_node.command_t):
                        child_node.command_line = cmd_clean
                        child_node.command_t = event_t

                princ = record.get("principal")
                if isinstance(princ, str) and princ.strip():
                    princ_clean = princ.strip()[:MAX_PRINCIPAL_LEN]
                    if not child_node.principal or (child_node.principal_t is None or event_t < child_node.principal_t):
                        child_node.principal = princ_clean
                        child_node.principal_t = event_t

                raw_pid = record.get("pid") if record.get("pid") is not None else props.get("pid")
                if raw_pid is not None:
                    try:
                        pid_int = int(raw_pid)
                        child_node.pid = pid_int
                        if host in self.pid_tracker and pid_int in self.pid_tracker[host]:
                            prior_uuid, prior_t = self.pid_tracker[host][pid_int]
                            if prior_uuid != child_uuid and prior_t < event_t:
                                self.stats["pid_reuse_conflict_count"] += 1
                        self.pid_tracker[host][pid_int] = (child_uuid, event_t)
                    except (ValueError, TypeError):
                        pass

        # 2. Non-CREATE events (FILE, MODULE, REGISTRY, SHELL, THREAD, PROCESS OPEN, etc.)
        elif actor_uuid:
            actor_node = procs.get(actor_uuid)
            if actor_node is not None and ttl_us > 0 and (event_t - actor_node.last_seen_t) > ttl_us:
                del procs[actor_uuid]
                self.evicted_uuids[host].append(actor_uuid)
                self.stats["evicted_count"] += 1
                actor_node = None
            if actor_node is None:
                actor_node = ProcessNode(uuid=actor_uuid, host=host, last_seen_t=event_t)
                procs[actor_uuid] = actor_node
            else:
                actor_node.last_seen_t = max(actor_node.last_seen_t, event_t)

            # If image_path is present and missing on actor_node
            img = props.get("image_path")
            if isinstance(img, str) and img.strip():
                img_clean = img.strip()[:MAX_IMAGE_PATH_LEN]
                if not actor_node.image_path or (actor_node.image_t is None or event_t < actor_node.image_t):
                    actor_node.image_path = img_clean
                    actor_node.image_t = event_t

            princ = record.get("principal")
            if isinstance(princ, str) and princ.strip():
                princ_clean = princ.strip()[:MAX_PRINCIPAL_LEN]
                if not actor_node.principal or (actor_node.principal_t is None or event_t < actor_node.principal_t):
                    actor_node.principal = princ_clean
                    actor_node.principal_t = event_t

            # Record action in recent actions
            action_tag = f"{object_type.upper()}_{action.upper()}"
            actor_node.recent_actions.append((action_tag, event_t))
            if len(actor_node.recent_actions) > self.config.max_recent_actions * 2:
                actor_node.recent_actions.pop(0)

        # Any newly inserted timestamp is >= event_t (touches use max). Keeping an
        # earlier deadline is safe; exact expiry and original eviction order are preserved.
        floor = self._expiry_floor.get(host)
        deadline = event_t + ttl_us
        self._expiry_floor[host] = deadline if floor is None else min(floor, deadline)
        self._prune_if_needed(host, event_t)

    def save_checkpoint(self, path: Path) -> None:
        """Atomically persist tracker state to disk outside data roots."""
        path = validate_output_path(Path(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        from ML.code.preprocess.pipeline_contract import code_hashes
        from dataclasses import asdict
        data = {
            "schema_version": 3,
            "config": asdict(self.config),
            "code_hashes": code_hashes(CONTEXT_PIPELINE_FILES),
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "stats": dict(self.stats),
            "watermarks": dict(self.host_watermarks),
            "hosts": {
                host: {uuid: node.to_dict() for uuid, node in procs.items()}
                for host, procs in self.hosts.items()
            },
            "evicted_uuids": {
                host: list(evicted) for host, evicted in self.evicted_uuids.items()
            },
            "pid_tracker": {
                host: {str(pid): [uuid, t] for pid, (uuid, t) in self.pid_tracker.get(host, {}).items()}
                for host in self.hosts
            },
        }
        temp = validate_output_path(path.with_name(f".{path.name}.{os.getpid()}.tmp"))
        with temp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)

    def load_checkpoint(self, path: Path) -> None:
        """Restore tracker state from an existing checkpoint with strict compatibility checks."""
        p = Path(path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"checkpoint file not found: {p}")
        data = json.loads(p.read_text(encoding="utf-8"))
        schema_v = data.get("schema_version")
        if schema_v != 3:
            raise ValueError(
                f"unsupported checkpoint schema version: {schema_v}; expected 3 (PID audit tracking). "
                "Schema v2 lacks PID tracking history; migration/rebuild required."
            )

        from ML.code.preprocess.pipeline_contract import code_hashes
        from dataclasses import asdict

        expected_hashes = code_hashes(CONTEXT_PIPELINE_FILES)
        saved_hashes = data.get("code_hashes", {})
        for f, expected_h in expected_hashes.items():
            if saved_hashes.get(f) != expected_h:
                raise ValueError(f"checkpoint code_hashes mismatch for {f}: saved={saved_hashes.get(f)}, current={expected_h}")

        current_cfg = asdict(self.config)
        saved_cfg = data.get("config", {})
        for k, v in current_cfg.items():
            if k not in saved_cfg:
                raise ValueError(f"checkpoint configuration missing key: {k}")
            if saved_cfg[k] != v:
                raise ValueError(f"checkpoint configuration mismatch for {k}: saved={saved_cfg[k]}, current={v}")

        self._expiry_floor = {}  # Recompute from canonical loaded state on first observe.
        self.stats = dict(data.get("stats", {}))
        self.host_watermarks = {
            canonical_host(host): int(t)
            for host, t in data.get("watermarks", {}).items()
            if canonical_host(host)
        }
        self.hosts = {}
        for host, procs_data in data.get("hosts", {}).items():
            self.hosts[host] = {
                uuid: ProcessNode.from_dict(node_dict)
                for uuid, node_dict in procs_data.items()
            }
        self.evicted_uuids = {}
        for host, evicted_list in data.get("evicted_uuids", {}).items():
            self.evicted_uuids[host] = deque(evicted_list, maxlen=2000)

        # Restore PID audit tracking state (Schema v3 strictly requires pid_tracker mapping for all loaded hosts)
        if "pid_tracker" not in data or not isinstance(data["pid_tracker"], dict):
            raise ValueError(
                "checkpoint missing required 'pid_tracker' section for Schema v3; "
                "cannot silently discard PID audit history."
            )

        raw_pid_tracker = data["pid_tracker"]
        self.pid_tracker = {}
        for host in self.hosts:
            if host not in raw_pid_tracker:
                raise ValueError(
                    f"checkpoint missing required pid_tracker mapping for host '{host}' in Schema v3; "
                    "cannot silently default to empty PID tracking state."
                )
            pids_data = raw_pid_tracker[host]
            if not isinstance(pids_data, dict):
                raise ValueError(f"invalid pid_tracker dictionary for host '{host}' in Schema v3")
            self.pid_tracker[host] = {
                int(pid_str): (item[0], int(item[1]))
                for pid_str, item in pids_data.items()
            }


def tokenize_record_with_context(
    record: Mapping[str, Any],
    tracker: HostProcessContextTracker | None = None,
    query_t: int | None = None,
    update_tracker: bool = False,
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Tokenize record, appending causally bounded actor and parent context tokens."""
    grouped, audit = tokenize_record(record)
    if not audit.get("eligible"):
        if update_tracker and tracker is not None and tracker.config.enabled:
            tracker.observe(record, event_t=query_t)
        return grouped, audit
    if tracker is not None and tracker.config.enabled:
        ctx_tokens = tracker.get_context_tokens(record, query_t=query_t)
        grouped["structure_semantic"].extend(ctx_tokens)
        if update_tracker:
            tracker.observe(record, event_t=query_t)
    return grouped, audit
