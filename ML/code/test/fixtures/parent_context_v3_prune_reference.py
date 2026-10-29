# Frozen v3 pruning reference before optimization. Source SHA256: 8f4b34ea5ad7f2f29bc9a9d2a5f76f41b25c9d116d0cb5ccea8bcab4174bba89
def _prune_if_needed(self, host: str, current_t: int | None = None) -> None:
    procs = self._get_host_processes(host)
    ttl_us = int(self.config.ttl_seconds * 1_000_000)

    # 1. Prune by TTL if current_t is available
    if current_t is not None and ttl_us > 0:
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
