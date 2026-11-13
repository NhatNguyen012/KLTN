"""IL dataset export: SOC-verified lab telemetry -> labelled events per model domain (General Architecture: the
`validated datasets` store feeding the Incremental Learning Service).

Labels come only from SOC verification (alert_reviews):
  * attack  : events named in `labels.attack_refs` of a `confirmed` review (raw record ids or host-event keys);
  * benign  : events inside the window of a `false_positive` alert, and baseline events of the same hosts that lie
              outside every alert window (+- 30 min) -- i.e. reviewed-quiet periods;
  * unknown : everything else inside an alert window (not a training row; still replayed for causal context).
Splits are by incident and time, never by random event: per domain the confirmed incidents are ordered in time, the
first 60 % (and the benign time before them) train, the next 20 % validate, the last 20 % test. A domain with fewer
than 3 confirmed incidents, or without attack events in VAL and TEST, cannot be evaluated: it is rejected (gate)
instead of trained blind.
Events the current sensor policy no longer records are left out (`pipeline_event`): the telemetry pipeline's own
connections were audited until the self-exclusion of 2026-11-14 (zz-kltn-sensor.rules, Sysmon v3), so training on
them would teach a distribution the endpoints no longer produce.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

PAD = timedelta(minutes=30)
MIN_INCIDENTS = 3
MIN_ATTACK_EVENTS = 20
MIN_BENIGN_EVENTS = 2000
DOMAINS = ("linux-audit", "windows-sysmon")
_WIN_PIPELINE = ("c:\\kltn\\agent\\", "c:\\kltn\\packages\\fluent-bit\\")


def pipeline_event(domain: str, ev: dict) -> bool:
    """True for an event of the telemetry pipeline itself that the current sensor policy excludes at the source."""
    if domain == "linux-audit":
        return ev.get("kind") == "netconn" and (ev.get("image") == "/opt/fluent-bit/bin/fluent-bit"
                                                 or str(ev.get("cmd") or "").startswith("/opt/kltn-agent/"))
    return ev.get("eid") in (3, 12, 13, 14, 22) and str(ev.get("path") or "").lower().startswith(_WIN_PIPELINE)


def export(conn, query: dict) -> dict:
    t_to = datetime.fromisoformat(query["to"]) if query.get("to") else datetime.now(timezone.utc)
    t_from = datetime.fromisoformat(query["from"]) if query.get("from") else t_to - timedelta(days=30)
    host_domain = dict(conn.execute("SELECT host_id, domain FROM hosts").fetchall())
    reviews = conn.execute('''SELECT DISTINCT ON (r.alert_id) r.alert_id, r.decision, r.labels, a.host_id, a.first_seen, a.last_seen
      FROM alert_reviews r JOIN alerts a ON a.alert_id=r.alert_id WHERE r.created_at BETWEEN %s AND %s
      ORDER BY r.alert_id, r.created_at DESC''', (t_from, t_to)).fetchall()
    windows = defaultdict(list)
    for host, fs, ls in conn.execute('SELECT host_id, first_seen, last_seen FROM alerts WHERE last_seen >= %s AND first_seen <= %s',
                                     (t_from - PAD, t_to + PAD)).fetchall():
        windows[host].append((fs - PAD, ls + PAD))
    attack_refs, fp_windows, incidents = set(), defaultdict(list), defaultdict(list)
    for alert_id, decision, labels, host, fs, ls in reviews:
        if decision == "confirmed":
            refs = set((labels or {}).get("attack_refs", []))
            attack_refs |= refs
            if refs:
                incidents[host_domain.get(host, "unknown")].append(fs)
        elif decision == "false_positive":
            fp_windows[host].append((fs - PAD, ls + PAD))
    out = {"from": t_from.isoformat(), "to": t_to.isoformat(), "domains": {}}
    for domain in DOMAINS:
        inc = sorted(incidents.get(domain, []))
        cuts = (inc[int(0.6 * len(inc))], inc[int(0.8 * len(inc))]) if len(inc) >= MIN_INCIDENTS else None

        def split_of(ts):
            return "train" if cuts is None or ts < cuts[0] else ("val" if ts < cuts[1] else "test")
        rows = conn.execute('''SELECT host_id, event_key, ts, event, raw_refs FROM host_events
          WHERE domain=%s AND ts BETWEEN %s AND %s ORDER BY host_id, ts_us, id''', (domain, t_from, t_to)).fetchall()
        events, stats = [], defaultdict(int)
        for host, key, ts, ev, raw_refs in rows:
            if pipeline_event(domain, ev):
                stats["dropped_pipeline"] += 1
                continue
            if key in attack_refs or any(r in attack_refs for r in raw_refs or ()):
                y = 1
            elif any(a <= ts <= b for a, b in fp_windows.get(host, ())) or not any(a <= ts <= b for a, b in windows.get(host, ())):
                y = 0
            else:
                y = -1
            sp = split_of(ts)
            events.append({"host": host, "key": key, "ts": ts, "event": ev, "y": y, "split": sp})
            stats[f"{sp}_{ {1: 'attack', 0: 'benign', -1: 'unknown'}[y] }"] += 1
        gate = {"incidents": len(inc) >= MIN_INCIDENTS,
                "attack_events": sum(v for k, v in stats.items() if k.endswith("_attack")) >= MIN_ATTACK_EVENTS,
                "benign_events": sum(v for k, v in stats.items() if k.endswith("_benign")) >= MIN_BENIGN_EVENTS,
                "val_and_test_attacks": stats.get("val_attack", 0) > 0 and stats.get("test_attack", 0) > 0}
        out["domains"][domain] = {"events": events, "stats": dict(stats), "incidents": len(inc), "gate": gate,
                                  "trainable": all(gate.values())}
    return out
