"""Label-blind, time-qualified Host/Process backbone. No neural dependencies."""
from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import re
import sqlite3

ROLES = {
    'shell': {'cmd.exe', 'powershell.exe', 'pwsh.exe'},
    'script': {'wscript.exe', 'cscript.exe', 'mshta.exe', 'python.exe', 'python3.exe'},
    'office': {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'},
    'browser': {'chrome.exe', 'firefox.exe', 'iexplore.exe', 'msedge.exe'},
    'service': {'services.exe', 'svchost.exe', 'taskhostw.exe', 'taskeng.exe'},
    'session': {'winlogon.exe', 'userinit.exe', 'explorer.exe', 'lsass.exe'},
    'loader': {'rundll32.exe', 'regsvr32.exe', 'installutil.exe', 'regasm.exe', 'msiexec.exe'},
    'admin': {'schtasks.exe', 'sc.exe', 'net.exe', 'net1.exe', 'wmic.exe', 'psexec.exe'},
    'transfer': {'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'wget.exe', 'ftp.exe'},
}
TRAITS = {
    'encoded': r'(?i)(?:^|\s)-(?:enc|encodedcommand|e)\s',
    'download': r'(?i)downloadstring|downloadfile|invoke-webrequest|\bhttps?://',
    'inline': r'(?i)(?:^|\s)(?:-command|-c|/c)\s',
    'hidden': r'(?i)(?:-windowstyle\s+hidden|-w\s+hidden|\b-nop(?:rofile)?\b)',
    'remote_admin': r'(?i)winrm|invoke-command|enter-pssession|\\\\[^\\\s]+\\admin\$',
}
SERVICES = {22: 'ssh', 53: 'dns', 80: 'web', 443: 'web', 445: 'smb',
            135: 'rpc', 3389: 'rdp', 5985: 'winrm', 5986: 'winrm'}
FACTS = ([f'role={x}' for x in [*ROLES, 'other', 'missing']] +
         [f'location={x}' for x in ['system', 'program_files', 'user', 'temp', 'other', 'missing']] +
         [f'launch={x}' for x in TRAITS] +
         [f'network_service={x}' for x in sorted(set(SERVICES.values()) | {'other'})] +
         [f'network_scope={x}' for x in ['private', 'public', 'loopback', 'other']])
FEATURES = [f'graph::{depth}::{fact}' for depth in ['actor', 'parent', 'grandparent'] for fact in FACTS]
FEATURES += [f'graph::{depth}::{state}' for depth in ['actor', 'parent', 'grandparent']
             for state in ['present', 'missing', 'conflict', 'cycle', 'metadata_missing']]
FEATURES += [f'graph::host::{direction}::{bucket}' for direction in ['out', 'in', 'two_hop_out']
             for bucket in ['zero', 'one', 'two_to_four', 'five_plus']]
FEATURES += [f'graph::host::{s}' for s in ['unresolved_peer', 'ambiguous_ip', 'fanout_capped', 'missing']]
FEATURES += ['graph::event::missing_identity_or_time']
COL = {s: i for i, s in enumerate(FEATURES)}
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def timestamp(value):
    try:
        d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if d.tzinfo is None:
            return None
        delta = d.astimezone(timezone.utc) - EPOCH
        return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    except (TypeError, ValueError, OverflowError):
        return None


def identity(record):
    # File-host is deliberately NOT used as event-host fallback.
    host = str(record.get('hostname') or '').strip().lower().rstrip('.')
    proc = str(record.get('actorID') or '').strip().lower()
    return host, proc, timestamp(record.get('timestamp'))


def image_facts(path):
    p = str(path or '')[:32768].lower().replace('/', '\\')
    name = p.rsplit('\\', 1)[-1]
    role = next((k for k, names in ROLES.items() if name in names), 'other' if p else 'missing')
    location = ('missing' if not p else 'temp' if '\\temp\\' in p else
                'system' if '\\windows\\' in p else 'program_files' if '\\program files' in p else
                'user' if '\\users\\' in p else 'other')
    return {f'role={role}', f'location={location}'}


def launch_facts(command):
    return {f'launch={name}' for name, pattern in TRAITS.items()
            if re.search(pattern, str(command or '')[:32768])}


def address(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def scope(ip):
    a = ipaddress.ip_address(ip)
    return 'loopback' if a.is_loopback else 'public' if a.is_global else 'private' if a.is_private else 'other'


def connect(path, readonly=False):
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) if readonly else sqlite3.connect(path)
    db.execute('PRAGMA cache_size=-32768')
    db.execute('PRAGMA temp_store=FILE')
    if not readonly:
        db.execute('PRAGMA journal_mode=DELETE'); db.execute('PRAGMA synchronous=FULL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS fact(host TEXT, proc TEXT, fact TEXT, t INTEGER, source TEXT, line INTEGER,
            PRIMARY KEY(host,proc,fact)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS parent(host TEXT, child TEXT, parent TEXT, t INTEGER, source TEXT, line INTEGER,
            PRIMARY KEY(host,child,parent)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS binding(ip TEXT, host TEXT, t INTEGER, source TEXT, line INTEGER,
            PRIMARY KEY(ip,host)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS flow(host TEXT, direction TEXT, peer TEXT, t INTEGER, source TEXT, line INTEGER,
            PRIMARY KEY(host,direction,peer)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS target(source TEXT, line INTEGER, host TEXT, proc TEXT, t INTEGER, split INTEGER,
            PRIMARY KEY(source,line)) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS progress(source TEXT PRIMARY KEY, line INTEGER, prefix_sha TEXT, complete INTEGER);
        ''')
    return db


def first(db, table, keys, values, t, source, line):
    names = keys + ['t', 'source', 'line']
    # First-seen facts, with deterministic source/line tie-breaking across unordered files.
    db.execute(f"INSERT INTO {table} ({','.join(names)}) VALUES ({','.join('?' for _ in names)}) "
               f"ON CONFLICT ({','.join(keys)}) DO UPDATE SET t=excluded.t,source=excluded.source,line=excluded.line "
               f"WHERE (excluded.t,excluded.source,excluded.line)<({table}.t,{table}.source,{table}.line)",
               [*values, t, source, line])


def observe(db, record, source, line):
    """Consume only an explicit allowlist. Never read label/ground truth/PID fields."""
    host, actor, t = identity(record)
    if not host or t is None:
        return False
    props = record.get('properties') or {}
    if not isinstance(props, dict):
        return False
    obj, action = str(record.get('object', '')).upper(), str(record.get('action', '')).upper()
    target = str(record.get('objectID') or '').strip().lower()
    observations = []
    if obj == 'PROCESS':
        if action == 'CREATE':
            if actor and target:
                first(db, 'parent', ['host', 'child', 'parent'], [host, target, actor], t, source, line)
            if actor:
                observations.append((actor, image_facts(props.get('parent_image_path'))))
            if target:
                observations.append((target, image_facts(props.get('image_path')) | launch_facts(props.get('command_line'))))
        # OPEN/TERMINATE image fields can describe target, not actor. No ancestry inference.
    elif actor:
        observations.append((actor, image_facts(props.get('image_path'))))
    if obj == 'FLOW':
        direction = str(props.get('direction', '')).lower()
        src, dst = address(props.get('src_ip')), address(props.get('dest_ip'))
        if direction in ('outbound', 'inbound') and src and dst:
            local, peer = (src, dst) if direction == 'outbound' else (dst, src)
            first(db, 'binding', ['ip', 'host'], [local, host], t, source, line)
            first(db, 'flow', ['host', 'direction', 'peer'], [host, direction, peer], t, source, line)
            try:
                port = int(props.get('dest_port'))
            except (TypeError, ValueError):
                port = -1
            if actor:
                observations.append((actor, {f'network_service={SERVICES.get(port, "other")}', f'network_scope={scope(peer)}'}))
    for proc, facts in observations:
        for fact in facts:
            first(db, 'fact', ['host', 'proc', 'fact'], [host, proc, fact], t, source, line)
    return True


def bucket(n):
    return 'zero' if n == 0 else 'one' if n == 1 else 'two_to_four' if n <= 4 else 'five_plus'


class Encoder:
    """Strictly earlier evidence; exact timestamps retain same-second ancestry.

    Max two ancestry edges, max fanout peers per host per hop. No label or split queries.
    """
    def __init__(self, db, fanout=16, quantum_us=1):
        if fanout < 1 or quantum_us < 1:
            raise ValueError('positive fanout and time quantum required')
        self.db, self.fanout, self.quantum = db, fanout, quantum_us
        self.features = lru_cache(maxsize=4096)(self._features)
        self.host_context = lru_cache(maxsize=4096)(self._host_context)

    def encode(self, host, proc, t):
        if not host or not proc or t is None:
            return (COL['graph::event::missing_identity_or_time'],)
        return self.features(host, proc, t // self.quantum * self.quantum)

    def ancestry(self, host, proc, cutoff):
        chain, seen, edges = [('actor', proc, 'present')], {proc}, []
        for depth in ('parent', 'grandparent'):
            candidates = self.db.execute('SELECT parent,t,source,line FROM parent WHERE host=? AND child=? AND t<? ORDER BY parent LIMIT 2',
                                         (host, proc, cutoff)).fetchall()
            if len(candidates) != 1:
                chain.append((depth, '', 'conflict' if candidates else 'missing')); break
            parent, t, source, line = candidates[0]
            if parent in seen:
                chain.append((depth, '', 'cycle')); break
            edges.append(dict(child=proc, parent=parent, timestamp_us=t, source_id=source, source_line=line))
            chain.append((depth, parent, 'present')); seen.add(parent); proc = parent
            cutoff = min(cutoff, t + 1)  # ancestor creation cannot be later than its child's creation
        return chain, edges

    def peers(self, host, direction, cutoff):
        rows = self.db.execute('SELECT peer FROM flow WHERE host=? AND direction=? AND t<? ORDER BY peer LIMIT ?',
                               (host, direction, cutoff, self.fanout + 1)).fetchall()
        flags, peers = set(), set()
        if len(rows) > self.fanout:
            flags.add('fanout_capped')
        for (ip,) in rows[:self.fanout]:
            bindings = self.db.execute('SELECT host FROM binding WHERE ip=? AND t<? ORDER BY host LIMIT 2', (ip, cutoff)).fetchall()
            if len(bindings) == 1:
                if bindings[0][0] != host:
                    peers.add(bindings[0][0])
            else:
                flags.add('ambiguous_ip' if bindings else 'unresolved_peer')
        return peers, flags

    def _host_context(self, host, cutoff):
        outgoing, flags = self.peers(host, 'outbound', cutoff)
        incoming, more = self.peers(host, 'inbound', cutoff); flags |= more
        second = set()
        for peer in sorted(outgoing):
            neighbors, more = self.peers(peer, 'outbound', cutoff); second |= neighbors; flags |= more
        second -= {host}; second -= outgoing
        tokens = {f'graph::host::{name}::{bucket(len(values))}' for name, values in
                  [('out', outgoing), ('in', incoming), ('two_hop_out', second)]}
        tokens |= {f'graph::host::{flag}' for flag in flags}
        if not self.db.execute('SELECT 1 FROM flow WHERE host=? AND t<? LIMIT 1', (host, cutoff)).fetchone():
            tokens.add('graph::host::missing')
        return tokens

    def _features(self, host, proc, cutoff):
        chain, _ = self.ancestry(host, proc, cutoff)
        tokens = set(self.host_context(host, cutoff)); visited = set()
        for depth, node, state in chain:
            visited.add(depth); tokens.add(f'graph::{depth}::{state}')
            if not node:
                continue
            facts = [r[0] for r in self.db.execute('SELECT fact FROM fact WHERE host=? AND proc=? AND t<?', (host, node, cutoff))]
            if not facts:
                tokens.add(f'graph::{depth}::metadata_missing')
            tokens |= {f'graph::{depth}::{fact}' for fact in facts}
        for depth in {'actor', 'parent', 'grandparent'} - visited:
            tokens.add(f'graph::{depth}::missing')
        return tuple(sorted(COL[t] for t in tokens))

    def explain(self, host, proc, t):
        cutoff = t // self.quantum * self.quantum
        chain, edges = self.ancestry(host, proc, cutoff)
        return dict(host=host, actor=proc, cutoff_us=cutoff, ancestors=chain, edges=edges,
                    features=[FEATURES[i] for i in self.encode(host, proc, t)],
                    interpretation='Observed ancestry candidates, not a claim that an ancestor is malicious.')
