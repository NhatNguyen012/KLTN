"""Bounded host context for one tree detector; no labels or network attributes.

Observe source rows BEFORE cohort selection. Query only already-observed events
with earlier timestamps; equal-timestamp events are conservatively excluded.
Raw process UUIDs and paths are internal join keys, never emitted as tokens.
"""
from bisect import bisect_left, bisect_right, insort
from collections import OrderedDict, Counter
from functools import lru_cache
from .common_schema import classify_image_dir, classify_system_resource, extract_basename

FAMILIES = ('browser', 'shell', 'interpreter', 'service', 'native', 'unknown')
ACTIVITIES = ('read_auth', 'read_process', 'read_inventory', 'write_config',
              'write_user', 'write_temp', 'write_other', 'exec', 'spawn', 'ipc')
WINDOWS = (30, 300)
COUNTS = ('1', '2_3', '4_7', '8_plus')


@lru_cache(maxsize=8192)
def family(path):
    name = extract_basename(path).lower().removesuffix('.exe')
    if not name:
        return 'unknown'
    if name in ('firefox', 'chrome', 'chromium', 'iexplore', 'msedge'):
        return 'browser'
    if name in ('sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'cmd', 'powershell', 'pwsh'):
        return 'shell'
    if name.startswith(('python', 'perl', 'ruby')) or name in ('node', 'java', 'wscript', 'cscript'):
        return 'interpreter'
    if name in ('sshd', 'systemd', 'init', 'cron', 'cupsd', 'dbus-daemon', 'services', 'svchost'):
        return 'service'
    return 'native'


@lru_cache(maxsize=8192)
def resource_activity(op, path):
    if op in ('EVENT_OPEN', 'EVENT_READ'):
        if classify_system_resource(path) == 'auth_db':
            return 'read_auth'
        if path.startswith('/proc/'):
            part = path[6:].split('/', 1)[0]
            return 'read_process' if part.isdigit() or part in ('self', 'thread-self') else 'read_inventory'
    if op == 'EVENT_WRITE':
        if path.startswith('/etc/'):
            return 'write_config'
        if path.startswith(('/home/', '/root/')):
            return 'write_user'
        if path.startswith(('/tmp/', '/var/tmp/')):
            return 'write_temp'
        return 'write_other'
    return ''


def count_bucket(n):
    return '1' if n == 1 else '2_3' if n < 4 else '4_7' if n < 8 else '8_plus'


WRITER_RELATIONS = ('self', 'parent', 'grandparent', 'other')

CONTEXT_TOKENS = [
    *[f'ctx_host::{scope}::family={f}' for scope in ('actor', 'parent', 'grandparent', 'incoming') for f in FAMILIES],
    *[f'ctx_host::lineage={a}>{b}>{c}' for a in FAMILIES for b in FAMILIES for c in FAMILIES],
    *[f'ctx_host::{scope}::prior_{act}_{w}s={count}' for scope in ('actor', 'parent', 'grandparent')
      for act in ACTIVITIES for w in WINDOWS for count in COUNTS],
    *[f'ctx_host::{scope}::has_netconn_{w}s' for scope in ('actor', 'parent', 'grandparent') for w in WINDOWS],
    *[f'ctx_host::incoming::age={a}' for a in ('lt1s', '1_30s', '30_300s')],
    *[f'ctx_host::execution::prior_writer={a}' for a in ('self', 'parent', 'other')],
    *[f'ctx_host::{scope}::image_prior_writer={a}' for scope in ('actor', 'parent') for a in WRITER_RELATIONS],
    'ctx_host::parent_missing', 'ctx_host::grandparent_missing',
    'ctx_host::late_beyond_window',
]


class FileSessionIndex:
    def __init__(self, raw_context=None, source_stream=False, max_processes=50000,
                 max_files=50000, max_history=32, ttl_micros=300_000_000):
        if min(max_processes, max_files, max_history, ttl_micros) <= 0:
            raise ValueError('Context limits must be positive')
        self.raw_context, self.source_stream = raw_context, source_stream
        self.max_processes, self.max_files = max_processes, max_files
        self.max_history, self.ttl = max_history, ttl_micros
        self.nodes, self.writes = OrderedDict(), OrderedDict()
        self.watermark = 0
        self.stats = Counter()

    def _node(self, guid, ts, create=False):
        if not guid:
            return None
        node = self.nodes.get(guid)
        if node is not None and self.watermark - node['seen'] > self.ttl:
            del self.nodes[guid]
            node = None
            self.stats['expired_processes'] += 1
        if node is None and create:
            node = dict(seen=ts, parent=[], network=[], incoming=[], actions={}, exec_writes=[])
            self.nodes[guid] = node
        if node is not None and create:
            node['seen'] = max(ts, node['seen'])
            self.nodes.move_to_end(guid)
            while len(self.nodes) > self.max_processes:
                self.nodes.popitem(last=False)
                self.stats['capacity_evictions'] += 1
            self.stats['peak_processes'] = max(self.stats['peak_processes'], len(self.nodes))
        return node

    def _append(self, history, item):
        ts = item[0] if isinstance(item, tuple) else item
        if ts < self.watermark - self.ttl:
            self.stats['late_observations_ignored'] += 1
            return
        if not history or item > history[-1]:
            history.append(item)
        elif item not in history:
            insort(history, item)
        if len(history) > self.max_history:
            del history[:-self.max_history]
        cutoff = self.watermark - self.ttl
        while history and (history[0][0] if isinstance(history[0], tuple) else history[0]) < cutoff:
            del history[0]

    def _parent(self, guid, parent, path, ts):
        if not parent or parent == guid or set(parent.replace('-', '')) == {'0'}:
            return
        node = self._node(guid, ts, True)
        value = (ts, parent, extract_basename(path).lower(), classify_image_dir(path))
        # Repeated reads do not create repeated copies of the same parent edge.
        if not node['parent'] or node['parent'][-1][1:] != value[1:]:
            self._append(node['parent'], value)

    def _action(self, guid, action, ts):
        node = self._node(guid, ts, True)
        if node:
            self._append(node['actions'].setdefault(action, []), ts)

    def _observed_path(self, guid, path, ts):
        if self.raw_context is None:
            return path
        snapshot = self.raw_context.subject(guid, ts)
        return snapshot[3] if snapshot else ''

    def observe_row(self, op, src, dst, ts, line, processes, files):
        """Fast ingestion hook: no label, endpoint value, or sampling decision."""
        self.watermark = max(self.watermark, ts)
        self.stats['source_rows'] += 1
        if op == 'EVENT_CLONE':
            parent, child = processes.get(src), processes.get(dst)
            if parent and child:
                self._parent(child[0], parent[0], self._observed_path(parent[0], parent[1], ts), ts)
                self._action(parent[0], 'spawn', ts)
            return
        actor = processes.get(src) or processes.get(dst)
        if not actor:
            return
        guid, path, _ = actor
        if op in ('EVENT_CONNECT', 'EVENT_SENDTO', 'EVENT_RECVFROM', 'EVENT_SENDMSG', 'EVENT_RECVMSG', 'EVENT_READ_SOCKET_PARAMS'):
            self._append(self._node(guid, ts, True)['network'], ts)
        elif op == 'EVENT_SHM':
            target = processes.get(dst)
            self._action(guid, 'ipc', ts)
            if target and target[0] != guid:
                self._append(self._node(target[0], ts, True)['incoming'], (ts, family(self._observed_path(guid, path, ts))))
        elif op == 'EVENT_EXECUTE':
            self._action(guid, 'exec', ts)
            target = files.get(dst) or files.get(src)
            if target:
                history = self.writes.get(target[0], [])
                eligible = [(t, writer) for t, writer in history if ts - self.ttl <= t < ts]
                if eligible:
                    self._append(self._node(guid, ts, True)['exec_writes'], (ts, eligible[-1][1]))
        elif op in ('EVENT_OPEN', 'EVENT_READ', 'EVENT_WRITE'):
            target = files.get(dst) or files.get(src)
            if not target:
                return
            activity = resource_activity(op, target[1])
            if activity:
                self._action(guid, activity, ts)
            if op == 'EVENT_WRITE' and target[1]:
                history = self.writes.setdefault(target[0], [])
                self._append(history, (ts, guid))
                self.writes.move_to_end(target[0])
                while len(self.writes) > self.max_files:
                    self.writes.popitem(last=False)
                    self.stats['file_evictions'] += 1
                self.stats['peak_files'] = max(self.stats['peak_files'], len(self.writes))

    def add_event(self, event):
        self.watermark = max(self.watermark, event.timestamp)
        if self.source_stream:
            parent_guid, _, _ = self.get_parent(event.process_guid, event.timestamp)
            if parent_guid and parent_guid != event.parent_guid:
                parent = self.raw_context.subject(parent_guid, event.timestamp) if self.raw_context else None
                event.parent_guid = parent_guid
                event.parent_path = parent[3] if parent else ''
                event.parent_cmdline = parent[4] if parent else ''
            return  # Clone edges and activity already observed before row selection.
        self._parent(event.process_guid, event.parent_guid, event.parent_path, event.timestamp)
        if event.event_type in ('FLOW_START', 'NETWORK_UNKNOWN'):
            self._append(self._node(event.process_guid, event.timestamp, True)['network'], event.timestamp)
        elif event.event_type == 'CROSS_PROCESS' and event.target_guid and event.target_path:
            self._append(self._node(event.target_guid, event.timestamp, True)['incoming'],
                         (event.timestamp, family(event.process_path)))
        if not self.source_stream and event.raw_operation == 'EVENT_EXECUTE' and getattr(event, 'target_file_guid', ''):
            history = self.writes.get(event.target_file_guid, [])
            eligible = [(t, writer) for t, writer in history if event.timestamp - self.ttl <= t < event.timestamp]
            if eligible:
                self._append(self._node(event.process_guid, event.timestamp, True)['exec_writes'],
                             (event.timestamp, eligible[-1][1]))

    def get_parent(self, guid, ts):
        # Observed CLONE is the causal creator. A later Subject snapshot may
        # instead name init after reparenting, so it must not overwrite this edge.
        node = self._node(guid, ts)
        history = node['parent'] if node else []
        idx = bisect_right(history, (ts, chr(0x10ffff), chr(0x10ffff), chr(0x10ffff)))
        if idx:
            return history[idx - 1][1:]
        if self.raw_context:
            subject = self.raw_context.subject(guid, ts)
            if subject and subject[0] and subject[0] != guid and set(subject[0].replace('-', '')) != {'0'}:
                parent = self.raw_context.subject(subject[0], ts)
                if parent:
                    return subject[0], extract_basename(parent[3]).lower(), classify_image_dir(parent[3])
        return ('', '', 'OTHER')

    def ancestors(self, guid, ts, max_depth=2):
        seen, result = {guid}, []
        for _ in range(max_depth):
            parent = self.get_parent(guid, ts)
            if not parent[0] or parent[0] in seen:
                break
            result.append(parent)
            seen.add(parent[0])
            guid = parent[0]
        return result

    def has_netconn(self, guid, ts, window_micros=30_000_000, check_parent=True):
        candidates = [guid]
        if check_parent:
            candidates.extend(anc[0] for anc in self.ancestors(guid, ts, max_depth=2))
        for candidate in candidates:
            node = self._node(candidate, ts)
            history = node['network'] if node else []
            if bisect_left(history, ts) > bisect_left(history, ts - window_micros):
                return True
        return False

    def _writer_relation(self, writer_guid, target_guid, ts):
        if writer_guid == target_guid:
            return 'self'
        anc = self.ancestors(target_guid, ts, max_depth=2)
        if len(anc) > 0 and writer_guid == anc[0][0]:
            return 'parent'
        if len(anc) > 1 and writer_guid == anc[1][0]:
            return 'grandparent'
        return 'other'

    def tokens(self, event):
        ts, guid = event.timestamp, event.process_guid
        actor_family = family(self._observed_path(guid, event.process_path, ts))
        result = [f'ctx_host::actor::family={actor_family}']
        ancestors = self.ancestors(guid, ts, max_depth=2)
        for depth, scope in enumerate(('parent', 'grandparent')):
            result.append(f'ctx_host::{scope}::family={family(ancestors[depth][1])}' if len(ancestors) > depth
                          else f'ctx_host::{scope}_missing')
        if len(ancestors) >= 2:
            result.append('ctx_host::lineage=' + '>'.join((family(ancestors[1][1]), family(ancestors[0][1]), actor_family)))
        if ts < self.watermark - self.ttl:
            return result + ['ctx_host::late_beyond_window']

        scope_candidates = (
            ('actor', guid),
            ('parent', ancestors[0][0] if len(ancestors) > 0 else ''),
            ('grandparent', ancestors[1][0] if len(ancestors) > 1 else ''),
        )
        for scope, candidate in scope_candidates:
            node = self._node(candidate, ts)
            if not node:
                continue
            for action, history in node['actions'].items():
                right = bisect_left(history, ts)  # Strictly prior, excludes current row.
                for seconds in WINDOWS:
                    n = right - bisect_left(history, ts - seconds * 1_000_000)
                    if n:
                        result.append(f'ctx_host::{scope}::prior_{action}_{seconds}s={count_bucket(n)}')
            net_history = node['network']
            if net_history:
                right_net = bisect_left(net_history, ts)
                for seconds in WINDOWS:
                    if right_net > bisect_left(net_history, ts - seconds * 1_000_000):
                        result.append(f'ctx_host::{scope}::has_netconn_{seconds}s')
            if scope in ('actor', 'parent') and node.get('exec_writes'):
                eligible_exec = [(t, w) for t, w in node['exec_writes'] if ts - self.ttl <= t <= ts]
                if eligible_exec:
                    rel = self._writer_relation(eligible_exec[-1][1], candidate, ts)
                    result.append(f'ctx_host::{scope}::image_prior_writer={rel}')
            if scope == 'actor':
                for when, source_family in node['incoming']:
                    if ts - self.ttl <= when < ts:
                        age = 'lt1s' if ts - when < 1_000_000 else '1_30s' if ts - when <= 30_000_000 else '30_300s'
                        result.extend((f'ctx_host::incoming::family={source_family}', f'ctx_host::incoming::age={age}'))
        if event.raw_operation == 'EVENT_EXECUTE':
            history = self.writes.get(event.target_file_guid, [])
            eligible = [(t, writer) for t, writer in history if ts - self.ttl <= t < ts]
            if eligible:
                writer = eligible[-1][1]
                relation = 'self' if writer == guid else 'parent' if ancestors and writer == ancestors[0][0] else 'other'
                result.append(f'ctx_host::execution::prior_writer={relation}')
        return sorted(set(result))
