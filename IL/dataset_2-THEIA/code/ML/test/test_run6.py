import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest
import numpy as np
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'preprocess'))
from build_host_shards import FileSessionIndex, extract_domain_shift_tokens, canonical_ecar_record, build_host_shards
from preprocess.common_schema import CanonicalEvent, classify_image_dir, classify_system_resource, classify_proc_resource
from threshold_policy import select_fpr_threshold


def event(**kw):
    args = dict(event_id='event', timestamp=10, hostname='host', event_type='FILE_READ',
                scenario='train', process_guid='child', process_path='/home/admin/Downloads/firefox/firefox')
    return CanonicalEvent(**(args | kw))


class Run6Tests(unittest.TestCase):
    def test_component_boundaries(self):
        for p in ['/home/admin/project', '/home/admin/sys', '/home/admin/bin', '/home/admin/library']:
            self.assertEqual(classify_image_dir(p), 'USERS_OTHER')
        for p in ['/proc/1/maps', '/sys/kernel', '/dev/null']:
            self.assertEqual(classify_image_dir(p), 'PSEUDO_FS')
        self.assertEqual(classify_image_dir('/etcetera/a'), 'OTHER')
        self.assertEqual(classify_image_dir('/home/a/../../etc/hosts'), 'WINDOWS_OTHER')

    def test_resource_roles_do_not_hide_config_or_writes(self):
        s = FileSessionIndex()
        self.assertEqual(classify_system_resource('/etc/resolv.conf'), 'name_service_config')
        self.assertEqual(classify_system_resource('/etc/ld.so.cache'), 'dynamic_loader_config')
        for p in ['/etc/hosts', '/etc/firefox/native-messaging-hosts/gtcache', '/etc/ld.so.cache', '/home/other/.mozilla/firefox/a']:
            self.assertNotIn('temp_context::app_own_cache', extract_domain_shift_tokens(event(target_path=p), s))
        tokens=extract_domain_shift_tokens(event(target_path='/home/admin/.mozilla/firefox/a'),s)
        self.assertIn('temp_context::app_own_cache', tokens)
        self.assertEqual(canonical_ecar_record(event(event_type='FILE_WRITE',target_path='/etc/hosts'))['action'],'write')

    def test_out_of_order_context_and_no_future_parent(self):
        s=FileSessionIndex()
        s.add_event(event(event_type='PROCESS_START',timestamp=100,parent_guid='parent',parent_path='/bin/bash'))
        self.assertEqual(s.get_parent('child',99)[0],'')
        self.assertEqual(s.get_parent('child',100)[0],'parent')
        s.add_event(event(event_type='FLOW_START', timestamp=100))
        s.add_event(event(event_type='FLOW_START', timestamp=5))
        self.assertTrue(s.has_netconn('child',6,window_micros=2))
        self.assertFalse(s.has_netconn('child',99,window_micros=2))
        self.assertFalse(s.has_netconn('parent',100))

    def test_ipc_either_endpoint_and_clone_self_parent(self):
        s=FileSessionIndex()
        s.add_event(event(event_type='FLOW_START', process_guid='target', timestamp=9))
        tokens=extract_domain_shift_tokens(event(event_type='CROSS_PROCESS',target_guid='target'),s)
        self.assertIn('crossproc::incoming_netconn',tokens)
        clone=event(event_type='PROCESS_START',parent_path='/bin/bash',parent_guid='p',target_guid='child')
        s.add_event(clone)
        self.assertEqual(s.get_parent('child',10)[0],'p')
        self.assertEqual(canonical_ecar_record(clone)['properties']['parent_image_path'],'/bin/bash')

    def test_threshold_ties_and_all_one(self):
        th, i=select_fpr_threshold([90,0,10,0],.05)
        self.assertEqual(i,3)
        self.assertEqual(th,1)
        th,i=select_fpr_threshold([0,0,100],.01)
        self.assertGreater(th,1)
        with self.assertRaises(ValueError):select_fpr_threshold([0,0])

    def test_fixed_output_publication_preserves_dependencies(self):
        from build_host_shards import publish_output
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'output';staged=root/'staged';out.mkdir();staged.mkdir()
            (out/'shards').mkdir();(out/'shards/stale.npz').write_bytes(b'old')
            (out/'manifest.json').write_text('old')
            (out/'frozen-model.txt').write_text('frozen')
            (staged/'shards').mkdir();(staged/'shards/new.npz').write_bytes(b'new')
            (staged/'manifest.json').write_text('new')
            publish_output(staged,out)
            self.assertEqual((out/'manifest.json').read_text(),'new')
            self.assertFalse((out/'shards/stale.npz').exists())
            self.assertEqual((out/'frozen-model.txt').read_text(),'frozen')
            self.assertEqual((out/'shards/new.npz').read_bytes(),b'new')

    def test_output_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaises(ValueError):
                build_host_shards(root,root/'labels',root/'vocab',root/'derived')
            self.assertFalse((root/'derived').exists())

    def test_adapter_keeps_context_before_sampling(self):
        from preprocess.theia_adapter import THEIAAdapter
        class Refiner:
            attack_edge_uuids=set()
            attack_process_uuids={}
            def get_attack_chain_for_process(self,g):return ''
            def refine_event_label(self,e):return 0
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.csv'
            p.write_text('src,si,op,dst,di,id,ts\n'
                         'p,0,EVENT_CONNECT,n,1,00000001-0000,1522764134000380070\n'
                         'p,0,EVENT_CLONE,c,2,00000001-0001,1522764134000380071\n')
            a=THEIAAdapter(Refiner(),Path(d));a._loaded_node_tables=True
            a.process_nodes={0:('P','/bin/bash',''),2:('C','/bin/dash','')}
            a.netflow_nodes={1:('N','10.0.6.60',1234,'8.8.8.8',80)}
            events=list(a.stream_canonical_events(p,undersample_benign_ratio=30))
            self.assertEqual([e.event_type for e in events],['FLOW_START','PROCESS_START'])
            self.assertEqual([e.source_line for e in events],[2,3])

    def test_frozen_composite_real_checkpoints(self):
        import hashlib
        from scipy import sparse
        from frozen_atlas import FrozenAtlasModel
        workspace=ROOT.parents[3]
        anchor=workspace/'IL/dataset_1-ATLASv2/code/ML/pretrained_optc_model/model-slot-0.txt'
        residual=ROOT/'pretrained_optc_model/model-slot-0.txt'
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            (d/'residual.txt').symlink_to(residual)
            config={'alpha':.8,'anchor':{'path':str(anchor),'sha256':hashlib.sha256(anchor.read_bytes()).hexdigest()},
                    'residual':{'path':'residual.txt','sha256':hashlib.sha256(residual.read_bytes()).hexdigest()}}
            (d/'composition.json').write_text(json.dumps(config))
            model=FrozenAtlasModel(d/'residual.txt')
            X=sparse.csr_matrix(([1.,1.,1.],([0,1,2],[1,300,10316])),shape=(3,10317))
            expected=.8*model.anchor.predict(X,raw_score=True,num_threads=1)
            expected+=model.residual.predict(model.align(X,12337),raw_score=True,num_threads=1)
            np.testing.assert_allclose(model.predict(X,raw_score=True),expected,rtol=0,atol=0)
            self.assertFalse(np.allclose(expected,model.residual.predict(model.align(X,12337),raw_score=True,num_threads=1)))
            config['anchor']['sha256']='0'*64;(d/'composition.json').write_text(json.dumps(config))
            with self.assertRaises(ValueError):FrozenAtlasModel(d/'residual.txt')

    def test_notebook_policy_and_syntax(self):
        n=json.loads((ROOT/'notebook/lgbm_atlasv2_theia.ipynb').read_text())
        for c in n['cells']:
            if c['cell_type']=='code':ast.parse(''.join(c['source']))
        source=''.join(n['cells'][2]['source'])
        tree=ast.parse(source)
        fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='select_fpr_threshold')
        ns={'np':np};exec(compile(ast.Module(body=[fn],type_ignores=[]),'\u003cpolicy\u003e','exec'),ns)
        self.assertEqual(ns['select_fpr_threshold']([90,0,10,0],.05),select_fpr_threshold([90,0,10,0],.05))
        self.assertNotIn('np.where(y_rep == 1, 0.25',source)

    # ========================================================================
    # Run 7 regression tests: IPC disambiguation, semantic resource roles
    # ========================================================================

    def test_run7_network_unknown_vs_ipc_vs_external(self):
        """Adapter must correctly classify EVENT_CONNECT by endpoint type (Run 7 fix)."""
        from preprocess.theia_adapter import THEIAAdapter
        class Refiner:
            attack_edge_uuids=set()
            attack_process_uuids={}
            def get_attack_chain_for_process(self,g):return ''
            def refine_event_label(self,e):return 0
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.csv'
            # Row 2: external IP — FLOW_START
            # Row 3: NA dst (like /var/log/mail 500 events) — NETWORK_UNKNOWN (not CROSS_PROCESS)
            # Row 4: Unix socket path — CROSS_PROCESS (unix_domain)
            # Row 5: loopback dst — CROSS_PROCESS (loopback)
            p.write_text(
                'src,si,op,dst,di,id,ts\n'
                'p,0,EVENT_CONNECT,n,1,AAAA0001-0000,1522764134000000001\n'
                'p,0,EVENT_CONNECT,n,2,AAAA0001-0001,1522764134000000002\n'
                'p,0,EVENT_CONNECT,n,3,AAAA0001-0002,1522764134000000003\n'
                'p,0,EVENT_CONNECT,n,4,AAAA0001-0003,1522764134000000004\n'
            )
            a=THEIAAdapter(Refiner(),Path(d));a._loaded_node_tables=True
            a.process_nodes={0:('P','/home/admin/Downloads/firefox/firefox','')}
            a.netflow_nodes={
                1:('N1','10.0.6.60',1234,'128.55.12.110',4444),
                2:('N2','10.0.6.60',47005,'NA',0),
                3:('N3','/var/run/dbus/system_bus_socket',0,'',0),
                4:('N4','127.0.0.1',1111,'127.0.0.1',2222),
            }
            events=list(a.stream_canonical_events(p,undersample_benign_ratio=1))
            types=[e.event_type for e in events]
            endpoints=[e.net_endpoint_type for e in events]
            self.assertEqual(types[0],'FLOW_START',   "external IP must be FLOW_START")
            self.assertEqual(types[1],'NETWORK_UNKNOWN', "NA dst must be NETWORK_UNKNOWN (not CROSS_PROCESS)")
            self.assertEqual(types[2],'CROSS_PROCESS', "unix socket path must be CROSS_PROCESS")
            self.assertEqual(types[3],'FLOW_START', "loopback is an IP socket, not proof of cross-process access")
            self.assertEqual(endpoints[0],'external')
            self.assertEqual(endpoints[1],'unknown_endpoint')
            self.assertEqual(endpoints[2],'unix_domain')
            self.assertEqual(endpoints[3],'loopback')

    def test_run7_proc_resource_roles(self):
        """/proc/* paths must be classified into distinct semantic roles (Run 7)."""
        self.assertEqual(classify_proc_resource('/proc/meminfo'), 'proc_map::sysinfo_read')
        self.assertEqual(classify_proc_resource('/proc/cpuinfo'), 'proc_map::sysinfo_read')
        self.assertEqual(classify_proc_resource('/proc/loadavg'), 'proc_map::sysinfo_read')
        self.assertEqual(classify_proc_resource('/proc/1234/maps', '99'), 'proc_map::other_maps')
        self.assertEqual(classify_proc_resource('/proc/1234/mem', '99'), 'proc_map::other_maps')
        self.assertEqual(classify_proc_resource('/proc/1234/fd', '99'), 'proc_map::other_fd')
        self.assertEqual(classify_proc_resource('/proc/1234/status', '99'), 'proc_map::other_status')
        self.assertEqual(classify_proc_resource('/proc/self/maps'), 'proc_map::self_maps')
        self.assertEqual(classify_proc_resource('/proc/self/fd'), 'proc_map::self_fd')
        self.assertEqual(classify_proc_resource('/etc/passwd'), '')
        self.assertEqual(classify_proc_resource('/var/log/mail'), '')

    def test_run7_extended_system_resource_roles(self):
        """auth_db, tz_config, browser_host_config, system_log roles (Run 7)."""
        self.assertEqual(classify_system_resource('/etc/passwd'), 'auth_db')
        self.assertEqual(classify_system_resource('/etc/shadow'), 'auth_db')
        self.assertEqual(classify_system_resource('/etc/group'), 'auth_db')
        self.assertEqual(classify_system_resource('/etc/localtime'), 'tz_config')
        self.assertEqual(classify_system_resource('/etc/timezone'), 'tz_config')
        self.assertEqual(classify_system_resource('/etc/firefox/native-messaging-hosts/gtcache'), 'browser_host_config')
        self.assertEqual(classify_system_resource('/etc/firefox/pref/firefox.js'), 'browser_host_config')
        self.assertEqual(classify_system_resource('/var/log/mail'), 'system_log')
        self.assertEqual(classify_system_resource('/var/log/syslog'), 'system_log')
        self.assertEqual(classify_system_resource('/etc/resolv.conf'), 'name_service_config')
        self.assertEqual(classify_system_resource('/etc/ld.so.cache'), 'dynamic_loader_config')

    def test_run7_domain_tokens_include_new_roles(self):
        """extract_domain_shift_tokens must emit new Run 7 tokens."""
        s = FileSessionIndex()
        t = extract_domain_shift_tokens(event(target_path='/proc/meminfo'), s)
        self.assertIn('file_role::proc_map::sysinfo_read', t)
        self.assertNotIn('file_role::proc_map::other_maps', t)
        t2 = extract_domain_shift_tokens(event(target_path='/proc/1234/maps', process_pid='99'), s)
        self.assertIn('file_role::proc_map::other_maps', t2)
        self.assertNotIn('file_role::proc_map::sysinfo_read', t2)
        t3 = extract_domain_shift_tokens(event(target_path='/etc/passwd'), s)
        self.assertIn('file_role::auth_db', t3)
        t4 = extract_domain_shift_tokens(event(target_path='/etc/firefox/native-messaging-hosts/gtcache'), s)
        self.assertIn('file_role::browser_host_config', t4)
        t5 = extract_domain_shift_tokens(event(target_path='/var/log/mail'), s)
        self.assertIn('file_role::system_log', t5)

    def test_run7_parent_is_shell_token(self):
        """parent_image::is_shell emitted when parent is a shell process (Run 7)."""
        s = FileSessionIndex()
        for shell in ('bash', 'dash', 'sh', 'zsh'):
            t = extract_domain_shift_tokens(event(parent_path=f'/bin/{shell}'), s)
            self.assertIn('parent_image::is_shell', t, f"expected is_shell for parent={shell}")
        t_ns = extract_domain_shift_tokens(event(parent_path='/usr/bin/python3'), s)
        self.assertNotIn('parent_image::is_shell', t_ns)

    def test_run7_crossproc_net_endpoint_tokens(self):
        """crossproc::net_endpoint=loopback / unix_domain emitted on CROSS_PROCESS (Run 7)."""
        s = FileSessionIndex()
        e_lb = event(event_type='FLOW_START', net_endpoint_type='loopback')
        t_lb = extract_domain_shift_tokens(e_lb, s)
        self.assertNotIn('crossproc::net_endpoint=loopback', t_lb)
        self.assertNotIn('crossproc::net_endpoint=unix_domain', t_lb)
        e_ud = event(event_type='CROSS_PROCESS', net_endpoint_type='unix_domain')
        t_ud = extract_domain_shift_tokens(e_ud, s)
        self.assertIn('crossproc::net_endpoint=unix_domain', t_ud)
        e_no = event(event_type='CROSS_PROCESS', net_endpoint_type='')
        t_no = extract_domain_shift_tokens(e_no, s)
        self.assertNotIn('crossproc::net_endpoint=loopback', t_no)
        self.assertNotIn('crossproc::net_endpoint=unix_domain', t_no)

    def test_run10_process_lineage_and_shell_parent(self):
        """structure::process_lineage and parent_image::is_shell (Run 10)."""
        s = FileSessionIndex()
        # Same binary lineage (e.g. firefox -> firefox worker)
        e_clone = event(process_path='/usr/bin/firefox', parent_path='/usr/bin/firefox')
        t_clone = extract_domain_shift_tokens(e_clone, s)
        self.assertIn('structure::process_lineage=firefox->firefox', t_clone)
        self.assertNotIn('parent_image::is_shell', t_clone)

        # Shell spawning binary (e.g. dash -> gtcache)
        e_spawn = event(process_path='/home/admin/gtcache', parent_path='/bin/dash')
        t_spawn = extract_domain_shift_tokens(e_spawn, s)
        self.assertIn('structure::process_lineage=dash->gtcache', t_spawn)
        self.assertIn('parent_image::is_shell', t_spawn)

    def test_run10_recon_and_dns_tokens(self):
        """net_actor_proc_read, shell_actor_proc_read, routine_dns_lookup (Run 10 & 12)."""
        s = FileSessionIndex()
        s.add_event(event(process_guid='NET_PROC', event_type='NETWORK_UNKNOWN', timestamp=100))

        # Networked process reading another process's /proc maps (cross-process introspection)
        e_net_proc = event(process_guid='NET_PROC', event_type='FILE_READ', target_path='/proc/123/maps', timestamp=105)
        t_net_proc = extract_domain_shift_tokens(e_net_proc, s)
        self.assertIn('proc_context::net_actor_proc_read', t_net_proc)

        # Shell-spawned process reading another process's /proc status
        e_shell_proc = event(parent_path='/bin/dash', event_type='FILE_READ', target_path='/proc/123/status', timestamp=105)
        t_shell_proc = extract_domain_shift_tokens(e_shell_proc, s)
        self.assertIn('crossproc::shell_actor_proc_read', t_shell_proc)

        # Self-inspection and system-info reads MUST NOT trigger cross-process recon tokens
        e_self_proc = event(process_guid='NET_PROC', parent_path='/bin/dash', event_type='FILE_READ', target_path='/proc/self/maps', timestamp=105)
        t_self = extract_domain_shift_tokens(e_self_proc, s)
        self.assertNotIn('proc_context::net_actor_proc_read', t_self)
        self.assertNotIn('crossproc::shell_actor_proc_read', t_self)

        e_sysinfo = event(process_guid='NET_PROC', parent_path='/bin/dash', event_type='FILE_READ', target_path='/proc/cpuinfo', timestamp=105)
        t_sysinfo = extract_domain_shift_tokens(e_sysinfo, s)
        self.assertNotIn('proc_context::net_actor_proc_read', t_sysinfo)
        self.assertNotIn('crossproc::shell_actor_proc_read', t_sysinfo)

        # Networked process routine DNS lookup
        e_dns = event(process_guid='NET_PROC', event_type='FILE_READ', target_path='/etc/resolv.conf', timestamp=105)
        t_dns = extract_domain_shift_tokens(e_dns, s)
        self.assertIn('proc_context::routine_dns_lookup', t_dns)

    def test_pid_unknown_and_preseed_agree(self):
        from build_host_shards import PREDEFINED_DOMAIN_TOKENS
        self.assertEqual(classify_proc_resource('/proc/123/maps'), 'proc_map::unknown_maps')
        self.assertEqual(classify_proc_resource('/proc/123/maps', '123'), 'proc_map::self_maps')
        self.assertEqual(classify_proc_resource('/proc/123/maps', '99'), 'proc_map::other_maps')
        for path in ('/proc', '/proc/123/maps', '/proc/self/fd', '/proc/meminfo'):
            token = 'file_role::' + classify_proc_resource(path)
            self.assertIn(token, PREDEFINED_DOMAIN_TOKENS)

    def test_raw_history_gates_future_and_retains_unknown(self):
        from preprocess.raw_context import RawContext
        r = RawContext.__new__(RawContext)
        r.subjects = {'P': [(100, ['A','U','5','/bin/bash','bash -c whoami']),
                            (200, ['B','V','5','/bin/bash','bash -c id'])]}
        r.principals = {'U': [(110, '0')]}
        self.assertIsNone(r.subject('P', 99))
        self.assertEqual(r.subject('P', 150)[0], 'A')
        self.assertEqual(r.subject('P', 200)[0], 'B')
        self.assertIsNone(r.uid('U', 109))
        self.assertEqual(r.uid('U', 110), '0')

    def test_unknown_operation_not_process_start_and_command_context(self):
        self.assertEqual(canonical_ecar_record(event(event_type='SYSTEM_CALL'))['action'], 'unknown')
        tokens = extract_domain_shift_tokens(event(process_cmdline='bash -c whoami',
                                                   principal_role='root'), FileSessionIndex())
        self.assertIn('principal_context::role=root', tokens)
        self.assertTrue(any(t.startswith('command_line::') for t in tokens))

    def test_unknown_network_updates_context_without_host_socket_tokens(self):
        s = FileSessionIndex()
        s.add_event(event(event_type='NETWORK_UNKNOWN', timestamp=9))
        tokens = extract_domain_shift_tokens(event(timestamp=10), s)
        self.assertIn('proc_context::has_netconn', tokens)
        self.assertFalse(any(t.startswith('flow::') for t in tokens))

    def test_raw_scanner_watermark_and_cache(self):
        import io, tarfile, sqlite3
        from preprocess.raw_context import ensure_raw_context, RawContext
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); raw = root/'dataset/RAW'; raw.mkdir(parents=True)
            records = [
                {'Event': {'timestampNanos': 200000}},
                {'Principal': {'uuid': 'U', 'userId': '0'}},
                {'Subject': {'uuid': 'P', 'startTimestampNanos': 100000,
                             'localPrincipal': 'U', 'cid': 123,
                             'parentSubject': {'UUID': 'A'},
                             'cmdLine': {'string': 'bash -c id'},
                             'properties': {'map': {'path': '/bin/bash', 'tgid': '123'}}}},
            ]
            lines = b''.join((json.dumps({'datum': {'com.bbn.tc.schema.avro.cdm18.'+k: v}},
                                        separators=(',', ':'))+'\n').encode()
                             for r in records for k, v in r.items())
            with tarfile.open(raw/'fixture.tar.gz', 'w:gz') as tar:
                m=tarfile.TarInfo('fixture.json');m.size=len(lines);tar.addfile(m,io.BytesIO(lines))
            path = ensure_raw_context(root/'dataset', root/'output/context.sqlite')
            r = RawContext(path)
            self.assertIsNone(r.subject('P', 99))
            self.assertEqual(r.subject('P', 100), ['A','U','123','/bin/bash','bash -c id'])
            self.assertEqual(r.uid('U', 200), '0')
            stamp = path.stat().st_mtime_ns
            ensure_raw_context(root/'dataset', path)
            self.assertEqual(stamp, path.stat().st_mtime_ns)
            with self.assertRaises(ValueError):
                ensure_raw_context(root/'dataset', raw/'invalid.sqlite')

    def test_provenance_alignment_and_grouped_metrics(self):
        import hashlib
        from scipy import sparse
        from cohort_metrics import grouped_metrics, load_provenance
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); path=root/'provenance.npz'
            np.savez_compressed(path, source_line=np.array([2,3,4]),
                                process_guid=np.array(['P','P','N']),
                                scenario=np.array(['campaign','campaign','background']),
                                timestamp=np.array([0,1,2]))
            part={'path':'dummy','provenance_path':path.name,
                  'provenance_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            decode=lambda *args:(sparse.csr_matrix((3,2)),np.array([1,1,0]),np.array([2,3,4]))
            result=grouped_metrics(root,[part],2,decode,lambda X:np.array([.8,.1,.9]),.5)
            self.assertEqual(result['process_recall'],1)
            self.assertEqual(result['campaigns']['campaign']['recall'],.5)
            self.assertEqual(result['sampled_fp_by_utc_day']['1970-01-01']['fp'],1)
            with self.assertRaises(ValueError):load_provenance(root,part,np.array([3,2,4]))

    def test_notebook_alpha_applies_to_retention_and_export(self):
        n=json.loads((ROOT/'notebook/lgbm_atlasv2_theia.ipynb').read_text())
        evaluation=''.join(n['cells'][4]['source'])
        self.assertNotIn('z_tot = 0.8', evaluation)
        self.assertEqual(evaluation.count('return deployed_model.predict(X_full, num_threads=PREDICT_THREADS)'),2)
        self.assertIn('task2_alpha=BASE_MARGIN_ALPHA', ''.join(n['cells'][7]['source']))

    def test_run13_label_refiner_two_tier_intersection(self):
        from preprocess.label_refiner import LabelRefiner
        refiner = LabelRefiner.__new__(LabelRefiner)
        refiner.attack_process_uuids = {'FIREFOX_UUID': 'theia_3.11_success', 'PAYLOAD_UUID': 'theia_3.11_success'}
        refiner.attack_edge_uuids = {'EDGE_LOADER', 'EDGE_PROC_STAT', 'EDGE_PAYLOAD'}
        refiner.scenario_attack_micros = {'theia_3.11_success': 1000}

        # 1. Edge match but OS loader library -> labeled 0
        e_loader = event(event_id='EDGE_LOADER', process_guid='FIREFOX_UUID', process_path='/usr/bin/firefox',
                         event_type='FILE_READ', target_path='/lib/x86_64-linux-gnu/libc-2.15.so', timestamp=2000)
        self.assertEqual(refiner.refine_event_label(e_loader), 0)

        # 2. Edge match but Firefox reading /proc/123/stat -> labeled 0 (Firefox paradox)
        e_proc = event(event_id='EDGE_PROC_STAT', process_guid='FIREFOX_UUID', process_path='/usr/bin/firefox',
                       event_type='FILE_READ', target_path='/proc/123/stat', timestamp=2000)
        self.assertEqual(refiner.refine_event_label(e_proc), 0)

        # 3. Firefox dropping payload into /etc -> labeled 1
        e_drop = event(event_id='EDGE_DROP', process_guid='FIREFOX_UUID', process_path='/usr/bin/firefox',
                       event_type='FILE_WRITE', target_path='/etc/firefox/native-messaging-hosts/gtcache', timestamp=2000)
        self.assertEqual(refiner.refine_event_label(e_drop), 1)

        # 4. Standalone payload post-cutoff -> labeled 1
        e_payload = event(event_id='EDGE_PAYLOAD', process_guid='PAYLOAD_UUID', process_path='/usr/bin/gtcache',
                          event_type='FILE_READ', target_path='/etc/passwd', timestamp=2000)
        self.assertEqual(refiner.refine_event_label(e_payload), 1)

    def test_run13_grandparent_tokens_and_crossproc(self):
        s = FileSessionIndex()
        s.add_event(event(process_guid='GP', process_path='/home/admin/firefox', timestamp=10))
        s.add_event(event(process_guid='P', parent_guid='GP', parent_path='/home/admin/firefox',
                          process_path='/bin/dash', timestamp=20))
        s.add_event(event(process_guid='ACTOR', parent_guid='P', parent_path='/bin/dash',
                          process_path='/home/admin/gtcache', timestamp=30))

        e = event(process_guid='ACTOR', parent_guid='P', parent_path='/bin/dash',
                  process_path='/home/admin/gtcache', event_type='FILE_READ',
                  target_path='/proc/999/status', timestamp=40)
        tokens = extract_domain_shift_tokens(e, s)
        self.assertIn('grandparent_image::dir=USERS_OTHER', tokens)
        self.assertIn('relation::grandparent_dir->actor_dir=USERS_OTHER->USERS_OTHER', tokens)
        self.assertIn('parent_image::is_shell', tokens)
        self.assertIn('crossproc::shell_actor_proc_read', tokens)

        # Grandparent is shell: GP=bash, P=python, ACTOR=curl reading /proc/123/status
        s2 = FileSessionIndex()
        s2.add_event(event(process_guid='GP_SHELL', process_path='/bin/bash', timestamp=10))
        s2.add_event(event(process_guid='P_PY', parent_guid='GP_SHELL', parent_path='/bin/bash',
                           process_path='/usr/bin/python3', timestamp=20))
        s2.add_event(event(process_guid='ACTOR2', parent_guid='P_PY', parent_path='/usr/bin/python3',
                           process_path='/usr/bin/curl', timestamp=30))
        e2 = event(process_guid='ACTOR2', parent_guid='P_PY', parent_path='/usr/bin/python3',
                   process_path='/usr/bin/curl', event_type='FILE_READ',
                   target_path='/proc/999/status', timestamp=40)
        tokens2 = extract_domain_shift_tokens(e2, s2)
        self.assertIn('grandparent_image::is_shell', tokens2)
        self.assertIn('crossproc::shell_actor_proc_read', tokens2)

    def test_run13_exec_prior_writer_lifetime(self):
        s = FileSessionIndex()
        procs = {1: ('P', '/bin/bash', ''), 2: ('C', '/tmp/gtcache', '')}
        files = {3: ('F_GT', '/tmp/gtcache')}
        s.observe_row('EVENT_WRITE', 1, 3, 10, 2, procs, files)
        s.observe_row('EVENT_CLONE', 1, 2, 20, 3, procs, files)
        s.observe_row('EVENT_EXECUTE', 3, 2, 30, 4, procs, files)

        e_read = event(process_guid='C', timestamp=100, event_type='FILE_READ', target_path='/etc/passwd')
        tokens = s.tokens(e_read)
        self.assertIn('ctx_host::actor::image_prior_writer=parent', tokens)

        # Grandparent prior activity
        procs[4] = ('SC', '/bin/cat', '')
        s.observe_row('EVENT_CLONE', 2, 4, 60, 6, procs, files)
        e_sc = event(process_guid='SC', timestamp=70, event_type='FILE_READ', target_path='/etc/passwd')
        tokens_sc = s.tokens(e_sc)
        self.assertIn('ctx_host::grandparent::prior_spawn_300s=1', tokens_sc)

    def test_run13_threshold_plateau_selection(self):
        from threshold_policy import select_validation_operating_point, select_validation_threshold
        pos = np.zeros(101, dtype=np.int64)
        neg = np.zeros(101, dtype=np.int64)
        pos[30:100] = 10
        neg[0:30] = 1000
        neg[30:40] = 1
        neg[40:50] = 1

        th_old, idx_old = select_validation_operating_point(pos, neg, max_fpr=0.01, plateau_rel_tol=0.0)
        th_new, idx_new = select_validation_operating_point(pos, neg, max_fpr=0.01, plateau_rel_tol=0.03)
        self.assertLessEqual(th_new, th_old)
        self.assertGreaterEqual(th_new, 0.0)

        y_val = np.array([1]*50 + [0]*1000)
        scores = np.concatenate([np.random.RandomState(42).uniform(0.3, 0.9, 50),
                                 np.random.RandomState(42).uniform(0.0, 0.2, 1000)])
        res = select_validation_threshold(y_val, scores, fpr_ceiling=0.01)
        self.assertIn('threshold', res)
        self.assertIn('f1', res)
        self.assertEqual(res['policy'], 'left_edge_f1_plateau_fpr_bounded')


if __name__=='__main__':unittest.main()
