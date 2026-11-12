"""Process-centered graph inputs and a separate, explicitly weak supervision review.

Feature construction accepts observable event records only. Supervision review is
never called by the feature constructor. All graph decisions are at window end.
"""
from bisect import bisect_right
from collections import defaultdict,Counter
import numpy as np
from provenance_context import family,path_role,command_tokens,age_bucket

PORTAL_DOMAINS=frozenset({'detectportal.firefox.com','prod.detectportal.prod.cloudops.mozgcp.net'})


def review_targets(positive_rows, *, scenario, original_label):
    """Mask uncertain evidence; never relabel an uncertain positive as benign.

    Remaining stage annotations are historical process-stage WEAK labels.
    This review is a supervision sensitivity policy, not newly verified truth.
    """
    historical=np.zeros(4,np.float32);retained=np.zeros(4,np.float32);uncertain=[]
    for row in positive_rows:
        stage=int(row['stage'])
        if 1<=stage<=4:historical[stage-1]=1
        is_portal=(row['event_type']=='FLOW_START' and row['process']=='firefox.exe'
                   and row['target'].strip().lower() in PORTAL_DOMAINS)
        if is_portal:uncertain.append(int(row['line']))
        elif 1<=stage<=4:retained[stage-1]=1
    invalid_gate=scenario=='s3'
    only_uncertain=bool(original_label) and bool(uncertain) and not retained.any()
    known=not (invalid_gate or only_uncertain)
    return dict(original_stages=historical,reviewed_stages=retained,
        reviewed_binary=int(bool(original_label)),review_mask=known,
        reason='invalid_s3_time_gate' if invalid_gate else 'only_unresolved_portal_evidence' if only_uncertain else
               'mixed_unresolved_portal_evidence' if uncertain else 'retained_historical_evidence',
        uncertain_source_lines=uncertain)


class ObservationIndex:
    def __init__(self, records):
        unique={}
        for record in records:
            for e in [record['event']]+[x['observation'] for x in record['evidence']]:
                unique[(e['line'],e['kind'],e['actor'],e['target'])]=e
        self.observations=sorted(unique.values(),key=lambda e:(e['timestamp'],e['line']))
        self.incoming=defaultdict(list);self.metadata=defaultdict(list)
        for e in self.observations:
            a=(e['host'],e['actor'])
            if e['actor']:self.metadata[a].append((e['timestamp'],e['actor_path'],e['actor_command']))
            if e['target'] and e['target_path']:
                self.metadata[(e['host'],e['target'])].append((e['timestamp'],e['target_path'],''))
            if e['target'] and e['direction_known'] and e['actor']!=e['target']:
                self.incoming[(e['host'],e['target'])].append(e)
        self.times={k:[e['timestamp'] for e in v] for k,v in self.incoming.items()}
        self.meta_times={k:[x[0] for x in v] for k,v in self.metadata.items()}

    def prior(self,key,end):
        rows=self.incoming.get(key,[]);idx=bisect_right(self.times.get(key,[]),end)
        # Bounds are per relation, avoiding eviction of rare kinds by frequent OPEN.
        counts=Counter();out=[]
        for e in reversed(rows[:idx]):
            if end-e['timestamp']>86_400_000_000:break
            if counts[e['relation']]>=8:continue
            counts[e['relation']]+=1;out.append(e)
        return out

    def describe(self,key,end):
        rows=self.metadata.get(key,[]);idx=bisect_right(self.meta_times.get(key,[]),end)
        path=command=''
        for t,p,c in reversed(rows[:idx]):
            if end-t>86_400_000_000:break
            if not path and p:path=p
            if not command and c:command=c
            if path and command:break
        return path,command


def descriptor(path,command,event_vocab,is_file=False):
    tokens={f'event::actor_family={family(path)}',f'event::actor_role={path_role(path)}'}
    tokens.update('event::'+t for t in command_tokens(command))
    out=np.zeros(len(event_vocab)+3,np.float32)
    for token in tokens:
        if token in event_vocab:out[event_vocab[token]]=1
    out[-3]=float(is_file);out[-2]=float(not is_file)
    out[-1]=float(is_file and path.lower().endswith(('.exe','.com','.scr')))
    return out


def build_window_graph(records,index,event_vocab,*,max_central=64,max_nodes=128,max_events=64):
    """Pure observable construction: no labels, split names or verdicts accepted."""
    records=sorted(records,key=lambda r:(r['event']['timestamp'],r['line']))
    end=max(r['event']['timestamp'] for r in records)
    histories=defaultdict(list)
    for r in records:
        e=r['event']
        if e['actor']:histories[(e['host'],e['actor'])].append(r)
    central=sorted(histories,key=lambda k:(-histories[k][-1]['event']['timestamp'],k))[:max_central]
    if not central:raise ValueError('Window has no observable process identity')
    nodes=list(central);lookup={k:i for i,k in enumerate(nodes)};edges={};max_evidence_time=0
    def add_node(key):
        if key not in lookup:
            if len(nodes)>=max_nodes:return None
            lookup[key]=len(nodes);nodes.append(key)
        return lookup[key]
    def add_edge(e):
        nonlocal max_evidence_time
        if e['timestamp']>end:raise AssertionError('Future edge')
        if not e['direction_known'] or not e['target'] or not e['actor']:return
        src,dst=(e['host'],e['actor']),(e['host'],e['target'])
        if src==dst:return
        a,b=add_node(src),add_node(dst)
        if a is not None and b is not None:
            edges[(a,b,e['relation'])]=max(edges.get((a,b,e['relation']),0),e['timestamp'])
            max_evidence_time=max(max_evidence_time,e['timestamp'])
    # Two hops are traversed from observed incoming/parent relations, with raw
    # identities used only for joins. Reverse model edges have distinct kinds.
    frontier=list(central);visited=set()
    for _ in range(2):
        following=[]
        for key in frontier:
            if key in visited:continue
            visited.add(key)
            for e in index.prior(key,end):
                add_edge(e)
                other=(e['host'],e['actor'])
                if other in lookup:following.append(other)
        frontier=following
    for r in records:
        add_edge(r['event'])
        for entry in r['evidence']:
            e=entry['observation']
            if e['timestamp']>=r['event']['timestamp']:raise AssertionError('Non-past snapshot')
            if entry['kind']!='image_writer':continue
            key=(e['host'],'file:'+e['target_path']);f=add_node(key);a=add_node((e['host'],e['actor']))
            current=r['event'];child=add_node((current['host'],current['target'])) if current['target'] else None
            if f is not None and a is not None:edges[(a,f,'file_write')]=e['timestamp']
            if f is not None and child is not None:edges[(f,child,'image_path_join')]=current['timestamp']
    attrs=[]
    for key in nodes:
        is_file=key[1].startswith('file:')
        path,cmd=(key[1][5:],'') if is_file else index.describe(key,end)
        attrs.append(descriptor(path,cmd,event_vocab,is_file))
    seq=[];lengths=[]
    for key in central:
        events=histories[key][-max_events:];x=np.zeros((len(events),len(event_vocab)+2),np.float32)
        previous=events[0]['event']['timestamp']
        for i,r in enumerate(events):
            for token in r['tokens']:
                if token in event_vocab:x[i,event_vocab[token]]=1
            t=r['event']['timestamp'];x[i,-2]=np.log1p(max(0,(t-previous)/1e6));x[i,-1]=np.log1p(max(0,(end-t)/1e6));previous=t
        seq.append(x);lengths.append(len(x))
    edge_list=[];kinds=[];ages=[]
    buckets={'lt1s':0,'lt10s':1,'lt30s':2,'lt5m':3,'lt1h':4,'ge1h':5}
    for (a,b,kind),t in sorted(edges.items()):
        edge_list.extend([(a,b),(b,a)]);kinds.extend([kind,kind+'_reverse']);ages.extend([buckets[age_bucket(end-t)]]*2)
    return dict(node_attr=np.array(attrs),sequences=seq,lengths=np.array(lengths),central_count=len(central),
        edge_index=np.array(edge_list,dtype=np.int64).reshape(-1,2).T,edge_kind=kinds,edge_age=np.array(ages,np.int64)),dict(
        node_ids=nodes,end_timestamp=end,max_edge_timestamp=max_evidence_time,
        omitted_central=max(0,len(histories)-len(central)),truncated_process_sequences=sum(len(histories[k])>max_events for k in central))
