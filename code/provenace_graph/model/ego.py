"""Construct explicit causal two-hop typed ego graphs, not aggregate tree features."""
from functools import lru_cache
from pathlib import Path
import sys
import numpy as np

PREPROCESS=Path(__file__).resolve().parents[1]/'preprocess'
sys.path.insert(0,str(PREPROCESS))
from graph import FACTS, Encoder, connect

ATTRIBUTES=['node=process','node=host','missing_metadata','unresolved_relation','cycle','truncated',*FACTS]
ATTRIBUTE_INDEX={name:i for i,name in enumerate(ATTRIBUTES)}


class EgoGraphs:
    def __init__(self, db, fanout=8, max_nodes=64, quantum_us=1):
        if min(fanout,quantum_us)<1 or max_nodes<4:raise ValueError('invalid graph limits')
        self.db,self.fanout,self.max_nodes,self.quantum=db,fanout,max_nodes,quantum_us
        self.lineage=Encoder(db,fanout,quantum_us)
        self.node_facts=lru_cache(maxsize=4096)(self._node_facts)
        self.sample=lru_cache(maxsize=2048)(self._sample)

    def _node_facts(self,host,proc,cutoff):
        if proc is None:
            rows=self.db.execute('SELECT DISTINCT fact FROM fact WHERE host=? AND t<?',(host,cutoff))
        else:
            rows=self.db.execute('SELECT fact FROM fact WHERE host=? AND proc=? AND t<?',(host,proc,cutoff))
        return tuple(sorted(r[0] for r in rows))

    def build(self,host,actor,t):
        if not host or not actor or t is None:
            x=np.zeros((2,len(ATTRIBUTES)),dtype=np.float32)
            x[0,0]=1;x[1,1]=1;x[:,2:4]=1;x.setflags(write=False)
            return dict(x=x,edges=(),root=0,host_root=1,node_keys=((host,actor),(host,None)),
                        cutoff_us=None,evidence=(),flags=('missing_identity_or_time',))
        # Keep the event's microsecond timestamp: rounding to the start of a
        # second hides genuinely earlier CREATE edges in that same second.
        return self.sample(host,actor,t//self.quantum*self.quantum)

    def _sample(self,host,actor,cutoff):
        keys=[];indices={};attrs=[];edges=set();evidence=[];flags=set()
        def node(h,p):
            key=(h,p)
            if key in indices:return indices[key]
            if len(keys)>=self.max_nodes:flags.add('truncated');return None
            i=len(keys);indices[key]=i;keys.append(key)
            x=np.zeros(len(ATTRIBUTES),dtype=np.float32)
            x[ATTRIBUTE_INDEX['node=host' if p is None else 'node=process']]=1
            facts=self.node_facts(h,p,cutoff)
            if not facts:x[ATTRIBUTE_INDEX['missing_metadata']]=1
            for fact in facts:x[ATTRIBUTE_INDEX[fact]]=1
            attrs.append(x);return i
        root=node(host,actor);host_root=node(host,None)
        chain,ancestry=self.lineage.ancestry(host,actor,cutoff)
        for _,proc,state in chain:
            if proc:
                n=node(host,proc);edges.add((host_root,n,'hosts'))
            if state in ('conflict','missing'):flags.add('unresolved_relation')
            elif state=='cycle':flags.add('cycle')
        for e in ancestry:
            edges.add((indices[(host,e['parent'])],indices[(host,e['child'])],'creates'))
            evidence.append(dict(e,relation='creates',host=host))
        visited={host};frontier=[host]
        for depth in range(2):
            next_hosts=[]
            for current in sorted(frontier):
                for direction in ('inbound','outbound'):
                    rows=self.db.execute('SELECT peer,t,source,line FROM flow WHERE host=? AND direction=? AND t<? ORDER BY peer LIMIT ?',
                                         (current,direction,cutoff,self.fanout+1)).fetchall()
                    if len(rows)>self.fanout:flags.add('truncated')
                    for ip,t,source,line in rows[:self.fanout]:
                        bindings=self.db.execute('SELECT host,t FROM binding WHERE ip=? AND t<? ORDER BY host LIMIT 2',(ip,cutoff)).fetchall()
                        if len(bindings)!=1:flags.add('unresolved_relation');continue
                        remote=bindings[0][0]
                        if remote==current:continue
                        a,b=node(current,None),node(remote,None)
                        if a is None or b is None:continue
                        src,dst=(a,b) if direction=='outbound' else (b,a)
                        edges.add((src,dst,'communicates'));edges.add((dst,src,'communicates_reverse'))
                        evidence.append(dict(relation='communicates',source_node=keys[src][0],target_node=keys[dst][0],
                                             timestamp_us=t,source_id=source,source_line=line,binding_timestamp_us=bindings[0][1]))
                        if remote not in visited:visited.add(remote);next_hosts.append(remote)
            frontier=next_hosts
        for f in flags:
            attrs[root][ATTRIBUTE_INDEX[f]]=1;attrs[host_root][ATTRIBUTE_INDEX[f]]=1
        x=np.stack(attrs);x.setflags(write=False)
        return dict(x=x,edges=tuple(sorted(edges)),root=root,host_root=host_root,node_keys=tuple(keys),
                    cutoff_us=cutoff,evidence=tuple(evidence),flags=tuple(sorted(flags)))
