"""Event-only v5a two-layer relational mean GraphSAGE in NumPy.

No tree classifier, GNN framework, or node-ID embedding. Explicit backpropagation
is finite-difference tested. Returns node embeddings and an optional binary head.
"""
import os
import numpy as np

RELATIONS = ('creates', 'communicates', 'communicates_reverse', 'hosts',
             'performs', 'performs_reverse')


class RelationalSAGE:
    def __init__(self, input_dim, hidden=32, embedding=16, seed=1):
        if min(input_dim, hidden, embedding) < 1:
            raise ValueError('positive dimensions required')
        self.input_dim, self.hidden, self.embedding = input_dim, hidden, embedding
        rng = np.random.default_rng(seed)
        self.params = {}
        for layer, a, b in [(1, input_dim, hidden), (2, hidden, embedding)]:
            for relation in ('self', *RELATIONS):
                self.params[f'W{layer}_{relation}'] = rng.normal(0, np.sqrt(2/(a+b)), (a,b))
            self.params[f'b{layer}'] = np.zeros(b)
        self.params['head'] = rng.normal(0, 1/np.sqrt(2*embedding), 2*embedding)
        self.params['bias'] = np.zeros(1)
        self.steps = 0
        self.m = {k: np.zeros_like(v) for k,v in self.params.items()}
        self.v = {k: np.zeros_like(v) for k,v in self.params.items()}

    @property
    def parameter_count(self):
        return sum(v.size for v in self.params.values())

    def adjacency(self, graph):
        n = len(graph['x']); matrices = {r:np.zeros((n,n)) for r in RELATIONS}
        for src, dst, relation in graph['edges']:
            if not (0 <= src < n and 0 <= dst < n) or relation not in matrices:
                raise ValueError('invalid graph edge')
            matrices[relation][dst, src] = 1
        for r,A in matrices.items():
            matrices[r] = A / np.maximum(A.sum(axis=1,keepdims=True),1)
        return matrices

    def forward(self, graph):
        x = np.asarray(graph['x'], dtype=float)
        if x.ndim != 2 or x.shape[1] != self.input_dim or not np.isfinite(x).all():
            raise ValueError('invalid node attributes')
        A = self.adjacency(graph); layers=[];h=x
        for layer in (1,2):
            z = h @ self.params[f'W{layer}_self'] + self.params[f'b{layer}']
            for r in RELATIONS:z += (A[r] @ h) @ self.params[f'W{layer}_{r}']
            layers.append((h,z));h=np.maximum(z,0)
        root,host=graph['root'],graph['host_root']
        readout=np.concatenate([h[root],h[host]])
        logit=float(readout @ self.params['head'] + self.params['bias'][0])
        return logit,h,(A,layers,readout)

    def predict(self, graph):
        logit,h,_=self.forward(graph)
        probability=float(np.exp(-np.logaddexp(0,-logit)))
        return dict(probability=probability, process_embedding=h[graph['root']].copy(),
                    host_embedding=h[graph['host_root']].copy())

    def loss_gradient(self, graph, label, positive_weight=1.):
        if label not in (0,1) or positive_weight <= 0:raise ValueError('invalid label/weight')
        logit,h,(A,layers,readout)=self.forward(graph)
        weight=positive_weight if label else 1.
        loss=weight*(np.logaddexp(0,logit)-label*logit)
        delta=weight*(np.exp(-np.logaddexp(0,-logit))-label)
        gradients={k:np.zeros_like(v) for k,v in self.params.items()}
        gradients['head']=delta*readout;gradients['bias'][0]=delta
        dh=np.zeros_like(h);dh[graph['root']]+=delta*self.params['head'][:self.embedding]
        dh[graph['host_root']]+=delta*self.params['head'][self.embedding:]
        for layer in (2,1):
            before,z=layers[layer-1];dz=dh*(z>0)
            gradients[f'W{layer}_self']=before.T@dz;gradients[f'b{layer}']=dz.sum(axis=0)
            previous=dz@self.params[f'W{layer}_self'].T
            for r in RELATIONS:
                gradients[f'W{layer}_{r}']=(A[r]@before).T@dz
                previous += A[r].T @ (dz@self.params[f'W{layer}_{r}'].T)
            dh=previous
        return float(loss),gradients

    def train_batch(self, examples, learning_rate=.001, positive_weight=1., weight_decay=1e-5):
        if not examples:raise ValueError('empty batch')
        gradients={k:np.zeros_like(v) for k,v in self.params.items()};loss=0.
        for graph,label in examples:
            value,g=self.loss_gradient(graph,int(label),positive_weight);loss+=value
            for k in gradients:gradients[k]+=g[k]/len(examples)
        self.steps+=1
        for k,value in self.params.items():
            g=gradients[k]+weight_decay*value
            self.m[k]=.9*self.m[k]+.1*g;self.v[k]=.999*self.v[k]+.001*g*g
            value-=learning_rate*(self.m[k]/(1-.9**self.steps))/(np.sqrt(self.v[k]/(1-.999**self.steps))+1e-8)
        return loss/len(examples)

    def save(self, path):
        # Callers must validate publication path; no pickle payloads.
        with open(path,'wb') as f:
            np.savez_compressed(f,dimensions=[self.input_dim,self.hidden,self.embedding],steps=self.steps,
                                **self.params,**{'adam_m_'+k:v for k,v in self.m.items()},
                                **{'adam_v_'+k:v for k,v in self.v.items()})
            f.flush();os.fsync(f.fileno())

    @classmethod
    def load(cls,path):
        with np.load(path,allow_pickle=False) as d:
            model=cls(*map(int,d['dimensions']));model.steps=int(d['steps'])
            for k in model.params:
                if d[k].shape != model.params[k].shape:raise ValueError('checkpoint shape mismatch')
                model.params[k]=d[k].copy();model.m[k]=d['adam_m_'+k].copy();model.v[k]=d['adam_v_'+k].copy()
        return model
