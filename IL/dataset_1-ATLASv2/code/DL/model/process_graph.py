"""Small process-sequence MIL model with optional learned typed graph messages.

There is no independent binary head to veto a stage: a window's attack logit is
the maximum of its four stage-presence logits. Labels are consumed only by loss.
"""
import numpy as np
import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence,pad_packed_sequence


def collate_graphs(items,policy='reviewed'):
    node_attr=[];seq=[];edges=[];kinds=[];ages=[];central=[];owners=[];offset=0
    for owner,item in enumerate(items):
        g=item['features'];node_attr.append(g['node_attr']);seq.extend(g['sequences'])
        central.extend(offset+i for i in range(g['central_count']));owners.extend([owner]*g['central_count'])
        edges.append(g['edge_index']+offset);kinds.append(g['edge_kind']);ages.append(g['edge_age']);offset+=len(g['node_attr'])
    lengths=torch.tensor([len(x) for x in seq],dtype=torch.long)
    padded=torch.zeros(len(seq),int(lengths.max()),seq[0].shape[-1])
    for i,x in enumerate(seq):padded[i,:len(x)]=torch.from_numpy(x)
    reviewed=policy=='reviewed'
    result=dict(node_attr=torch.from_numpy(np.concatenate(node_attr)),sequences=padded,lengths=lengths,
        edge_index=torch.from_numpy(np.concatenate(edges,axis=1)),edge_kind=torch.from_numpy(np.concatenate(kinds)),
        edge_age=torch.from_numpy(np.concatenate(ages)),central_index=torch.tensor(central),owner=torch.tensor(owners),batch_size=len(items),
        binary_target=torch.tensor([x['original_label'] for x in items],dtype=torch.float32),
        stage_target=torch.from_numpy(np.stack([x['targets']['reviewed_stages' if reviewed else 'original_stages'] for x in items])),
        target_mask=torch.tensor([x['targets']['review_mask'] if reviewed else True for x in items]),
        sample_ids=[x['sample_id'] for x in items])
    if 'process_stage_target' in items[0]['targets']:
        result['process_stage_target']=torch.from_numpy(np.concatenate([x['targets']['process_stage_target'] for x in items]))
        result['process_target_mask']=torch.from_numpy(np.concatenate([x['targets']['process_target_mask'] for x in items]))
    return result


class TypedMessageLayer(nn.Module):
    def __init__(self,hidden,relations):
        super().__init__();self.relation=nn.Embedding(relations,8);self.age=nn.Embedding(6,4)
        self.message=nn.Sequential(nn.Linear(hidden+12,hidden),nn.GELU())
        self.update=nn.Sequential(nn.Linear(hidden*2,hidden),nn.GELU(),nn.Linear(hidden,hidden))
        nn.init.zeros_(self.update[-1].weight);nn.init.zeros_(self.update[-1].bias)

    def forward(self,h,edge_index,kind,age):
        src,dst=edge_index
        messages=self.message(torch.cat([h[src],self.relation(kind),self.age(age)],dim=1))
        aggregate=torch.zeros_like(h);aggregate.index_add_(0,dst,messages)
        degree=torch.zeros(len(h),1,device=h.device);degree.index_add_(0,dst,torch.ones(len(dst),1,device=h.device))
        aggregate=aggregate/degree.clamp(min=1)
        return h+self.update(torch.cat([h,aggregate],dim=1))


class ProcessGraphMIL(nn.Module):
    def __init__(self,event_dim,relations,*,graph=True,hidden=32):
        super().__init__();self.use_graph=graph
        self.node_encoder=nn.Sequential(nn.Linear(event_dim+3,hidden),nn.LayerNorm(hidden),nn.GELU())
        self.event_encoder=nn.Sequential(nn.Linear(event_dim+2,hidden),nn.LayerNorm(hidden),nn.GELU(),nn.Dropout(.1))
        self.sequence=nn.GRU(hidden,hidden,batch_first=True)
        self.layers=nn.ModuleList([TypedMessageLayer(hidden,relations) for _ in range(2)])
        self.classifier=nn.Sequential(nn.LayerNorm(hidden),nn.Linear(hidden,hidden),nn.GELU(),nn.Dropout(.1),nn.Linear(hidden,4))

    def forward(self,batch,return_process=False):
        h=self.node_encoder(batch['node_attr'])
        event=self.event_encoder(batch['sequences'])
        packed=pack_padded_sequence(event,batch['lengths'].cpu(),batch_first=True,enforce_sorted=False)
        output,last=self.sequence(packed);output,_=pad_packed_sequence(output,batch_first=True)
        mask=torch.arange(output.shape[1],device=output.device)[None,:]<batch['lengths'][:,None]
        maximum=output.masked_fill(~mask[:,:,None],-1e9).max(1).values
        process=.5*last[-1]+.5*maximum
        h=h.index_add(0,batch['central_index'],process)
        if self.use_graph:
            for layer in self.layers:h=layer(h,batch['edge_index'],batch['edge_kind'],batch['edge_age'])
        logits=self.classifier(h[batch['central_index']])
        window=torch.full((batch['batch_size'],4),-1e9,device=logits.device)
        window.scatter_reduce_(0,batch['owner'][:,None].expand_as(logits),logits,reduce='amax',include_self=True)
        return (window,logits) if return_process else window
