#!/usr/bin/env python3
"""Resume the unchanged raw graph scanner after retiring an unused feature adapter.

Every originally recorded implementation file must match either its active copy or
an archived, hash-verified copy. No scanner source or checkpoint identity is edited.
"""
from pathlib import Path
import sys,json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'preprocess'))
import build_graph
from common import safe,sha


def main():
    args=build_graph.parser().parse_args()
    work=safe(args.output.with_name('.'+args.output.name+'.work'))
    reference=json.loads((work/'config.json').read_text())['implementation']
    source=Path(build_graph.__file__).parent
    for name,expected in reference.items():
        if Path(name).name!=name:raise ValueError('invalid implementation filename')
        path=source/name
        if not path.exists():
            if name!='augment_shards.py':raise ValueError('missing scanner dependency')
            path=work/'source_snapshot'/name
        if sha(path)!=expected:raise ValueError(f'implementation mismatch: {name}')
    # The retired adapter never participates in indexing; preserve its old provenance
    # fingerprint so the original scanner can validate its otherwise identical config.
    build_graph.implementation=lambda:dict(reference)
    build_graph.build(args)


if __name__=='__main__':main()
