"""Tests for actual message passing, analytic gradients, and learned predictions."""
from pathlib import Path
import sys,tempfile,unittest
import numpy as np
HERE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(HERE/'model'),str(HERE/'preprocess')]
from relational_sage import RelationalSAGE
from ego import EgoGraphs,ATTRIBUTES
from graph import connect,observe,timestamp


def toy(signal):
    # Root and parent have identical attributes in both classes. Only the
    # grandparent's attribute differs; it reaches root through two CREATE edges.
    x=np.zeros((4,3));x[0,0]=1;x[1,0]=1;x[2,1]=signal;x[3,2]=1
    return dict(x=x,edges=((2,1,'creates'),(1,0,'creates'),(3,0,'hosts')),root=0,host_root=3)


class LearnedTests(unittest.TestCase):
    def test_two_hop_signal_and_edge_removal(self):
        model=RelationalSAGE(3,8,4)
        a,b=toy(0),toy(1)
        self.assertFalse(np.allclose(model.predict(a)['process_embedding'],model.predict(b)['process_embedding']))
        a=dict(a,edges=((1,0,'creates'),));b=dict(b,edges=((1,0,'creates'),))
        np.testing.assert_allclose(model.predict(a)['process_embedding'],model.predict(b)['process_embedding'])
    def test_parameter_gradients(self):
        model=RelationalSAGE(3,4,3,seed=8);g=toy(1);_,analytic=model.loss_gradient(g,1)
        epsilon=1e-5
        for key in model.params:
            value=model.params[key];idx=np.unravel_index(np.argmax(np.abs(analytic[key])),value.shape);old=value[idx]
            value[idx]=old+epsilon;upper=model.loss_gradient(g,1)[0]
            value[idx]=old-epsilon;lower=model.loss_gradient(g,1)[0];value[idx]=old
            self.assertAlmostEqual(float(analytic[key][idx]),(upper-lower)/(2*epsilon),places=5,msg=key)
    def test_learns_and_checkpoint_preserves_optimizer(self):
        model=RelationalSAGE(3,8,4);data=[(toy(0),0),(toy(1),1)]
        initial=sum(model.loss_gradient(g,y)[0] for g,y in data)
        for _ in range(150):model.train_batch(data,learning_rate=.02)
        final=sum(model.loss_gradient(g,y)[0] for g,y in data)
        self.assertLess(final,initial*.1);self.assertLess(model.predict(toy(0))['probability'],.1)
        self.assertGreater(model.predict(toy(1))['probability'],.9)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'model.npz';model.save(path);other=RelationalSAGE.load(path)
            model.train_batch(data);other.train_batch(data)
            for key in model.params:np.testing.assert_array_equal(model.params[key],other.params[key])
    def test_node_order_equivariance(self):
        model=RelationalSAGE(3,8,4);g=toy(1);order=np.array([2,0,3,1]);inv=np.argsort(order)
        perm=dict(x=g['x'][order],edges=tuple((int(inv[a]),int(inv[b]),r) for a,b,r in g['edges']),
                  root=int(inv[g['root']]),host_root=int(inv[g['host_root']]))
        self.assertAlmostEqual(model.predict(g)['probability'],model.predict(perm)['probability'])
    def test_ego_graph_has_real_edges_and_no_future_or_label_attributes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=connect(Path(tmp)/'graph.sqlite')
            def record(sec,a,b,image):return dict(hostname='h',actorID=a,objectID=b,object='PROCESS',action='CREATE',
                timestamp=f'2019-09-23T00:00:{sec:02d}+00:00',properties=dict(image_path=image),label=1)
            observe(db,record(1,'grand','parent','powershell.exe'),'s',1)
            observe(db,record(3,'parent','child','notepad.exe'),'s',2)
            observe(db,record(30,'future','grand','cmd.exe'),'s',3);db.commit()
            graph=EgoGraphs(db).build('h','child',timestamp('2019-09-23T00:00:20+00:00'))
            self.assertEqual(sum(r=='creates' for _,_,r in graph['edges']),2)
            self.assertNotIn(('h','future'),graph['node_keys'])
            self.assertEqual(graph['x'].shape[1],len(ATTRIBUTES))
            self.assertFalse(any('label' in a or 'uuid' in a for a in ATTRIBUTES))
            db.close()

    def test_same_second_create_is_visible_only_when_strictly_earlier(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=connect(Path(tmp)/'graph.sqlite')
            def create(at, actor, child, line):
                observe(db, dict(hostname='h', actorID=actor, objectID=child,
                    object='PROCESS', action='CREATE', timestamp=at,
                    properties=dict(image_path='powershell.exe')), 's', line)
            create('2019-09-23T00:00:56.100000+00:00', 'grand', 'parent', 1)
            create('2019-09-23T00:00:56.169000+00:00', 'parent', 'child', 2)
            create('2019-09-23T00:00:56.190000+00:00', 'future', 'child', 3)
            db.commit()
            at_parent=EgoGraphs(db).build('h','child',timestamp('2019-09-23T00:00:56.169000+00:00'))
            self.assertFalse(any(edge[2]=='creates' for edge in at_parent['edges']))
            graph=EgoGraphs(db).build('h','child',timestamp('2019-09-23T00:00:56.189000+00:00'))
            self.assertEqual(graph['cutoff_us'],timestamp('2019-09-23T00:00:56.189000+00:00'))
            self.assertEqual(sum(edge[2]=='creates' for edge in graph['edges']),2)
            self.assertNotIn(('h','future'),graph['node_keys'])
            self.assertTrue(all(e['timestamp_us']<graph['cutoff_us'] for e in graph['evidence']))
            db.close()


if __name__=='__main__':unittest.main()
