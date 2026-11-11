from graph_helpers import *

igraph_file = sys.argv[1]

base_fname = igraph_file
if igraph_file.endswith("pkl.xz"):
    base_fname = igraph_file.replace(".pkl.xz", "")
else:
    base_fname= igraph_file.replace(".pickle", "")

seed_file = base_fname + ".csv"


g = pickle_read(igraph_file)

if False:
    print("Relabeling nodes and edges...")
    relabels(g)
    print("Recovering vertex times...")
    vertex_times(g)
    print("Coloring graph...")
    color_graph(g, seed_file)
    attack_only(g)    
    print("Decloning processes...")
    declone_processes(g)
    print("Pruning Edges...")
    prune_edges(g)
    print("Merging Vertices...")
    merge_vertices(g)
    print("Re-pruning Edges...")
    prune_edges(g)
    #lamport_timestamps(g)
mark_uuids(g)

time_dict = {}
for e in g.es:
    time_dict[e.index] = e["time"]


sorted_keys = sorted(time_dict, key=time_dict.get)

for k in sorted_keys:
    print_edge(g, k, "")

