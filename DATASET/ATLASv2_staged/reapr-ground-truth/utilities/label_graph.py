from graph_helpers import *

# Graph Input File
igraph_file = sys.argv[1]

# Remove file extension for base filename
base_fname = igraph_file
if igraph_file.endswith("pkl.xz"):
    base_fname = igraph_file.replace(".pkl.xz", "")
else:
    base_fname= igraph_file.replace(".pickle", "")

# Labels Input File is csv of base fname
seed_file = base_fname + ".csv"

# Output Files
pdf_file = base_fname + ".pdf" # Graph vizualization
label_file = base_fname + ".labels" # Full labels
output_seeds_file = base_fname + ".seeds" # Seeds for reproducibility

g = pickle_read(igraph_file)

vertex_times(g)
contaminate_graph(g, seed_file)
color_graph(g, seed_file)

for v in range(0,len(g.vs)):
    vertex = g.vs[v]
    
    if "attack_label" in vertex.attributes():
        vertex["label"] = "attack"
    elif "contaminate_label" in vertex.attributes():
        vertex["label"] = "contaminated"
    else:
        vertex["label"] = "benign"

# Remove path from displayname
display_name = base_fname.split("/")
display_name = display_name[len(display_name)-1]

# Write full label set out with ".labels" extension
labels_f = open(label_file, "w")
for v in range(0,len(g.vs)):
    vertex = g.vs[v]
    vertex_id = vertex["pid"] if "atlasv2" in base_fname else  vertex["uuid"]
    labels_f.write("%s, %s, %s, %s\n"
                   % (display_name, vertex_id, vertex["name"], vertex["label"]))
labels_f.close()



# Write root_cause/impact seed labels out with ".seeds" extension
#  this is so that we can eventually rerun the labeling script with the whole graph in memory
#  to ensure we capture all of the contaminates.
seed_labels = get_seed_labels(seed_file)
seeds_f = open(output_seeds_file, "w")

g = pickle_read(igraph_file) # Pull fresh copy of graph to replicate dump_vertices format
vertex_times(g)
for v in range(0,len(g.vs)):
    vertex = g.vs[v]
    time = int(vertex["min_time"])
    vertex_id = vertex["pid"] if "atlasv2" in base_fname else  vertex["uuid"]
    if vertex_id in seed_labels and seed_labels[vertex_id] in ["root_cause", "impact"]:
        seeds_f.write("%d,%s,\"%s\",%s,%s\n" %
                      (time, vertex["type"], vertex["name"], vertex_id, seed_labels[vertex_id]))
seeds_f.close()
