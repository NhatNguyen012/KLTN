These scripts are all designed to work on igraph exports of provenance graphs serialized and compressed as `pkl.xz` files. There are several vertex and edge attributes that must be present in order for them to work:

Vertices:

* `name`: Object name, by default this will be copied over to the graph as the vertex label
* `type`: Object type (process, file, regkey, socket, unknown)
* `time`: UNIX timestamp  
* `uuid`: Unique object identifier used for labeling

Edges:

* `type`: Edge relationship, most often syscall names. By default this is copied over to the graph as the edge label. At the moment the only edge type that has special handling is the `clone` type, used by `declone_processes`.
* `time`: UNIX timestamp

Description of scripts:

* `graph_helpers.py`: Helper functions for manipulating provenance igraphs.

* `dump_igraph.py`: Outputs every provenance vertex and edge relationship in kinda-pretty format.

* `dump_vertices.py`: Outputs every provenance vertex in kinda-pretty format. Used to seed the `color_graph` function with root causes and impacts. Dump the vertices into a csv file with the same name as your igraph pkl. Add a new column to each row with a preliminary "seed" label (start with `benign` or `contaminated`). Update root causes to the `root_cause` label and impact vertices to the `impact` label. If there are vertices you wish to add to the attack chain that won't naturally appear in the forward/backtraces, mark them manually with `attack`.

* `igraph_to_viz.py`: Outputs cleaned up visualization of the provenance graph using the igraph plot function. Calls the `color_graph` function to update seed labels via forward/backtraces. 

* `label_graph.py`: Basically does the same thing as the `igraph_to_viz.py` script but the output is the finalized labels instead of a visualization. Both scripts use the `color_graph` function to identify the attack graph from its root causes and impacts.
