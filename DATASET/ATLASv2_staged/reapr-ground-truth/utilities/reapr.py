import csv
import json
import igraph
import matplotlib.pyplot as plt
import os
import sys
import argparse

from graph_helpers import *

def enable_postmortem():
    def excepthook(typ, value, tb):
        if hasattr(sys, "ps1") or not sys.stderr.isatty():
            # interactive mode, use default handler
            sys.__excepthook__(typ, value, tb)
        else:
            import traceback
            import pdb
            traceback.print_exception(typ, value, tb)
            print()
            pdb.post_mortem(tb)
    sys.excepthook = excepthook

if __name__ == "__main__":
    enable_postmortem()

    # increase stack size: some of the trace recursions are segfaulting
    import resource
    resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    sys.setrecursionlimit(int(1e9))

    # Parse args
    parser = argparse.ArgumentParser()
    parser.add_argument("igraph_file")
    parser.add_argument("-p", "--process", default="all")
    parser.add_argument("-d", "--data", default="none")
    #parser.add_argument("filter_list")
    args = parser.parse_args()

    # Read graphs
    base_fname = args.igraph_file
    print(base_fname)
    if args.igraph_file.endswith(".xz"):
        base_fname = args.igraph_file.replace(".xz", "")

    if base_fname.endswith(".pkl"):
        base_fname = base_fname.replace(".pkl", "")
    else:
        base_fname= base_fname.replace(".pickle", "")

    # Check if ".seeds" file exists, otherwise use ".csv"
    print(base_fname)
    if os.path.exists(base_fname + ".seeds"):
        seed_file = base_fname + ".seeds"
    else:
        seed_file = base_fname + ".csv"
    pdf_file = f"{base_fname}.pdf"
    print(seed_file)
    g = pickle_read(args.igraph_file)

    
    # read filter list
    with open("empirical_filter_set.json", "rt") as f:
        filter_list = set(json.load(f))

    if args.process not in {"inter", "intra", "all", "none"}:
        print(f"invalid -p argument: {args.process}")
        sys.exit(1)
    if args.data not in {"cluster", "leaf", "all", "none"}:
        print(f"invalid -d argument: {args.data}")
        sys.exit(1)

    print("===============================")
    print(f"IPC: {args.process}")
    print(f"data: {args.data}")
    print("===============================")

    print("Relabeling nodes and edges...")
    relabels(g)
    print("Recovering vertex times...")
    vertex_times(g)
    print("Coloring graph...")
    color_graph(g, seed_file, filter_list, args.process)

    attack_only(g)
    
    dump_edges(g, f"{base_fname}_edges.csv")
    dump_vertices(g, f"{base_fname}_vertices.csv")
    label_file = f"{base_fname}.labels"
    write_labels_file_attack_only(g, base_fname, label_file)
    
    if args.data in {"leaf", "all"}:
        print("Removing singleton data...")
        remove_singleton_data(g)
        prune_vertices(g, seed_file)
    if args.data in {"cluster", "all"} and not base_fname.startswith("fs"):
        print("Applying clustering to data objects...")
        contract_clustered_files(g)


    
    print("Cleaning Graph Visualization...")
    # Remove data entities that are not connected to a process
    #remove_orphan_data(g)
    # Mark UUID's on vertices to help interpret graph results
    # mark_uuids(g)
    # Mask all data names (name=*) to simplify visualization
    mask_data_names(g, seed_file)
    merge_vertices(g, seed_file)
    prune_edges(g)

    # for any path-like (contains \ or /), only take final component
    # This is applied to processes too so run it last or else processes
    # could get merged.
    relabel_name(g)
    
    print("Plotting %s of size V=%d, E=%d..." %(pdf_file, len(g.vs), len(g.es)))
    if g.vcount() == 0:
        print("\t...nevermind.")
        sys.exit(-1)

    if args.data != "all" and args.process != "all":
        print("Not producing graph for any control variant")
        sys.exit(0)

    g = g.permute_vertices(sorted(range(g.vcount()), key=lambda i: g.vs["start"][i]))
    layout = g.layout_sugiyama()
    g.vs["label"] = [v["name"] for v in g.vs]
    g.vs["shape"] = ["rectangle" for _ in g.vs]
    g.vs["height"] = [25 for _ in g.vs]
    g.vs["width"] = [50 + 10*(len(n)-1) for n in g.vs["name"]]

    # lamport_timestamps(g)
    g.es["label"] = [e["type"] for e in g.es]
    g.es["arrow_size"] = [1.25 for _ in g.es]

    igraph.plot(g, pdf_file, layout=layout, bbox=(2560, 1080), margin=200)

