import os
import pickle
import sys
import csv
import re
from collections import defaultdict


def parse_program_name(path):
    """Extracts the program name from a file path."""
    match = re.search(r"[^\\/]+$", path)
    return match.group(0).lower() if match else path.lower()


def process_graphs(graph_dir):
    """Processes graphs to extract crossproc and filemod information."""
    crossproc_counts = defaultdict(int)  # { (prog_name, uuid): count }
    neighbors_lists = defaultdict(lambda: defaultdict(int))  # For crossproc

    filemod_counts = defaultdict(int)  # { (prog_name, uuid): count }
    file_targets_lists = defaultdict(lambda: defaultdict(int))  # For filemod

    for igraph_file in os.listdir(graph_dir):
        if not igraph_file.endswith(".pkl"):
            continue

        g = pickle.load(open(os.path.join(graph_dir, igraph_file), "rb"))

        vertex_info = {
            v.index: (parse_program_name(v["name"]), v["uuid"]) for v in g.vs
        }

        # Crossproc edges
        for e in g.es.select(type_in=["crossproc_in", "crossproc_out"]):
            src_info = vertex_info[e.source]
            tgt_info = vertex_info[e.target]

            crossproc_counts[src_info] += 1
            crossproc_counts[tgt_info] += 1

            neighbors_lists[src_info][tgt_info[0]] += 1
            neighbors_lists[tgt_info][src_info[0]] += 1

        # Filemod edges
        for e in g.es.select(type="filemod"):
            src_info = vertex_info[e.source]
            tgt_vertex = g.vs[e.target]
            tgt_file = parse_program_name(tgt_vertex["name"])

            filemod_counts[src_info] += 1
            file_targets_lists[src_info][tgt_file] += 1

    return crossproc_counts, neighbors_lists, filemod_counts, file_targets_lists


def compute_counts(count_dict):
    """Computes number of program executions and distinct processes."""
    name_counts = defaultdict(int)
    distinct_proc_counts = defaultdict(int)

    for (name, _), count in count_dict.items():
        name_counts[name] += count
        distinct_proc_counts[name] += 1

    return name_counts, distinct_proc_counts


def derive_candidates(stats_dict, counts_dict, neighbors_dict, threshold=10):
    """Derives exclusion candidates based on average event frequency."""
    cur_stats = stats_dict.copy()
    exclusion_candidates = []

    while cur_stats:
        cur_exclusion_candidate = max(
            cur_stats.items(), key=lambda x: x[1][1]  # avg events
        )
        candidate_prog_name, (_, avg_events, _) = cur_exclusion_candidate

        if avg_events <= threshold:
            break

        exclusion_candidates.append(candidate_prog_name)
        del cur_stats[candidate_prog_name]

        filtered_counts = {
            k: v for k, v in counts_dict.items() if k[0] not in exclusion_candidates
        }
        name_counts, distinct_proc_counts = compute_counts(filtered_counts)
        cur_stats = {
            name: (
                distinct_proc_counts[name],
                name_counts[name] / distinct_proc_counts[name],
                neighbors_dict.get((name, None), {}),
            )
            for name in name_counts
        }

    return exclusion_candidates


def save_csv(filename, stats, neighbors_dict):
    """Writes stats and neighbor/target info to CSV."""
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["prog_name", "num_prog_exe", "avg_events", "explosion_metric", "neighbors"]
        )

        for prog_name, (num_exe, avg_events, _) in stats:
            total_events = num_exe * avg_events
            neighbors = {}

            for key in neighbors_dict:
                if key[0] == prog_name:
                    for neighbor, count in neighbors_dict[key].items():
                        neighbors[neighbor] = neighbors.get(neighbor, 0) + count

            sorted_neighbors = sorted(
                neighbors.items(), key=lambda x: x[1], reverse=True
            )

            writer.writerow(
                [prog_name, num_exe, avg_events, total_events, sorted_neighbors]
            )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_graphs.py <graph_directory>")
        sys.exit(1)

    graph_dir = sys.argv[1]

    print("Processing graph files...")
    crossproc_counts, neighbors_lists, filemod_counts, file_targets_lists = process_graphs(graph_dir)

    print("Computing CROSSPROC stats...")
    cp_name_counts, cp_distinct_proc_counts = compute_counts(crossproc_counts)
    crossproc_stats = {
        name: (
            cp_distinct_proc_counts[name],
            cp_name_counts[name] / cp_distinct_proc_counts[name],
            neighbors_lists.get((name, None), {}),
        )
        for name in cp_name_counts
    }

    print("Computing FILEMOD stats...")
    fm_name_counts, fm_distinct_proc_counts = compute_counts(filemod_counts)
    filemod_stats = {
        name: (
            fm_distinct_proc_counts[name],
            fm_name_counts[name] / fm_distinct_proc_counts[name],
            file_targets_lists.get((name, None), {}),
        )
        for name in fm_name_counts
    }

    # print("Deriving exclusion candidates for CROSSPROC...")
    # crossproc_exclusions = derive_candidates(crossproc_stats, crossproc_counts, neighbors_lists)
    # print("Derived CROSSPROC exclusions:", crossproc_exclusions)

    # print("Deriving exclusion candidates for FILEMOD...")
    # filemod_exclusions = derive_candidates(filemod_stats, filemod_counts, file_targets_lists)
    # print("Derived FILEMOD exclusions:", filemod_exclusions)

    print("Saving CSVs...")
    save_csv("crossproc_stats.csv", sorted(crossproc_stats.items(), key=lambda x: x[1][1], reverse=True), neighbors_lists)
    save_csv("filemod_stats.csv", sorted(filemod_stats.items(), key=lambda x: x[1][1], reverse=True), file_targets_lists)

    print("Done.")
