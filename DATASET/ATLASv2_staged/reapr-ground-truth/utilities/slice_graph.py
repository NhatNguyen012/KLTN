# attack_igraph_carbanak.py
"""
This script extracts a subgraph (attack graph) from the full provenance graph based on user-specified timestamps.
It allows for temporal analysis of events within a specific time range.
"""

import sys
from graph import GraphBuilder
from dateutil.parser import parse
from graph_helpers import pickle_read
import datetime


def load_graph(input_file):
    """Loads the serialized graph from a pickle file."""
    # graph = GraphBuilder.read_csv(input_file)
    graph = pickle_read(input_file)
    return graph


def filter_graph_by_time(graph, start_time, end_time):
    """Filters the graph to include only nodes and edges within the specified time range."""
    start_unix = convert_to_unix_time(start_time)
    end_unix = convert_to_unix_time(end_time)

    # Filter vertices and edges by time
    subgraph = graph.subgraph_edges(
        [e.index for e in graph.es if start_unix <= e["start"] <= end_unix]
    )
    return subgraph


def convert_to_unix_time(utc_timestamp):
    """Converts a UTC timestamp string to Unix time in nanoseconds."""
    dt_object = parse(utc_timestamp)
    return int(datetime.datetime.timestamp(dt_object))


def save_attack_graph(graph, output_prefix):
    """Saves the filtered attack graph to disk."""
    graph.write_pickle(output_prefix + ".pickle")
    # graph.write_dot(output_prefix + ".dot")


def main(argv):
    """Handles command-line arguments, loads the graph, filters it by time, and saves the attack graph."""
    try:
        input_file = argv[1]
        start_time = argv[2]
        end_time = argv[3]
        output_prefix = argv[4] if len(argv) > 4 else "carbanak_attack_graph"
    except IndexError:
        print(
            "Usage: python slice_graph.py INPUT_FILE START_TIME END_TIME [OUTPUT_PREFIX]"
        )
        sys.exit(1)

    graph = load_graph(input_file)
    attack_graph = filter_graph_by_time(graph, start_time, end_time)
    save_attack_graph(attack_graph, output_prefix)
    print(
        f"Attack graph saved as {output_prefix}.pickle and {output_prefix}.dot"
    )


if __name__ == "__main__":
    main(sys.argv)
