import argparse
import copy
import pickle as pkl
import os
import json
import networkx as nx
from tqdm import tqdm
from datetime import datetime, timedelta
import gzip
import re
import concurrent.futures
from utils import (
    _create_folder,
    save,
    period,
    save_json,
    transform_date,
    Node,
)


class Graph_builder:
    def __init__(self, data, nodes):
        self.data = data
        self.nodes = nodes
        self.num = 0
        self.start = 0
        self.labels = 0
        self.g = self.build_graph()

    def get_g(self):
        return self.g

    def get_nodes(self):
        return self.nodes

    def is_in_line(self, id_, line):
        if id_ in line:
            return line[id_]
        else:
            return -1

    def build_graph(self):
        g = nx.MultiDiGraph()
        data = self.data
        for line in tqdm(data):
            g = self.add_one_log_into_graph(line, g)
        print(len(g.nodes()), len(g.edges()), self.labels)
        return g

    def add_one_log_into_graph(self, line, g):
        # Manage time
        time_event = int(transform_date(self.is_in_line("timestamp", line)).timestamp())
        if self.start == 0:
            self.start = time_event
            time = self.start
        else:
            time = time_event - self.start

        # Action and label of the event
        action = self.is_in_line("action", line)
        red = self.is_in_line("label", line)
        self.labels += int(red)

        # Retrieve or create nodes
        isnewsrc, src, isnewdest, dest = self.build_nodes(line, time_event, red)

        if isnewsrc:
            g.add_node(src, type=src.type)
        if isnewdest:
            g.add_node(dest, type=dest.type)

        g.add_edge(
            src,
            dest,
            action=action,
            time=time,
            red=red,
        )
        return g

    def build_nodes(self, line, time, red):
        # Actor
        actor = self.is_in_line("actorID", line)
        type = "Process"
        isnewsrc, src = self.find_nodes(actor, time, type, red)
        # Destination
        object = self.is_in_line("objectID", line)
        type = self.is_in_line("object", line).capitalize()
        isnewdest, dest = self.find_nodes(object, time, type, red)
        return isnewsrc, src, isnewdest, dest

    def find_nodes(self, ID, time, type, red):
        if ID in self.nodes.keys():
            # Retrieve node
            self.nodes[ID] = copy.deepcopy(self.nodes[ID])
            self.nodes[ID].manage_time(time)
            self.nodes[ID].manage_red(red)
            return False, self.nodes[ID]
        else:
            # Create a node
            node = Node(self.num, ID, type, time, time + 1, red)
            self.nodes[ID] = node
            self.num += 1
            return True, node


def extract_data(file, duration, save_folder):
    print("Extract: ", file)
    graph = []
    nodes = {}
    start = None
    end = None
    with gzip.open(file, "r") as f:
        for line in f:
            ob = json.loads(line)

            # Set the start, regarding first element of the json.
            if start == None:
                start = ob["timestamp"]
                end = period(start, duration)

            if start <= ob["timestamp"] < end:
                graph.append(ob)

            elif len(graph) > 0:
                # Create a graph
                ob_graph = Graph_builder(graph, nodes)
                save(
                    ob_graph.get_g(),
                    f"{save_folder}/{duration}/{start}.pkl",
                )
                print(f"{save_folder}/{duration}/{start}.pkl")
                nodes = ob_graph.get_nodes()
                graph = []
                graph.append(ob)
                start = ob["timestamp"]
                end = period(start, duration)

    ob_graph = Graph_builder(graph, nodes)
    save(
        ob_graph.get_g(),
        f"{save_folder}/{duration}/{start}.pkl",
    )
    return


def logs_from_folder_client(clients_data, folder_client, duration):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(extract_data, file, duration, folder_client): file
            for file in clients_data[folder_client]
        }
    return


def clients_files_graph(folder, clients, folder_save):
    clients_data = {}
    for c in clients:
        folder_c = folder.replace("/client/", f"/{c}/")
        folder_save_c = folder_save.replace("/client/", f"/{c}/")
        clients_data[folder_save_c] = []
        print(folder_c)
        for root, _, files in os.walk(folder_c):
            clients_data[folder_save_c].extend(
                [f"{root}/{f}" for f in files if f"0{c}" in f and "Label" not in f]
            )
    return clients_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build graphs from json files.")
    parser.add_argument(
        "-v",
        "--optc-version",
        dest="version",
        action="store",
        default="original",
        help="version of the OpTC: original, corrected.",
    )
    parser.add_argument(
        "-d",
        "--duration-graph",
        dest="duration",
        action="store",
        default=15,
        type=int,
        help="Graph duration in minutes",
    )
    parser.add_argument(
        "-f",
        "--graph_folder",
        dest="folder_graph",
        action="store",
        type=str,
        default="/client/",
        help="Folder that contains file to create graphs. Put 'client' instead of real client number identifier.",
    )
    parser.add_argument(
        "-fs",
        "--graph_folder_save",
        dest="folder_save",
        action="store",
        type=str,
        default="graphs/client/",
        help="Folder that contains graphs. Put 'client' instead of real client number identifier.",
    )
    args = parser.parse_args()

    try:
        fol = "data/OPTC_clients_suspect/evaluation/2019-09-25/AIA-51-75"
        fol_s = (
            "Pygod/"
            + args.folder_save
            + "/original/"
        )
        clients = ["051"]
        clients_files = clients_files_graph(fol, clients, fol_s)
        print(clients_files)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(
                    logs_from_folder_client,
                    clients_files,
                    folder_c,
                    args.duration,
                ): folder_c
                for folder_c in clients_files.keys()
            }

    except Exception as e:
        print(f"Error {e}")
        exit(1)
