from datetime import datetime, timedelta
import json
import os
import re
import pandas as pd
from torch_geometric.data import Data, Dataset
import torch
import torch
from tqdm import tqdm
import pickle as pkl

DURATION_EVENT = 1

NODES_TYPES = [
    "Node",
    "Process",
    "File",
    "Flow",
    "Module",
    "Thread",
    "Registry",
    "Task",
    "Shell",
    "Host",
    "Service",
    "User_session",
]

ACTION_TYPES = [
    "CREATE",
    "DELETE",
    "MODIFY",
    "READ",
    "RENAME",
    "WRITE",
    "MESSAGE",
    "OPEN",
    "START",
    "LOAD",
    "TERMINATE",
    "ADD",
    "EDIT",
    "REMOVE",
    "COMMAND",
    "REMOTE_CREATE",
    "GRANT",
    "INTERACTIVE",
    "LOGIN",
    "LOGOUT",
    "RDP",
    "REMOTE",
    "UNLOCK",
]


class CustomGraphDataset(Dataset):
    def __init__(self, path, host="", labels=None):
        super(CustomGraphDataset, self).__init__()

        if labels is not None:
            self.labels = self.extract_labels(labels, host)
        else:
            self.labels = []

        lst_graphs, label_graph, name_graph = self.create_graph(path)
        self.name_graph = name_graph

        self.data_list = []
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        for k, graph in tqdm(enumerate(lst_graphs)):
            x, edge_index, edge_attr, labels = self.extract_graph_data(
                graph, label_graph[k]
            )
            data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=labels).to(
                device
            )
            self.data_list.append(data)

    def extract_labels(self, path, hosts):
        print(path)
        labels = pd.read_csv(path)
        a_labels_ID = []
        for host in hosts:
            if f"SysClient0{host}.systemia.com" in labels["hostname"].values:
                a_labels_ID.extend(
                    labels[labels["hostname"] == f"SysClient0{host}.systemia.com"][
                        "timestamp"
                    ].values
                )
        return a_labels_ID

    def len(self):
        return len(self.data_list)

    def get(self, idx):
        return self.data_list[idx]

    def set(self, idx, data):
        self.data_list[idx] = data

    def extract(self, file):
        print(file)
        with open(file, "rb") as f:
            data = pkl.load(f)
        return data

    def create_graph(self, path):
        list_graph = []
        label_graph = {}
        name_graph = []
        for k, file in tqdm(enumerate(path)):
            start_time = file.split("/")[-1].replace(".pkl", "")
            end_time = period(start_time, 15)

            label_graph[k] = [0]
            for l in self.labels:
                if start_time <= l <= end_time:
                    label_graph[k] = [1]
                    break

            name_graph.append(file)
            print(file)
            G = self.extract(file)
            list_graph.append(G)

        return list_graph, label_graph, name_graph

    def extract_graph_data(self, G, labels):
        x = []
        # labels = []
        for node in G.nodes(data=True):
            # Create labels and node feature
            # if node[0].ID in labels_ID[0] or node[0].ID in labels_ID[1]:
            #    labels.append(1)
            # else:
            #    labels.append(0)
            x.append([NODES_TYPES.index(node[0].type), node[0].lifetime()])
        x = torch.tensor(x, dtype=torch.float)
        labels = torch.tensor(labels, dtype=torch.float)

        # Create edge index and edge_attr
        edge_index = []
        edge_attr = []
        times = []
        for edge in G.edges(data=True):
            edge_index.append([edge[0].num, edge[1].num])
            edge_attr.append([ACTION_TYPES.index(edge[2]["action"]), edge[2]["time"]])
            times.append(edge[2]["time"])
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(edge_attr, dtype=torch.float)

        return x, edge_index, edge_attr, labels


class Node:
    def __init__(self, num, ID, type, start, end, red):
        super(Node, self).__init__()
        self.num = num
        self.ID = ID
        self.type = type
        self.start = start
        self.end = end
        self.red = red
        self.not_real_end = True

    def manage_time(self, time):
        if self.start < time <= self.end:
            if self.not_real_end:
                self.end = time
                self.not_real_end = False
            return
        elif time > self.end:
            self.end = time
            return

    def lifetime(self):
        return self.end - self.start

    def manage_red(self, red):
        if self.red == 1:
            return
        else:
            self.red = red


def _create_folder(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)


def save(G, file):
    folder, _ = os.path.split(file)
    _create_folder(folder)
    with open(file, "wb") as file:
        pkl.dump(G, file)


def period(start, duration):
    datetime_object_start = transform_date(start)
    datatime_object_end = datetime_object_start + timedelta(minutes=duration)
    end = datatime_object_end.isoformat(timespec="milliseconds")
    return end


def save_json(datas, file):
    if len(datas) == 0:
        print("No data")
        return
    with open(file, "w") as outfile:
        for data in datas:
            json.dump(data, outfile)
            outfile.write("\n")


def transform_date(time):
    datetimeisoformat1_re = re.compile(r"(\.\d)(-04)")
    datetimeisoformat2_re = re.compile(r"(\.\d\d)(-04)")
    if datetimeisoformat1_re.search(time):
        return datetime.fromisoformat(re.sub(r"(\.\d)(-04)", r"\g<1>00-04", time))
    elif datetimeisoformat2_re.search(time):
        return datetime.fromisoformat(re.sub(r"(\.\d\d)(-04)", r"\g<1>0-04", time))
    else:
        return datetime.fromisoformat(time)
