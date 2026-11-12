"""
This module handles generic operations for building and manipulating graphs using the iGraph library.
It provides functions to add nodes and edges, build the graph in bulk, and export the graph to various formats.
This file is designed to be dataset-agnostic and can be used with different datasets.
"""

import igraph as ig
import csv
import copy
import lzma
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class NodeAttr:
    type: str
    name: str
    time: int  # Unix time in nanoseconds
    uuid: str


@dataclass
class EdgeAttr:
    type: str
    time: int  # Unix time in nanoseconds
    uuid: str
    etime: Optional[int] = None  # End time (optional, for time window analysis)


class GraphBuilder:
    """A class for building graphs using the iGraph library, designed to support bulk operations for performance."""

    node_fields = ["type", "name", "time", "uuid"]
    edge_fields = ["type", "time", "uuid", "etime"]

    def __init__(self):
        self.node_attrs = []
        self.edges = []
        self.edge_attrs = []

    def add_node(self, id: int, type: str, name: str, time: int, uuid: str):
        """Adds a node to the internal data structure."""
        self.node_attrs.append(NodeAttr(type=type, name=name, time=time, uuid=uuid))

    def add_edge(
        self,
        src_id: int,
        dst_id: int,
        type: str,
        time: int,
        uuid: str,
        etime: Optional[int] = None,
    ):
        """Adds an edge between two nodes with optional end time."""
        if etime is None:
            etime = time
        self.edges.append((src_id, dst_id))
        self.edge_attrs.append(EdgeAttr(type=type, time=time, uuid=uuid, etime=etime))
        return len(self.edges) - 1

    def build(self) -> ig.Graph:
        """Constructs the iGraph object from the internal data."""
        vertex_attrs = {
            field: [getattr(n, field) for n in self.node_attrs]
            for field in self.node_fields
        }
        edge_attrs = {
            field: [getattr(e, field) for e in self.edge_attrs]
            for field in self.edge_fields
        }
        return ig.Graph(
            n=len(self.node_attrs),
            edges=self.edges,
            directed=True,
            vertex_attrs=vertex_attrs,
            edge_attrs=edge_attrs,
        )

    def write_csv(self, out_prefix: str):
        """Exports the graph to CSV files."""
        node_path = f"{out_prefix}.nodes.csv.xz"
        edge_path = f"{out_prefix}.edges.csv.xz"

        with lzma.open(node_path, "wt") as f:
            writer = csv.DictWriter(f, self.node_fields)
            writer.writeheader()
            for attr in self.node_attrs:
                writer.writerow(attr.__dict__)

        with lzma.open(edge_path, "wt") as f:
            writer = csv.DictWriter(f, ["src", "dst"] + self.edge_fields)
            writer.writeheader()
            for (src, dst), attr in zip(self.edges, self.edge_attrs):
                row = copy.deepcopy(attr.__dict__)
                row["src"] = src
                row["dst"] = dst
                writer.writerow(row)

    @staticmethod
    def read_csv(csv_prefix: str) -> ig.Graph:
        """Reconstructs a graph from CSV files."""
        node_path = f"{csv_prefix}.nodes.csv.xz"
        edge_path = f"{csv_prefix}.edges.csv.xz"

        builder = GraphBuilder()
        with lzma.open(node_path, "rt") as f:
            reader = csv.DictReader(f)
            for row in reader:
                builder.node_attrs.append(NodeAttr(**row))

        with lzma.open(edge_path, "rt") as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = int(row.pop("src"))
                dst = int(row.pop("dst"))
                builder.edges.append((src, dst))
                builder.edge_attrs.append(EdgeAttr(**row))

        return builder.build()
