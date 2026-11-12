import csv
import math
import re
import igraph
import matplotlib.pyplot as plt
import os
import sys
import re
import pickle
import pdb
import lzma
import traceback
import tqdm
from collections import deque

# Why do I need this??? >_<
FUZZY_TRACE_TIME = 100
time_delta = 2 # in seconds

color_dict = {
    "root_cause": "#5AFA8E",  # green
    "impact": "#FA5D5A",  # red
    "process": "#5A62FA",  # blue
    "thread": "#5A62FF",  # blue
    "file": "#FADB59",  # yellow
    "regkey": "#FADB59",
    "socket": "#FADB59",
    "descendent": "#FADB59",
    "attack": "#FADB59",
    "contaminated": "grey",
    "benign": "grey",
    "default": "grey",
}

# Hard-coded filter lists for graph viz
#
# Empirically derived filter list
# NOTE: This is an ordered set. Sorted in descending order by number of avg
# CROSSPROC events, where each item had stats calculated without the previous
# item included.
empirical_filter_set = {
    "taskmgr.exe",
    "mrt.exe",
    "perfmon.exe",
    "msmpeng.exe",
    "adobearmhelper.exe",
    "googleupdate.exe",
    "lsass.exe",
    # "explorer.exe",  # attack essential
    "vpnagent.exe",
    "adnotificationmanager.exe",
    "officeclicktorun.exe",
    "mossapp.exe",
    # "mintty.exe",  # attack essential
    "dns.exe",
    "atbroker.exe",
    "microsoft.activedirectory.webservices.exe",
    "ismserv.exe",
    "dfsrs.exe",
    "wlms.exe",
    "dfssvc.exe",
    "vds.exe",
    "msdtc.exe",
    "reputils.exe",
    "code.exe",
    "codesetup-stable-dc96b837cf6bb4af9cd736aa3af08cf8279f7685.tmp",
    "magnify.exe",
    "credentialenrollmentmanager.exe",
    "shellexperiencehost.exe",
    "servermanager.exe",
    "peopleapp.exe",
    "codesetup-stable-dc96b837cf6bb4af9cd736aa3af08cf8279f7685.exe",
    "searchapp.exe",
    "hxaccounts.exe",
    "ctfmon.exe",
    "acwebhelper.exe",
    "sihost.exe",
    "searchui.exe",
    "dfsvc.exe",
    "git-bash.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
    "ssh-agent.exe",
    "textinputhost.exe",
    "zwebview2agent.exe",
    "wscript.exe",
    "plugin_host-3.3.exe",
    "codesetup-stable-b58957e67ee1e712cebf466b995adf4c5307b2bd.tmp",
    "sublime_text.exe",
    "systemsettings.exe",
    "lockapp.exe",
    "zoom.exe",
    "texstudio.exe",
    "vscode-win32-x64-user1121374930.tmp",
    "onedrive.exe",
    "radeonsettings.exe",
    "igfxemn.exe",
    "svchost.exe",
    "olk.exe",
    "pilotshubapp.exe",
    "winstore.app.exe",
    "microsoft.notes.exe",
    "wwahost.exe",
    "microsoft.aad.brokerplugin.exe",
    "_iu14d2n.tmp",
    "msiexec.exe",
    "gamebar.exe",
    "windowsterminal.exe",
    "csc_ui.exe",
    "mmc.exe",
    "adobecollabsync.exe",
    "identity_helper.exe",
    "texstudio-4.7.3-win-qt6.exe",
    "launchtm.exe",
    "unins000.exe",
    "screenclippinghost.exe",
    "git-credential-manager.exe",
    "cortana.exe",
    "phoneexperiencehost.exe",
    "hxoutlook.exe",
    "bootcamp.exe",
    "skypeapp.exe",
    "applecontrolpanel.exe",
    "dccw.exe",
    "microsoft.photos.exe",
    "deviceproperties.exe",
    "screensketch.exe",
    "fodhelper.exe",
    "dataexchangehost.exe",
    "netplwiz.exe",
    "inno_updater.exe",
    "wireshark.exe",
    "microsoft.sharepoint.exe",
    "applebcupdate.exe",
    "werfault.exe",
    "softwareupdate.exe",
    "onedrivesetup.exe",
    "consent.exe",
    "hxcalendarappimm.exe",
    "plugin_host-3.8.exe",
    "googlecrashhandler.exe",
    "igfxem.exe",
    "runonce.exe",
    "slack.exe",
    "notepad.exe",
    "openwith.exe",
    "msedgewebview2.exe",
    # "java-update.exe",  # attack essential
    "systemsettingsadminflows.exe",
    "wmic.exe",
    ##############################
    ####### MANUALLY ADDED #######
    ##############################
    "taskhostw.exe",
    # "msedge.exe",
    # "searchindexer.exe",
    # "powershell.exe",
    "runtimebroker.exe",
    # "microsoft.management.service.intunewindowsagent.exe",
}


# NOTE: t25_all_filters set has no particular ordering; it simply consists of
# the union of all programs that either exist in C:\Windows\System32 or is
# known to be a cause of dependency explosion where we take the those that
# satisfy this criteria for the top 25 programs in terms of number of
# CROSSPROC events, average number of CROSSPROC events, and the number of
# total program executions
t25_winsys32_filter_set = {
    "svchost.exe",
    "backgroundtaskhost.exe",
    "runtimebroker.exe",
    "lsass.exe",
    # "msmpeng.exe",              # Known cause of dependency explosion
    "dllhost.exe",
    "taskhostw.exe",
    "sppsvc.exe",
    "wmiprvse.exe",
    "taskmgr.exe",
    "smartscreen.exe",
    "audiodg.exe",
    "mousocoreworker.exe",
    "searchprotocolhost.exe",
    "perfmon.exe",
    # "mrt.exe",                  # Known cause of dependency explosion
    "dns.exe",
    "atbroker.exe",
    "wlms.exe",
    "vds.exe",
    "msdtc.exe",
    "ismserv.exe",
    "dfssvc.exe",
    "dfsrs.exe",
}
# Set of programs filtered in descending order by number of average CROSSPROC events
acpe_filter_set = {
    "perfmon.exe",
    "taskmgr.exe",
    "mrt.exe",
    "msmpeng.exe",
    "adobearmhelper.exe",
    "googleupdate.exe",
    "lsass.exe",
    "explorer.exe",
    "vpnagent.exe",
    "adnotificationmanager.exe",
    "officeclicktorun.exe",
    "mossapp.exe",
    "mintty.exe",
}
# Set of programs filtered in descending order by total number of CROSSPROC events
ncpe_filter_set = {
    "svchost.exe",
    "msedge.exe",
    "code.exe",
    "backgroundtaskhost.exe",
    "connhost.exe",
    "explorer.exe",
    "runtimebroker.exe",
    "lsass.exe",
    "msmpeng.exe",
    "googleupdate.exe",
    "slack.exe",
    "msedgewebview.exe",
    "dllhost.exe",
    "python3.11.exe",
}

def dagify_root_forward(g, root_cause_uuids):
    """
    Wrapper (your original approach):
      1) Keep only edges reachable by a forward traversal from root causes.
      2) From those edges, keep as many as possible while guaranteeing a DAG
         by adding edges in increasing edge-start time order and skipping edges
         that would create a cycle.

    Returns:
      dag_g, reachable_eids, kept_eids
    """
    uuid_to_vid = {str(v["uuid"]): v.index for v in g.vs}
    root_vids = [uuid_to_vid[u] for u in root_cause_uuids if u in uuid_to_vid]

    all_eids = set([e.index for e in g.es])
    necessary_eids = set()
    visited_paths = set()
    q = deque(root_vids)

    necessary_eids = set()
    for root_vid in root_vids:
      visited_vids = set()
      q = deque([root_vid])
      while q:
        u = q.popleft()
        for e in g.es.select(_source=u):            
            v = e.target 
            if (v not in visited_vids 
                and (u,v) not in visited_paths):
              necessary_eids.add(e.index)
              visited_vids.add(v)
              visited_paths.add((u,v))
              visited_paths.add((v,u))
              q.append(v)

    dag_g = g.copy()
    dag_g.delete_edges(all_eids - necessary_eids)
    dag_g.delete_vertices([v.index for v in dag_g.vs if len(v.neighbors())==0])
    return dag_g


def compute_vertex_label(v):
    """
    Returns one of: attack | contaminated | benign
    """
    if "attack_label" in v.attributes() and v["attack_label"]:
        return "attack"
    if "contaminate_label" in v.attributes() and v["contaminate_label"]:
        return "contaminated"
    return "benign"


def write_labels_file_attack_only(g, base_fname, label_file):
    """
    Writes a .labels file containing ONLY attack + contaminated vertices.
    Format (same as label_graph.py):
        display_name, vertex_id, vertex_name, label
    """
    display_name = os.path.basename(base_fname)


    with open(label_file, "w") as f:
        f.write("attack, process_name, process_id, process_uuid, label\n") 
        for v in g.vs:
            label = compute_vertex_label(v)

            # Skip benign vertices and non-processes
            if label == "benign" or v['type'] != 'process':
                continue

            process_id = v["pid"] if "pid" in v.attributes() else -1
            process_uuid = v["guid"] if "guid" in v.attributes() else v["uuid"]
            process_name = v["fullname"] if "fullname" in v.attributes() else v["name"]
            process_label = label

                
            f.write(f"{display_name},  {process_name}, {process_id}, {process_uuid}, {label}\n")

    print(f"Wrote labels: {label_file}")


def parse_program_name(path):
    """Extracts the program name from a file path."""
    match = re.search(r"[^\\/]+$", path)
    return match.group(0).lower() if match else path.lower()


def dump_vertices(selective_neighborhood, csv_filename):
    """Dumps all vertices and their metadata from selective_neighborhood into
    output_csv."""

    vertex_times(selective_neighborhood)
    vertices = []

    for i in range(len(selective_neighborhood.vs)):
        v = selective_neighborhood.vs[i]
        try:
            time = int(v["min_time"])
            default_label = "benign"
            pretty_name = v["name"].lstrip("\x00")
            vertices.append(
                [
                    time,
                    v["type"],
                    pretty_name,
                    v["uuid"],
                    default_label,
                ]
            )

        except Exception as e:
            print("Error: %s" % (e))
            pdb.set_trace()

    with open(csv_filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["time", "type", "name", "uuid", "label"])
        writer.writerows(vertices)

    print(f"Exported vertex data to {csv_filename}")


def dump_edges(selective_neighborhood, csv_filename):
    #mark_uuids(selective_neighborhood)

    time_dict = {}
    for e in selective_neighborhood.es:
        time_dict[e.index] = e["start"]

    sorted_keys = sorted(time_dict, key=time_dict.get)

    with open(csv_filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "src_v_idx",
                "src_v_name",
                "tgt_v_idx",
                "tgt_v_name",
                "e_idx",
                "e_type",
                "e_time",
            ]
        )
        for k in sorted_keys:
            e = selective_neighborhood.es[k]
            s = selective_neighborhood.vs[e.source]
            t = selective_neighborhood.vs[e.target]

            writer.writerow(
                [
                    s.index,
                    s["name"],
                    t.index,
                    t["name"],
                    e.index,
                    e["type"],
                    int(e["start"]),
                ]
            )

        print(f"Exported edge data to {csv_filename}")


def forward_trace(
    g,
    vertex_id,
    depth,
    timestamp,
    visited,
    max_time=False,
    impacts_only=False,
    max_depth=False,
    avoid_set=None,
    k=None,
):
    if avoid_set is None:
        avoid_set = set()

    ancestor = g.vs[vertex_id]

    # Skip the vertex if its name is in the avoid_set
    if ancestor["name"] in avoid_set:
        return []

    descendents = []

    #### FORWARD TRACE ONLY ####
    # Specify Sugiyama layer
    g.vs[vertex_id]["layer"] = depth

    if vertex_id in visited:
        return descendents
    elif max_depth and depth > max_depth:
        return descendents
    else:
        visited.append(vertex_id)

    terminal_node = True

    #outgoing_edges = g.es.select(_source=ancestor)
    #if ancestor["name"] in ["msedge.exe", "explorer.exe"] and k is not None:
    #    outgoing_edges = outgoing_edges[:k]
    outgoing_edges = g.es.select(_source=ancestor)
    if ancestor["name"] in {"msedge.exe", "explorer.exe"} and k is not None:
        # interval method - pick the edges starting within delta of current
        # (symmetric: could have been before or after)
        if timestamp:
            interval_end = timestamp + time_delta
            interval_start = timestamp - time_delta
            outgoing_edges = outgoing_edges.select(
                start_ge=interval_start, start_le=interval_end)

    for e in outgoing_edges:
        if (
            e.target in visited or g.vs[e.target]["name"] in avoid_set
            or g.vs[e.target]["name"].startswith("W32PosixPipe.")
        ):
            continue
        else:
            start = e["start"]
            end = e["end"]
            if start is None:
                start = 0
            if end is None:
                end = float("inf")
            if (not timestamp or timestamp <= (end + FUZZY_TRACE_TIME)) and (
                not max_time or max_time >= (start - FUZZY_TRACE_TIME)
            ):
                terminal_node = False
                g.es[e.index]["attack_label"] = True
                descendents.extend(
                    forward_trace(
                        g,
                        e.target,
                        depth + 1,
                        e["start"],
                        visited,
                        max_time,
                        impacts_only,
                        max_depth,
                        avoid_set,
                        k=k,
                    )
                )

    if not impacts_only or (impacts_only and terminal_node):
        descendents.append(vertex_id)

    return descendents


def backward_trace(
    g,
    vertex_id,
    depth,
    timestamp,
    visited,
    min_time=False,
    root_causes_only=False,
    max_depth=False,
    avoid_set=None,
    k=None,
):
    if avoid_set is None:
        avoid_set = set()

    descendent = g.vs[vertex_id]

    # Skip the vertex if its name is in the avoid_set
    if descendent["name"] in avoid_set:
        return []

    ancestors = []

    if vertex_id in visited:
        return ancestors
    elif max_depth and depth > max_depth:
        return ancestors
    else:
        visited.append(vertex_id)

    terminal_node = True

    #outgoing_edges = g.es.select(_target=descendent)
    #if descendent["name"] in ["msedge.exe", "explorer.exe"] and k is not None:
    #    outgoing_edges = outgoing_edges[:k]
    outgoing_edges = g.es.select(_target=descendent)
    if descendent["name"] in {"msedge.exe", "explorer.exe"} and k is not None:
        # interval method - pick the edges starting within delta of current
        # technically, shouldn't be symmetric, but the traversal will filter
        # out any inadmissible flows
        if timestamp:
            interval_end = timestamp + time_delta
            interval_start = timestamp - time_delta
            outgoing_edges = outgoing_edges.select(
                start_ge=interval_start, start_le=interval_end)

    for e in outgoing_edges:
        if (
            e.source in visited or g.vs[e.source]["name"] in avoid_set
            or g.vs[e.source]["name"].startswith("W32PosixPipe.")
        ):
            continue
        else:
            start = e["start"]
            end = e["end"]

            if start is None:
                start = 0
            if end is None:
                end = float("inf")

            if (not timestamp or timestamp >= (start - FUZZY_TRACE_TIME)) and (
                not min_time or min_time <= (end + FUZZY_TRACE_TIME)
            ):
                terminal_node = False
                g.es[e.index]["attack_label"] = True
                ancestors.extend(
                    backward_trace(
                        g,
                        e.source,
                        depth + 1,
                        int(e["start"]),
                        visited,
                        min_time,
                        root_causes_only,
                        max_depth,
                        avoid_set,
                        k=k,
                    )
                )

    if not root_causes_only or (root_causes_only and terminal_node):
        ancestors.append(vertex_id)

    return ancestors


def print_node(g, vertex_id, prefix=""):
    v = g.vs[vertex_id]
    print(
        "%s[v%d](%s, %s, %s)" % (prefix, v.index, v["name"], v["type"], str(v["uuid"]))
    )


def print_edge(g, edge_id, prefix):
    e = g.es[edge_id]
    s = g.vs[e.source]
    t = g.vs[e.target]

    print(
        "%s[v%d](%s) --[e%d](%s){%d}--> [v%d](%s)"
        % (
            prefix,
            s.index,
            s["name"],
            e.index,
            e["type"],
            int(e["start"]),
            t.index,
            t["name"],
        )
    )


def pickle_read(path):
    if path.endswith("xz"):
        opener = lzma.open
    else:
        opener = open
    with opener(path, "rb") as f:
        return pickle.load(f)


def pickle_write(data, path):
    if path.endswith("xz"):
        opener = lzma.open
    else:
        opener = open
    with opener(path, "wb") as f:
        pickle.dump(data, f)


class ClusterRelabeler:
    def __init__(self):
        print("loading data dependency clusters...")
        self.id_map = pickle_read("path_cluster_map.pkl.xz")
        self.path_map = pickle_read("cluster_rep_map.pkl.xz")

    def to_id(self, path: str) -> int:
        return self.id_map[path]

    def relabel_id(self, i: int) -> str:
        # this should never fail if used correctly
        return self.path_map[i]

def contract_clustered_files(g):
    """Cleanup the attack graph a bit more: find all data objects and
    apply the clustering to them. Contract the nodes in the same cluster."""
    before = g.vcount()
    clusterer = ClusterRelabeler()
    mapping = list(range(g.vcount()))
    to_delete = []
    clusters = {}
    for u in tqdm.tqdm(g.vs(type_ne="process")):
        nid = u.index
        if (g.vs[nid]["color"] == color_dict["root_cause"] or
            g.vs[nid]["color"] == color_dict["impact"]):
            # don't try to cluster important nodes
            continue
        try:
            cid = clusterer.to_id(u["name"])
        except KeyError:
            if u["type"] != "socket": # these aren't actually clustered
                print(f"warning: non-clustered path: {u['name']}")
            continue
        if cid not in clusters:
            clusters[cid] = []
        clusters[cid].append(nid)

    for cid, nids in clusters.items():
        # if we don't contract anything, then don't rename either
        if len(nids) <= 1:
            continue
        # remap all vertices to the first (minimum index)
        fst = min(nids)
        for nid in nids:
            mapping[nid] = fst
            if nid != fst:
                to_delete.append(nid)
        # rename to cluster path representative
        g.vs[fst]["name"] = clusterer.relabel_id(cid)

    g.contract_vertices(mapping, combine_attrs="first")
    g.delete_vertices(to_delete)



    
    print(f"data dependency reduction:" +
          f"  {before} -> {g.vcount()}")

# Any dataset-specific relabels go here
def relabels(g):
    # Drop leading substrings that match these
    winfile_prefix_filters = []

    # Drop ending substrings that come after these matches
    winfile_suffix_filters = []

    for i in range(0, len(g.vs)):
        name = g.vs[i]["name"]
        node_type = g.vs[i]["type"]

        #######################################
        #      DARPA E3 Hacks
        #######################################
        # Remove "deleted" from red team executable names
        if " (deleted)" in name:
            g.vs[i]["name"] = name.replace(" (deleted)", "")

        # Remove sock= prefix from sockets
        if name.startswith("sock="):
            g.vs[i]["name"] = name.split("=")[1]

        # Remove null prefix from unknown node labels,
        #  replace with empty string
        if "\x00" in name:
            g.vs[i].update_attributes({"name": ""})

        #######################################
        #      Unixy Hacks
        #######################################
        # Split unix file paths, keep file name
        #if node_type == "file" and "/" in name:
        #    name = name.split("/")
        #    name = name[len(name) - 1]
        #    g.vs[i]["name"] = name

        #######################################
        #      Windowsy Hacks
        #######################################
        # Gave up on cleaning up regkeys, just rename to "regkey"
        # if node_type in ["regkey"]:
        #     g.vs[i]["name"] = "regkeys"
        # elif node_type in ["file"]:
        #     g.vs[i]["name"] = "files"

        # If executable, always just go with exe name
        #  whether its a file or a process
        if node_type == "process" and name.endswith(".exe"):
            g.vs[i]["fullname"] = name
            name = name.split("\\")[-1]
            g.vs[i]["name"] = name

        # Filter windows file paths to make them semi-salient
        #  and semi-collapsable, pure trial and error on these filters
        #if node_type == "file" and "\\" in name:
        #    modified = False

        #    for prefix in winfile_prefix_filters:
        #        if prefix in name:
        #            name = name.split(prefix)
        #            name = name[len(name) - 1]

        #    for suffix in winfile_suffix_filters:
        #        if suffix in name:
        #            name = name[: name.index(suffix) + len(suffix)]
        #            modified = True

        #    if not modified:
        #        name = name.split("\\")
        #        name = name[len(name) - 1]

        #    g.vs[i]["name"] = name

    #######################################
    #      Edge relabels
    #######################################
    # Some syscalls in my input files started with "EVENT_", dropping that
    for j in range(0, len(g.es)):
        edge_type = g.es[j]["type"]
        if edge_type.startswith("EVENT_"):
            edge_type = edge_type.split("_")[1]
            g.es[j]["type"] = edge_type.lower()

import re
def relabel_name(g):
    for u in g.vs:
        name = u["name"]
        end = re.split(r"\\|/", name)[-1]
        u["name"] = end

def mask_data_names(g, seed_file):
    data_types = {"file", "regkey", "socket", "pipe"}
    seed_labels = get_seed_labels(seed_file)

    for u in g.vs:
        v_uuid = str(u["uuid"])
        if v_uuid  in seed_labels and seed_labels[v_uuid] in ["root_cause", "impact",]:
            continue
        elif u["type"] in data_types:
            u["name"] = "*"


# Modify processes to denote UUIDs
#  (must be done later in processing than relabels())
def mark_uuids(g):
    for i in range(0, len(g.vs)):
        if g.vs[i]["type"] == "process":
            g.vs[i]["name"] = g.vs[i]["name"] + ":" + str(g.vs[i]["uuid"])[-4:]


def get_seed_labels(seed_file):
    seed_labels = {}
    if os.path.isfile(seed_file):
        # Read seed labels in from csv
        try:
            with open(seed_file, "r") as csvfile:
                rdr = csv.DictReader(csvfile, quotechar='"')
                for row in rdr:
                    vertex_id = row["vertex_id"].lstrip().rstrip()
                    seed_label = row["seed_label"].lstrip().rstrip()
                    if vertex_id == "vertex_id":
                        continue
                    seed_labels[vertex_id] = seed_label
        except Exception as e:
            print("Error: %s" % (e))
            pdb.set_trace()

    return seed_labels

# Color the graph
def color_graph(g, seed_file, filter_list, reduce_ipc):
    seed_labels = {}
    if os.path.isfile(seed_file):
        seed_labels = get_seed_labels(seed_file)

        g.vs["attack_label"] = [False for n in g.vs["type"]]
        g.vs["contaminate_label"] = [False for n in g.vs["name"]]
        g.es["attack_label"] = [False for n in g.es["type"]]
        g.vs["color"] = g.vs["type"]

        # Generate lists of root causes and impacts
        root_min = False
        impact_max = False
        root_vertex_ids = []
        impact_vertex_ids = []
        for v in g.vs:
            i = v.index
            v_uuid = str(g.vs[i]["uuid"])

            if v_uuid in seed_labels and seed_labels[v_uuid] == "root_cause":
                root_vertex_ids.append(g.vs[i].index)
                if not root_min or root_min > g.vs[i]["min_time"]:
                    root_min = g.vs[i]["min_time"]

            elif v_uuid in seed_labels and seed_labels[v_uuid] == "impact":
                impact_vertex_ids.append(g.vs[i].index)
                if not impact_max or impact_max < g.vs[i]["max_time"]:
                    impact_max = g.vs[i]["max_time"]

            # Initial color
            g.vs["color"] = color_dict["default"]

        # terrible hack
        if os.path.basename(seed_file).startswith("fs"):
            impact_max = 1714676394

        print("FT max time is %f, BT min time is %f" % (impact_max, root_min))

        if reduce_ipc == "inter":
            k = None
            avoid_set = filter_list
        elif reduce_ipc == "intra":
            k = 5
            avoid_set = {}
        elif reduce_ipc == "all":
            k = 5
            avoid_set = filter_list
        elif reduce_ipc == "none":
            k = None
            avoid_set = {}
        else:
            raise ValueError("unknown IPC reduction")

        # Propagate root cause taint in graph colors
        descendents = []
        print("Root Causes:")
        for r in root_vertex_ids:
            print_node(g, r, "")
            descendents = descendents + forward_trace(
                g,
                r,
                depth=0,
                timestamp=False,
                max_time=impact_max,
                visited=[],
                max_depth=False,
                avoid_set=avoid_set,
                # avoid_set=empirical_filter_set,
                # avoid_set=None,
                k=k,
            )            
        print("\t %d descendents" % (len(descendents)))

        # Mark all descendents as contaminated
        for d in descendents:
            g.vs[d]["contaminate_label"] = True
        
        print("Impacts:")
        ancestors = []
        for i in impact_vertex_ids:
            print_node(g, i, "")
            ancestors = ancestors + backward_trace(
                g,
                i,
                depth=0,
                timestamp=False,
                min_time=root_min,
                visited=[],
                max_depth=False,
                avoid_set=avoid_set,
                # avoid_set=empirical_filter_set,
                # avoid_set=None,
                k=k,
            )
        print("\t %d ancestors" % (len(ancestors)))

        # Find the intersection of the ancestors and the descendents.
        attack_chain = []
        if len(descendents) > 0 and len(ancestors) > 0:
            attack_chain = [vertex for vertex in ancestors if vertex in descendents]
            # Add root causes and impacts back to the attack chain just to make clear if they're disconnected
            attack_chain += [
                vertex for vertex in root_vertex_ids if vertex not in attack_chain
            ]
            attack_chain += [
                vertex for vertex in impact_vertex_ids if vertex not in attack_chain
            ]

        if len(attack_chain) == 0 and len(ancestors) > 0:
            print(
                "There is no intersection between the ancestors and descendents. Setting attack chain to ancestors."
            )
            attack_chain = ancestors
        elif len(attack_chain) == 0 and len(descendents) > 0:
            print(
                "There is no intersection between the ancestors and descendents. Setting attack chain to descendents."
            )
            attack_chain = descendents

        print(
            "%d descendents and %d ancestors, %d attack chain"
            % (len(descendents), len(ancestors), len(attack_chain))
        )

        # Color attack chain and mark attack_label attribute as True
        for d in attack_chain:
            # for d in g.vs.indices: ===> uncomment this line to run filter-list-nbhd-viz.py
            vi = d
            v_uuid = str(g.vs[vi]["uuid"])
            g.vs[vi]["attack_label"] = True
            if v_uuid in seed_labels and seed_labels[v_uuid] in [
                "root_cause",
                "impact",
                "contaminated",
            ]:
                g.vs[vi]["color"] = color_dict[seed_labels[v_uuid]]
            elif g.vs[vi]["type"] != "unknown":
                g.vs[vi]["color"] = color_dict[g.vs[vi]["type"]]
            else:
                print("unknown in attack chain")
                print_node(g, vi)


def sys_utils_only(g):
    system_utilites = ["explorer.exe"]

    # Identify sys utils
    sys_util_uuids = []
    for v in g.vs:
        i = v.index
        v_uuid = str(g.vs[i]["uuid"])
        v_label = str(g.vs[i]["name"])
        if v_label in system_utilites:
            sys_util_uuids.append(v_uuid)
            g.vs[i]["attack_label"] = "sys_util"
            g.vs[i]["color"] = color_dict["root_cause"]

            for e in g.es.select(_source=i):
                # Processes only
                if g.vs[e.target]["type"] == "process":
                    g.vs[e.target]["attack_label"] = "one_hop"
                    if g.vs[e.target]["name"] not in system_utilites:
                        g.vs[e.target]["color"] = color_dict[g.vs[e.target]["type"]]
                        g.vs[e.target]["name"] = ""

            for e in g.es.select(_target=i):
                # Processes only
                if g.vs[e.source]["type"] == "process":
                    g.vs[e.source]["attack_label"] = "one_hop"
                    if g.vs[e.source]["name"] not in system_utilites:
                        g.vs[e.source]["color"] = color_dict[g.vs[e.source]["type"]]
                        g.vs[e.source]["name"] = ""

    # Delete Everything Else
    prune_set_v = []
    for v1 in g.vs:
        if not v1["attack_label"]:
            prune_set_v.append(v1.index)
    g.delete_vertices(prune_set_v)


# Declone processes
def declone_processes(g):
    parent_mapping = {}
    prune_set_e = set()
    prune_set_v = set()

    for ei in range(len(g.es)):
        e1 = g.es[ei]

        # Look for processes with the same name
        if (
            g.vs[e1.source]["name"] == g.vs[e1.target]["name"]
            and g.vs[e1.target]["type"] == "process"
            and g.vs[e1.source]["type"] == "process"
        ):
            if e1.source in parent_mapping:
                parent_mapping[e1.target] = parent_mapping[e1.source]
            else:
                parent_mapping[e1.target] = e1.source

            node_to_prune = g.vs[e1.target]
            node_to_rehome = g.vs[parent_mapping[e1.target]]

            prune_set_v.add(e1.target)
            prune_set_e.add(e1.index)

            # Reconnect outgoing edges from node_to_prune
            for e in g.es.select(_source=node_to_prune.index):
                if e.index == e1.index:
                    continue
                existing = g.es.select(_source=node_to_rehome.index, _target=e.target)
                if not any(
                    e_["type"] == e["type"] and e_["uuid"] == e["uuid"]
                    for e_ in existing
                ):
                    g.add_edge(
                        node_to_rehome.index,
                        e.target,
                        **{
                            "type": e["type"],
                            "start": e["start"],
                            "uuid": e["uuid"],
                        },
                    )
                prune_set_e.add(e.index)

            # Reconnect incoming edges to node_to_prune
            for e in g.es.select(_target=node_to_prune.index):
                if e.index == e1.index:
                    continue
                existing = g.es.select(_source=e.source, _target=node_to_rehome.index)
                if not any(
                    e_["type"] == e["type"] and e_["uuid"] == e["uuid"]
                    for e_ in existing
                ):
                    g.add_edge(
                        e.source,
                        node_to_rehome.index,
                        **{
                            "type": e["type"],
                            "start": e["start"],
                            "uuid": e["uuid"],
                        },
                    )
                prune_set_e.add(e.index)

    g.delete_edges(list(prune_set_e))
    g.delete_vertices(list(prune_set_v))


# Remove redundant edges from graph
# An edge is considered redundant if there is already an edge between
# the source and the destination target of the same type
def prune_edges(g, debug=False):
    prune_set_e = []
    for e1 in g.es:
        # Skip if edge 1 is already marked for pruning
        if e1.index in prune_set_e:
            continue

        for e2 in g.es.select(_source=e1.source, _target=e1.target):
            # Skip if e1 is e2
            if e1.index == e2.index:
                continue
            # Skip if edge 2 is already marked for pruning
            elif e2.index in prune_set_e:
                continue
            # Skip if edges are not of the same type
            elif e1["type"] != e2["type"]:
                continue
            # Prune edge since target and source indices match
            else:
                prune_set_e.append(e2.index)

    g.delete_edges(prune_set_e)


def _all_neighbors(g, vi):
    neighbors = []
    for e in g.es.select(_source=vi):
        v = g.vs[e.target]
        neighbors.append(v.index)

    for e in g.es.select(_target=vi):
        v = g.vs[e.source]
        if v.index not in neighbors:
            neighbors.append(v.index)

    return neighbors


# Remove dangling vertices
# (If they are not root causes or impacts)
def prune_vertices(g, seed_file, debug=False):
    seed_labels = get_seed_labels(seed_file)

    prune_set_v = []
    for vi in range(0, len(g.vs)):
        v = g.vs[vi]
        # Skip if this is a root cause or an impact
        if v["uuid"] in seed_labels and seed_labels[v["uuid"]] in [
            "root_cause",
            "impact",
        ]:
            continue

        outbound_edges = g.es.select(_source=v.index)
        inbound_edges = g.es.select(_target=v.index)
        if (len(inbound_edges) == 0 and len(outbound_edges) ==0):
            prune_set_v.append(v.index)
        # TEST FOR CARBANAKV2 TUTORIAL
        else:
            connections = set()
            for edge in outbound_edges:
                connections.add(edge.target)
            for edge in inbound_edges:
                connections.add(edge.source)

            if(len(connections) == 1):
                prune_set_v.append(v.index)
        
    g.delete_vertices(prune_set_v)


# For each known vertex,
#   if two of its neighbors are semantically equivalent
#   (same file or socket name, or type is unknown)
#   and do not convey any additional information flow,
#   drop the edge to one of the two neighbors.
# At the end, remove any disconnected vertices
def merge_vertices(g, seed_file, debug=False):
    prune_set_e = []
    prune_set_v = []
    seed_labels = get_seed_labels(seed_file)
    # Iterate over all nodes
    for v in g.vs:
        v_uuid = v["uuid"]

        # Skip if v is already marked for deletion
        if v.index in prune_set_v:
            continue
        # Skip if this isn't a process (we'll visit every node either way)
        elif v["type"] != "process":
            continue

        neighbors = _all_neighbors(g, v.index)
        for n1 in range(0, len(neighbors) - 1):
            v1 = g.vs[neighbors[n1]]
            v1_uuid = v1["uuid"]

            # Skip if first neighbor is already marked for deletion
            if v1.index in prune_set_v:
                continue

            # Skip if this is a root cause or an impact
            if v1_uuid in seed_labels and seed_labels[v1_uuid] in [
                "root_cause",
                "impact",
            ]:
                continue

            for n2 in range(n1 + 1, len(neighbors) - 1):
                v2 = g.vs[neighbors[n2]]
                v2_uuid = v2["uuid"]

                # Skip if second neighbor is already marked for deletion
                if v2.index in prune_set_v:
                    continue

                # Skip if this is a root cause or an impact
                if v2_uuid in seed_labels and seed_labels[v2_uuid] in [
                    "root_cause",
                    "impact",
                ]:
                    continue

                # Merge candidate if both are unknown
                # Merge candidate if both have same data entity name
                if (v1["type"] == v2["type"] and v1["type"] in ["unknown", "file"]) or (
                    v1["type"] == v2["type"]
                    and v1["type"] in ["file", "socket", "regkey"]
                    and v1["name"] == v2["name"]
                ):
                    #                    or (v1["name"] == "" and v2["name"] == "" and
                    #                        "process" not in  [v1["type"], v2["type"]]) ):

                    node_to_keep = v1
                    node_to_prune = v2
                    prune_set_v.append(v2.index)

                    for e in g.es.select(_source=node_to_prune):
                        if e.index == node_to_keep.index:
                            continue

                        new_e = g.add_edge(node_to_keep.index, e.target)
                        new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)

                    for e in g.es.select(_target=node_to_prune):
                        if e.index == node_to_keep.index:
                            continue

                        new_e = g.add_edge(e.source, node_to_keep.index)
                        new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)

                    if node_to_keep["name"] != node_to_prune["name"]:
                        node_to_keep["name"] = "*"

    g.delete_edges(prune_set_e)
    g.delete_vertices(prune_set_v)


def lamport_timestamps(g):
    MAX_TIMESTAMP = 2**63 - 1

    def normalize(ts, is_end=False):
        if ts is None:
            return MAX_TIMESTAMP if is_end else 0
        if ts == float("inf"):
            return MAX_TIMESTAMP
        return ts

    def display_lamport(ts, is_end=False):
        if ts is None:
            return "0" if not is_end else "inf"
        elif ts == float("inf") or ts == MAX_TIMESTAMP:
            return "inf"
        else:
            return str(ts_to_lamport[normalize(ts, is_end)])

    # Collect and normalize all timestamps
    timestamps = set()
    for e in g.es:
        timestamps.add(normalize(e["start"]))
        timestamps.add(normalize(e["end"], is_end=True))
    for v in g.vs:
        if "start" in v.attributes():
            timestamps.add(normalize(v["start"]))
        if "end" in v.attributes():
            timestamps.add(normalize(v["end"], is_end=True))

    sorted_timestamps = sorted(timestamps)
    ts_to_lamport = {ts: idx for idx, ts in enumerate(sorted_timestamps)}

    # Annotate edge labels
    edge_labels = []
    for e in g.es:
        start_disp = display_lamport(e["start"])
        end_disp = display_lamport(e["end"], is_end=True)
        range_str = f"[{start_disp}, {end_disp}]"

        old_label = e["label"] if "label" in e.attributes() else ""
        new_label = f"{old_label}, {range_str}" if old_label else range_str
        edge_labels.append(new_label)
    g.es["label"] = edge_labels

    # Annotate vertex labels if timestamps exist
    # if "start" in g.vs.attributes():
    #     for v in g.vs:
    #         start_disp = display_lamport(v["start"])
    #         end_disp = (
    #             display_lamport(v["end"], is_end=True)
    #             if "end" in v.attributes()
    #             else None
    #         )
    #         range_str = f"[{start_disp}, {end_disp}]" if end_disp else f"[{start_disp}]"
    #
    #         old_label = v["label"] if "label" in v.attributes() else ""
    #         v["label"] = f"{old_label}, {range_str}" if old_label else range_str


# Find the minimum and maximum access times per vertex.
# used to scope graph traversals.
def vertex_times(g):
    g.vs["min_time"] = [0 for n in g.vs["name"]]
    g.vs["max_time"] = g.vs["min_time"]
    
    # Make sure 'start' is initialized
    if "start" not in g.vs.attributes():
        g.vs['start'] = [0 for v in g.vs]
    # Else, replace start=None's with start=0
    else:
        g.vs(start_eq=None)["start"] = 0

    # Make sure 'end' is initialized
    if "end" not in g.vs.attributes():
        g.vs['end'] = [float("inf") for v in g.vs]
    # Else, replace end=None's with end=inf
    else:
        g.vs(end_eq=None)["end"] = float("inf")

    # Check to make sure start exists
    if "start" not in g.es.attributes():
        # Legacy graphs used 'time' and 'etime' instead
        #   of 'start' and 'end'
        if "time" in g.es.attributes():
            g.es["start"] = g.es["time"]
            del g.es["time"]
        
    # Some formats also have an "end" end timestamp.
    if "end" not in g.es.attributes():
        if "etime" in g.es.attributes():
            g.es["end"] = g.es["etime"]
            del g.es["etime"]
        else:
            # Mirror "start" into "end" if "end" or "etime" doesn't exist.
            g.es["end"] = [t for t in g.es["start"]]

    for v in g.vs:
        min_time = False
        max_time = False
        try:
            for e in g.es.select(_source=v.index):
                start = e["start"]
                end = e["end"]

                if start is None:
                    start = 0
                    min_time = True
                if end is None:
                    end = float("inf")
                    max_time = True

                if not min_time or start < min_time:
                    min_time = start
                if not max_time or end > max_time:
                    max_time = end

            for e in g.es.select(_target=v.index):
                start = e["start"]
                end = e["end"]

                if start is None:
                    start = 0
                    min_time = True
                if end is None:
                    end = float("inf")
                    max_time = True

                if not min_time or start < min_time:
                    min_time = start
                    if not max_time or end > max_time:
                        max_time = end

        except Exception as error:
            print("An exception occurred:", type(error).__name__)
            print(error)
            print(traceback.format_exc())
            pdb.set_trace()

        v["min_time"] = min_time
        v["max_time"] = max_time


def attack_only(g):
    prune_set_v = []
    for v1 in g.vs:
        if not v1["attack_label"]:
            prune_set_v.append(v1.index)
    g.delete_vertices(prune_set_v)

    prune_set_e = []
    for e1 in g.es:
        if not e1["attack_label"]:
            prune_set_e.append(e1.index)

    g.delete_edges(prune_set_e)


def merge_excess_sockets(g, seed_file):
    seed_labels = get_seed_labels(seed_file)

    prune_set_e = []
    prune_set_v = []
    # Iterate over all nodes
    for v in g.vs:
        # Skip if v is already marked for deletion
        if v.index in prune_set_v:
            continue
        # Skip if this isn't a process
        elif v["type"] != "process":
            continue

        neighbors = _all_neighbors(g, v.index)
        for n1 in range(0, len(neighbors) - 1):
            v1 = g.vs[neighbors[n1]]

            # Skip if first neighbor is already marked for deletion
            if v1.index in prune_set_v:
                continue

            for n2 in range(n1 + 1, len(neighbors) - 1):
                v2 = g.vs[neighbors[n2]]

                # Skip if second neighbor is already marked for deletion
                if v2.index in prune_set_v:
                    continue

                # Merge candidate if both are sockets
                # and neither is a root cause or impact
                if (v1["type"] == "socket" and v2["type"] == "socket") and not (
                    seed_labels[str(v1["uuid"])] in ["root_cause", "impact"]
                    or seed_labels[str(v2["uuid"])] in ["root_cause", "impact"]
                ):
                    node_to_keep = v1
                    v1["name"] = "*.*.*.*"
                    node_to_prune = v2
                    prune_set_v.append(v2.index)

                    for e in g.es.select(_source=node_to_prune):
                        if e.index == node_to_keep.index:
                            continue
                        # If this edge is redundant, do not add a new edge
                        if (
                            len(
                                g.es.select(
                                    _source=node_to_keep.index, _target=e.target
                                )
                            )
                            == 0
                        ):
                            new_e = g.add_edge(node_to_keep.index, e.target)
                            new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)

                    for e in g.es.select(_target=node_to_prune):
                        if e.index == node_to_keep.index:
                            continue
                        # If this edge is redundant, do not add a new edge
                        if (
                            len(
                                g.es.select(
                                    _source=e.source, _target=node_to_keep.index
                                )
                            )
                            == 0
                        ):
                            new_e = g.add_edge(e.source, node_to_keep.index)
                            new_e.update_attributes(e.attributes())
                        prune_set_e.append(e.index)

    g.delete_edges(prune_set_e)
    g.delete_vertices(prune_set_v)


def is_crossproc(g, data_idx):
    incident_procs = {
        #g.vs[nbr]["name"]
        nbr # above seems to break the graph
        for nbr in g.neighbors(data_idx, mode="all")
        if g.vs[nbr]["type"] == "process"
    }
    return len(incident_procs) > 1


def remove_singleton_data(g):
    vertices_to_prune = []
    for vertex in g.vs:
        if vertex["type"] in {"file", "regkey"} and not is_crossproc(g, vertex.index):
            vertices_to_prune.append(vertex.index)
    g.delete_vertices(vertices_to_prune)


def merge_processes(g):
    parent_mapping = {}
    prune_set_e = []
    prune_set_v = []
    for ei in range(0, len(g.es)):
        e1 = g.es[ei]

        if (
            e1["type"]
            in ["clone", "procstart", "crossproc_in", "crossproc_out", "procend"]
            and g.vs[e1.source]["name"] == g.vs[e1.target]["name"]
        ):
            pass

    g.delete_edges(prune_set_e)
    g.delete_vertices(prune_set_v)


def remove_orphan_data(g):
    data_types = {"file", "regkey", "socket", "pipe"}
    to_delete = []

    for v in g.vs:
        if v["type"] in data_types:
            incident_procs = [
                nbr for nbr in g.neighbors(v.index) if g.vs[nbr]["type"] == "process"
            ]
            if not incident_procs:
                to_delete.append(v.index)

    g.delete_vertices(to_delete)
    g.delete_vertices(g.vs(_degree_eq=0)) # remove disconnected nodes


def by_name(g, name: str) -> int:
    return g.vs(name_eq=name)[0].index
