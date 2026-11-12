"""
Visualizes one hop neighborhoods from a filter list.
For each program in the list, find all process instances from the
graphs contained in a specified directory, generate a one-hop
neighborhood subgraph for the program, plot it, and save it to a pdf.
"""

from graph_helpers import (
    pickle_read,
    parse_program_name,
    vertex_times,
    relabels,
    color_graph,
    lamport_timestamps,
    mark_uuids,
)
import sys
import os
import csv
import igraph
import argparse

subgraph_id = 0


def gen_selective_neighborhood(supergraph, central_vertex_index):
    """Generates a one-hop neighborhood from supergraph around the vertex
    identified by central_vertex_index, wherein the only edges included are
    those incident to the central vertex (inbound and outbound). Returns
    the 'selective_neighborhood' subgraph."""

    selective_neighborhood = igraph.Graph(directed=supergraph.is_directed())
    selective_neighborhood.add_vertex(
        **supergraph.vs[central_vertex_index].attributes()
    )

    # Track vertex mapping to preserve direction
    vertex_map = {central_vertex_index: 0}

    for edge_id in supergraph.incident(central_vertex_index, mode="all"):
        edge = supergraph.es[edge_id]

        target_vertex_idx = edge.target
        source_vertex_idx = edge.source

        for vertex_idx in (source_vertex_idx, target_vertex_idx):
            if vertex_idx not in vertex_map:
                vertex_map[vertex_idx] = selective_neighborhood.vcount()
                selective_neighborhood.add_vertex(
                    **supergraph.vs[vertex_idx].attributes()
                )

        if edge["type"] != "moduleload":
            selective_neighborhood.add_edge(
                vertex_map[source_vertex_idx],
                vertex_map[target_vertex_idx],
                **{attr: edge[attr] for attr in supergraph.es.attributes()},
            )

    # Graph sanity checks
    if "type" not in selective_neighborhood.es.attributes():
        selective_neighborhood.es["type"] = [""] * len(selective_neighborhood.es)
    if "name" not in selective_neighborhood.es.attributes():
        selective_neighborhood.es["name"] = [""] * len(selective_neighborhood.es)
    if "time" not in selective_neighborhood.es.attributes():
        selective_neighborhood.es["time"] = [-1] * len(selective_neighborhood.es)

    return selective_neighborhood


def prepare_graph(selective_neighborhood, v_csv_filename):
    print("Relabeling nodes and edges...")
    relabels(selective_neighborhood)

    print("Recovering vertex times...")
    vertex_times(selective_neighborhood)

    print("Dumping vertices to csv...")
    dump_vertices(selective_neighborhood, v_csv_filename)

    print("Coloring graph...")
    color_graph(selective_neighborhood, v_csv_filename)


def plot_selective_neighborhood(selective_neighborhood, pdf_filename):
    layout = selective_neighborhood.layout_davidson_harel()
    selective_neighborhood.vs["label"] = [
        parse_program_name(selective_neighborhood.vs[i]["name"])
        for i in range(0, len(selective_neighborhood.vs))
    ]
    selective_neighborhood.vs["shape"] = [
        "rectangle" for t in selective_neighborhood.vs["name"]
    ]
    selective_neighborhood.vs["height"] = [
        25 for n in selective_neighborhood.vs["name"]
    ]
    selective_neighborhood.vs["width"] = [
        20 + 10 * (len(n) - 1) for n in selective_neighborhood.vs["name"]
    ]
    selective_neighborhood.es["label"] = [t for t in selective_neighborhood.es["type"]]
    lamport_timestamps(selective_neighborhood)
    selective_neighborhood.es["arrow_size"] = [
        1.25 for t in selective_neighborhood.es["type"]
    ]
    igraph.plot(
        selective_neighborhood,
        pdf_filename,
        layout=layout,
        bbox=(2560, 1080),
        margin=200,
    )
    global subgraph_id
    subgraph_id += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("graph_dir")
    parser.add_argument("pdf_out_dir")
    parser.add_argument("csv_out_dir")
    args = parser.parse_args()

    empirical_filter_set = {
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
        "wkssvc",
        "officeclicktorun.exe",
        "mossapp.exe",
        "mintty.exe",
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
        "peopleapp.exe",
        "servermanager.exe",
        "searchapp.exe",
        "codesetup-stable-dc96b837cf6bb4af9cd736aa3af08cf8279f7685.exe",
        "hxaccounts.exe",
        "ctfmon.exe",
        "acwebhelper.exe",
        "searchui.exe",
        "sihost.exe",
        "sublime_text.exe",
        "startmenuexperiencehost.exe",
        "dfsvc.exe",
        "git-bash.exe",
        "textinputhost.exe",
        "applicationframehost.exe",
        "ssh-agent.exe",
        "zwebview2agent.exe",
        "wscript.exe",
        "codesetup-stable-b58957e67ee1e712cebf466b995adf4c5307b2bd.tmp",
        "plugin_host-3.3.exe",
        "lockapp.exe",
        "systemsettings.exe",
        "zoom.exe",
        "pilotshubapp.exe",
        "onedrive.exe",
        "msiexec.exe",
        "vscode-win32-x64-user1121374930.tmp",
        "fodhelper.exe",
        "microsoft.aad.brokerplugin.exe",
        "texstudio.exe",
        "microsoft.notes.exe",
        "radeonsettings.exe",
        "igfxemn.exe",
        "winstore.app.exe",
        "gamebar.exe",
        "svchost.exe",
        "olk.exe",
        "_iu14d2n.tmp",
        "wwahost.exe",
        "windowsterminal.exe",
        "mmc.exe",
        "screenclippinghost.exe",
        "cortana.exe",
        "csc_ui.exe",
        "adobecollabsync.exe",
        "identity_helper.exe",
        "unins000.exe",
        "git-credential-manager.exe",
        "screensketch.exe",
        "launchtm.exe",
        "texstudio-4.7.3-win-qt6.exe",
        "phoneexperiencehost.exe",
        "hxoutlook.exe",
        "bootcamp.exe",
        "skypeapp.exe",
        "netplwiz.exe",
        "inno_updater.exe",
        "dccw.exe",
        "microsoft.photos.exe",
        "deviceproperties.exe",
        "dataexchangehost.exe",
        "applecontrolpanel.exe",
        "hxcalendarappimm.exe",
        "wireshark.exe",
        "microsoft.sharepoint.exe",
        "werfault.exe",
        "applebcupdate.exe",
        "softwareupdate.exe",
        "onedrivesetup.exe",
        "consent.exe",
        "plugin_host-3.8.exe",
        "runonce.exe",
        "googlecrashhandler.exe",
        "igfxem.exe",
        "systemsettingsadminflows.exe",
        "slack.exe",
        "notepad.exe",
        "openwith.exe",
        "sechealthui.exe",
        "msedgewebview2.exe",
        "java-update.exe",
        "wmic.exe",
    }

    print(f"Getting pickle files from '{args.graph_dir}'...")
    pickle_files = [
        os.path.join(args.graph_dir, f)
        for f in os.listdir(args.graph_dir)
        if f.endswith(".pkl") or f.endswith(".pickle")
    ]
    print(f"Got pickle files from '{args.graph_dir}':\n{pickle_files}")

    print("Getting graphs from pickle files...")
    graphs = [pickle_read(igraph_file) for igraph_file in pickle_files]
    print("Got graphs from pickle files!")

    print("Iterating over filter list to viz each program...")
    skipped_list = []

    for target_prog in empirical_filter_set:
        print(f"\nSearching graphs for all instances of {target_prog}...")
        instance_found = False

        for g in graphs:
            g_prog_names = {
                parse_program_name(name): i for i, name in enumerate(g.vs["name"])
            }

            if target_prog not in g_prog_names:
                continue

            target_prog_instances = [
                i for name, i in g_prog_names.items() if name == target_prog
            ]

            if not target_prog_instances:
                continue

            for vi in target_prog_instances:
                print(f"\nFound a process instance of {target_prog}!")
                instance_found = True

                print(f"Generating one hop neighborhood of {target_prog}...")
                selective_neighborhood = gen_selective_neighborhood(g, vi)

                if len(selective_neighborhood.vs) == 1:
                    print(f"\t...nevermind. No subgraph for {target_prog}, skipping.")
                    instance_found = False
                    break

                print("Dumping edges to csv...")
                dump_edges(
                    selective_neighborhood,
                    f"{args.csv_out_dir}/{target_prog}_edges.csv",
                )

                v_csv_filename = f"{args.csv_out_dir}/{target_prog}_vertices.csv"
                print(f"Preparing graph of {target_prog} for plotting...")
                prepare_graph(selective_neighborhood, v_csv_filename)

                pdf_filename = (
                    f"{args.pdf_out_dir}/{target_prog}_subgraph{subgraph_id}.pdf"
                )
                print(
                    f"Plotting {pdf_filename} (V={len(selective_neighborhood.vs)}, E={len(selective_neighborhood.es)})..."
                )
                plot_selective_neighborhood(selective_neighborhood, pdf_filename)

        if not instance_found:
            print("Failed to a find process instance of target program!")
            skipped_list.append(target_prog)

    print(f"Skipped the following programs:\n{skipped_list}")
