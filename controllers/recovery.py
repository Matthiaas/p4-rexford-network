""" Define classes and methods for links failure recovery here"""
from networkx import NetworkXNoPath
from networkx.algorithms import all_pairs_dijkstra, bridges
from networkx.algorithms.shortest_paths.generic import all_shortest_paths
from networkx.algorithms.shortest_paths.weighted import _dijkstra, all_pairs_dijkstra_path_length
from p4utils.utils.topology import NetworkGraph as Graph
from p4utils.utils.helper import load_topo
from scapy.all import *
import json
import os
import sys
import failure_generator
from errors import *
from typing import List, Set, Tuple, Dict


def read_settings():
    path = sys.argv[0]
    base_path = "/".join(path.split("/")[:-1])
    if base_path == "":
        base_path = "."
    with open(base_path + "/configs/settings.json", "r") as f:
        return json.load(f)


SETTINGS = read_settings()


class Fast_Recovery_Manager(object):
    @staticmethod
    def add_delay_weight(g: Graph):
        # transform delay from string to float
        if SETTINGS["use_edge_delay"]:
            for e in g.edges:
                try:
                    g[e[0]][e[1]]["delay_w"] = (
                        float(g[e[0]][e[1]]["delay"].replace("ms", ""))
                        + SETTINGS["switch_delay"]
                    )
                except:
                    g[e[0]][e[1]]["delay_w"] = float(1.0)
        else:
            for e in g.edges:
                g[e[0]][e[1]]["delay_w"] = float(1.0)

    @staticmethod
    def __load_link_fail_map(config_file: str):
        """
        To be called by controller at runtime after precomputation
        Args:
            links_fail_file: path to the config containing all the routing
            tables for the precomputed failures
        Returns:
            dict{set(failures):
                dict{switch: dict{host: dict{"nexthops": [str], "lfa": str}}}}
            dict{set(failures): dict{switch: dict{host: Rlfa}}
        """
        failure_rts = {}
        failure_rlfas = {}
        with open(config_file, "r") as f:
            m = json.load(f)["map"]
            for entry in m:
                failures = frozenset([tuple(x.split("-")) for x in entry["failures"]])
                failure_rts[failures] = entry["routing_tbl"]
                failure_rlfas[failures] = entry["Rlfas"]
        return failure_rts, failure_rlfas

    def __init__(self, topo: Graph, links_fail_file: str):

        if not os.path.exists(links_fail_file):
            print("[!] link_fail_map not found at:" + links_fail_file)
            raise FileNotFound()

        self.failure_rts = {}
        self.failure_rlfas = {}
        (
            self.failure_rts,
            self.failures_rlfas,
        ) = Fast_Recovery_Manager.__load_link_fail_map(links_fail_file)
        self.topo: Graph = topo  # passed by controller
        self.switches: List[str] = self.topo.get_p4switches().keys()
        self.hosts: List[str] = self.topo.get_hosts().keys()

    ##############################
    #                            #
    # Methods for precomputation #
    #                            #
    ##############################
    """
    compute_nexthops, compute_lfas and compute_Rlfas should be called before 
    runtime, i.e used to build the links_fail_file.json structure
    """

    # used before runtime
    @staticmethod
    def dijkstra(graph: Graph, failures: Set[Tuple[str, str]] = None):
        """Compute shortest paths.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            tuple(dict, dict): First dict: costs (delay in ms), second: paths.
        """
        _graph = graph.copy()
        if failures is not None:
            for failure in failures:
                _graph.remove_edge(*failure)

        try:
            paths = {}
            for sw in _graph.get_p4switches().keys():
                paths[sw] = {}
                d = {}
                p = {}
                for h in _graph.get_hosts().keys():
                    # add only path with different first hop
                    all_paths = [
                        path for path in all_shortest_paths(_graph, sw, h, "delay_w")
                    ]
                    nexthops = set()
                    ecmps = []
                    for path in all_paths:
                        if path[1] not in nexthops:
                            nexthops.add(path[1])
                            ecmps.append(path)
                    paths[sw][h] = ecmps
            costs = dict(all_pairs_dijkstra_path_length(_graph, weight="delay_w"))
            return costs, paths
        except NetworkXNoPath:
            # It might happen that we detect a failure configuration that would disconnect the graph.
            # This is not supposed to happen in the project.
            # However, if it does occur we use a best effort approach and just remove violating failures.
            # (The removed failures are not guaranteed to be minimal).
            print("Failure combination disconnects Graph: ", failures)
            if failures is None:
                raise NetworkXNoPath("Graph is inherently flawed... NONONONONO")
            _graph = graph.copy()
            new_failures = []
            for failure in failures:
                if not failure in list(bridges(_graph)):
                    _graph.remove_edge(*failure)
                    new_failures.append(failure)

            print("Recomputing with failures: ", new_failures)
            return Fast_Recovery_Manager.dijkstra(_graph, None)


    @staticmethod
    def compute_nexthops(shortest_paths, switches, hosts):
        """Compute the best nexthops for all switches to each host.

        Optionally, a link can be marked as failed. This link will be excluded
        when computing the shortest paths.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            dict(str, list(str, list(str)))):
                Mapping from all switches to [host,[nexthops]].
        """

        # Translate shortest paths to mapping from host to nexthop node
        # (per switch).
        results = {}
        for switch in switches:
            switch_results = results[switch] = []
            for host in hosts:
                try:
                    paths = shortest_paths[switch][host]
                except KeyError:
                    print("WARNING: The graph is not connected!")
                    print("'%s' cannot reach '%s'." % (switch, host))
                    raise NotConnected()
                # Need to remove duplicates
                nexthops = list(
                    set([path[1] for path in paths])
                )  # path[0] is the switch itself.
                switch_results.append((host, nexthops))

        return results

    @staticmethod
    def compute_lfas(graph: Graph, switches, hosts, costs, nexthops):
        """
        Compute per-destination LFA  for all nexthops.

        Returns lfas =
            dict{str: dict{str: list[str]}} -> dict{Switch: dict{dest: sorted list of LFAs}}
        """
        lfas = {}
        # for every switch...
        for sw, destinations in nexthops.items():
            lfas[sw] = {}
            neighs = set(graph.get_p4switches_connected_to(sw))
            # for every host we want to reach
            for host, nexthops in destinations:
                nexthop = nexthops[0]
                if nexthop == host:
                    # direct link to host
                    continue

                # Retain only candidates for alternative next hop,
                # i.e remove current primary hops.
                alt_neighs = neighs - set(nexthops)

                # Try to find LFA
                #   for host
                #   from current sw

                loop_free = []
                for alt in alt_neighs:
                    # D(N, D) < D(N, S) + D(S, D) triangle condition
                    if costs[alt][host] < costs[alt][sw] + costs[sw][host]:
                        total_dist = costs[sw][alt] + costs[alt][host]
                        loop_free.append((alt, total_dist))

                if not loop_free:
                    continue
                # LFA with shortest distance.
                # lfas[sw][host] = min(loop_free, key=lambda x: x[1])[0]
                loop_free.sort(key=lambda x: x[1])
                lfas[sw][host] = [e[0] for e in loop_free[:4]]

        return lfas

    @staticmethod
    def compute_Rlfas(graph: Graph, switches, costs, nexthops, lfas):
        """
        Implements the PQ algorithm for Remote LFAs

        Returns Rlfa = dict{str : dict{str: str}} -> dict{Switch: {Neigh: RLFA}}
            i.e it maps every switch to the RLFA for every link towards one of its neigh
            that could fail

        """
        Rlfas = {}
        all_nodes = set(switches)
        for sw in switches:
            neighs = list(graph.get_p4switches_connected_to(sw))
            # Per-link calculation -> failed link is sw-neigh.
            Rlfas[sw] = {}
            for neigh in neighs:
                nodes = all_nodes - set([sw, neigh])
                P = set()
                # Compute the P set, i.e all nodes reachable without going
                # through sw-neigh.
                for n in nodes:
                    paths_to_n = all_shortest_paths(graph, sw, n, weight="delay_w")
                    skips_protected = True
                    for path in paths_to_n:
                        path = "-".join(path)
                        if sw + "-" + neigh in path or neigh + "-" + sw in path:
                            skips_protected = False
                            break
                    if skips_protected:
                        P.add(n)
                Q = set()
                # Q set, i.e all nodes from which neigh is reachable without
                # going through sw-neigh.
                for n in nodes:
                    paths_to_d = all_shortest_paths(graph, n, neigh, weight="delay_w")
                    skips_protected = True
                    for path in paths_to_d:
                        path = "-".join(path)
                        if sw + "-" + neigh in path or neigh + "-" + sw in path:
                            skips_protected = False
                            break
                    if skips_protected:
                        Q.add(n)
                PQ = P.intersection(Q)

                # take a Rlfa that is not already an lfa:
                #   - identify all the hosts sw reach via neigh
                #   - get the lfas for all the hosts we reach via neigh
                #   - filter PQ removing nodes that are already lfas

                # print(f"PQ for link {sw}-{neigh}: {PQ}")

                hosts = []
                for host, this_nexthops in nexthops[sw]:
                    if neigh in this_nexthops:
                        hosts.append(host)

                # print(f"Hosts reachable from {sw} via {neigh}: {hosts}")

                lfas_of_link = set()
                for host in hosts:
                    try:
                        lfas_of_link.add(lfas[sw][host][0])
                    except:
                        continue
                # print(f"all lfas for {sw}: {lfas[sw]}")
                # print(f"lfas affected by link {sw}-{neigh}: {lfas_of_link}")
                PQ = list(PQ - lfas_of_link)
                # print(f"filtered PQ: {PQ}")

                # take the alternative with shortest metric
                if len(PQ) > 1:
                    metric = [costs[sw][n] for n in PQ]
                    sorted_alt = [x for _, x in sorted(zip(metric, PQ))]
                    Rlfas[sw][neigh] = sorted_alt[0]
                elif len(PQ) == 1:
                    Rlfas[sw][neigh] = PQ[0]
                else:
                    Rlfas[sw][neigh] = ""
        # print("Rlfas:\n",Rlfas)
        return Rlfas

    @staticmethod
    def compute_scmps(
        lfas: Dict[str, Dict[str, List[str]]],
        costs: Dict[str, Dict[str, int]],
        threshold: int = 5,
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Find which LFAs can be used as SCMP paths.

        Args:
            lfas: Already computed lfas for all the switches
                (dict[switch, dict[destination, port]])
            costs: shortest path costs between all nodes
                (dict[src, dict[dest, distance]])
            threshold: Threshold of added delay by using LFA over shortest path
                (at this hop) in ms
        Returns:
            SCMP next hops for src and destination.
        """
        scmps: Dict[str, Dict[str, str]] = {}
        for src, dests in lfas.items():
            scmps[src] = {}
            for dst, lfas in dests.items():
                delay_shortest = costs[src][dst]

                def is_cheap_enough(lfa):
                    delay_scmp = costs[src][lfa] + costs[lfa][dst]
                    diff = delay_scmp - delay_shortest
                    # if diff < threshold:
                    #     print(f"{src} - {dst}: {lfa} {delay_shortest} {delay_scmp}")
                    return diff < threshold

                scmp_hops = [lfa for lfa in lfas if is_cheap_enough(lfa)]
                scmps[src][dst] = scmp_hops
        return scmps

    @staticmethod
    def __form_routing(graph, switches, hosts, failures=None):
        """
        Forms the routing state for the current failure scenario
        Returns a scenario data structure
        """

        # dijkstra handles removing the failed links here
        costs, shortest_paths = Fast_Recovery_Manager.dijkstra(graph, failures)
        nexthops = Fast_Recovery_Manager.compute_nexthops(
            shortest_paths, switches, hosts
        )
        lfas = Fast_Recovery_Manager.compute_lfas(
            graph, switches, hosts, costs, nexthops
        )
        sim_cost_paths = Fast_Recovery_Manager.compute_scmps(
            lfas, costs, SETTINGS["scmp_threshold"]
        )
        Rlfas = Fast_Recovery_Manager.compute_Rlfas(
            graph, switches, costs, nexthops, lfas
        )

        routing_tbl = {}
        for sw in switches:
            routing_tbl[sw] = {}
            for host, this_nexthops in nexthops[sw]:
                try:
                    lfa = lfas[sw][host][:2]
                    scmp = sim_cost_paths[sw][host]
                except:
                    # no lfa
                    lfa = []
                    scmp = []
                routing_tbl[sw][host] = {
                    "nexthops": this_nexthops,
                    "lfa": lfa,
                    "scmps": scmp,
                }

        scenario = {
            "failures": [failure_generator.edge_to_string(x) for x in failures],
            "routing_tbl": routing_tbl,
            "Rlfas": Rlfas,
        }
        return scenario

    @staticmethod
    def precompute_routing(
        graph: Graph,
        switches: List[str],
        hosts,
        all_failures: List[List[Tuple[str, str]]] = None,
    ):
        """
        Given a (sub)set of all possible failures from config, computes the
        routing table for all switches and dumps it into config.
        """
        # dumps into this file
        with open("./configs/link_failure_map_generated.json", "w") as f:
            map = {"map": []}
            scenarios = []
            if not all_failures:
                all_failures = [None]
            for failures in all_failures:
                scenario = Fast_Recovery_Manager.__form_routing(
                    graph, switches, hosts, failures
                )
                scenarios.append(scenario)
            map["map"] = scenarios
            json.dump(map, f)

    #############################
    #                           #
    #   CONTROLLER INTERFACE    #
    #                           #
    #############################

    def query_routing_state(self, failures=[]):
        """Called by controller to retrieve routing state given failures"""
        try:
            rt = self.failure_rts[frozenset(failures)]
            rlfa = self.failures_rlfas[frozenset(failures)]
            print(
                f"Recovery: loaded routing tables and rlfas from config for failures {failures}"
            )
            return rt, rlfa
        except KeyError:
            scenario = Fast_Recovery_Manager.__form_routing(
                self.topo, self.switches, self.hosts, failures
            )
            print(f"Scenario for {failures} not found in config. Recomputing...")
            print("[*] Scenario:\n")
            print(scenario)
            return scenario["routing_tbl"], scenario["Rlfas"]


def main(argv, argc):
    no_failures = False
    generate_all_failures = False
    generate_likely_failures = False
    args = argv[1:]
    links_file_path = ""
    likely_failures_dir = ""

    if "--no-failures" in args:
        no_failures = True
    elif "--generate-all-failures" in args:
        generate_all_failures = True
    elif "--generate-likely-failures" in args:
        for arg in args:
            if arg.startswith("-l="):
                links_file_path = arg[3:]
            if arg.startswith("-f="):
                likely_failures_dir = arg[3:]
        if not links_file_path or not likely_failures_dir:
            print("please specify -l= and -f= flags.")
            exit(-1)
        generate_likely_failures = True

    if "-h" in args:
        print("Usage: python ./recovery.py [--no-failures] [--generate-all-failures] [--generate-likely-failures -l=<path_to_additional_links> -f=<path_to_failures_dir>]")
        exit()

    print("[*] Generating Configurations...")
    graph = load_topo("../topology.json")
    failure_path = "./configs/failures_generated.json"
    # done
    if generate_all_failures:
        failure_generator.generate_possible_failures(graph, failure_path)
    if generate_likely_failures:
        failure_generator.generate_most_likely_failures(graph, likely_failures_dir, links_file_path, failure_path)
    print("[*] Failures computed, computing routing scenarios...")
    if no_failures:
        all_failures = [[]]
    else:
        all_failures = failure_generator.load_failures(failure_path)
        if not [] in all_failures:
            all_failures.append([])
    Fast_Recovery_Manager.add_delay_weight(graph)
    Fast_Recovery_Manager.precompute_routing(
        graph, graph.get_p4switches().keys(), graph.get_hosts().keys(), all_failures
    )
    print("...done")


if __name__ == "__main__":
    main(sys.argv, len(sys.argv))
