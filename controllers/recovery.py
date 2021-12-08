""" Define classes and methods for links failure recovery here"""
from networkx.algorithms import all_pairs_dijkstra, bridges
from networkx.algorithms.shortest_paths.generic import shortest_path,all_shortest_paths, shortest_path_length
from p4utils.utils.topology import NetworkGraph as Graph
from p4utils.utils.helper import load_topo
from scapy.all import *
import json
import os
from pickle import loads, dumps
import sys

from errors import *
from typing import List, Set, Tuple, Dict


class Fast_Recovery_Manager(object):
    @staticmethod
    def add_delay_weight(g: Graph):
        #transform delay from string to float
        for e in g.edges:
            g[e]['delay_w'] = float(g[e]['delay'].replace('ms',''))
    
    @staticmethod
    def parse_failures(failures: List[str]) -> List[Tuple[str, str]]:
        """
        Takes failures like ["s1-s2", "s2-s3"] and returns [(s1,s2),(s2,s3)]
        """
        f = []
        for link in failures:
            nodes = link.split("-")
            f.append((nodes[0], nodes[1]))
        return f

    @staticmethod
    def edge_to_string(e: Tuple[str, str]):
        return "{}-{}".format(e[0], e[1])

    @staticmethod
    def get_non_bridges(g: Graph):
        return [x for x in list(g.edges) if x not in list(bridges(g))]

    @staticmethod
    def __generate_possible_failures_helper(g: Graph, found_failure_sets: Set[str], cur_failure_set: List[str]):
        non_bridges = Fast_Recovery_Manager.get_non_bridges(g)
        for e in non_bridges:
            e_string = Fast_Recovery_Manager.edge_to_string(e)
            cur_failure_set.append(e_string)
            cur_failure_set.sort()
            cur_failure_set_string = ",".join(cur_failure_set)

            if cur_failure_set_string in found_failure_sets:
                cur_failure_set.remove(e_string)
                continue
            found_failure_sets.add(cur_failure_set_string)

            g_copy = g.copy()
            g_copy.remove_edge(e[0], e[1])
            Fast_Recovery_Manager.__generate_possible_failures_helper(g_copy, found_failure_sets, cur_failure_set)
            cur_failure_set.remove(e_string)
        return found_failure_sets

    @staticmethod
    def generate_possible_failures(g: Graph, failures_opath: str):
        possible_failures_str = Fast_Recovery_Manager.__generate_possible_failures_helper(g.copy(), set(), [])
        possible_failures = [x.split(",") for x in possible_failures_str]
        with open(failures_opath, "w") as f:
            json.dump({"failures": possible_failures}, f)

    @staticmethod
    def __load_link_fail_map(config_file: str):
        """
            To be called by controller at runtime after precomputation
            Args:
                links_fail_file: path to the config containing all the routing tables for the precomputed failures
            Returns:
                dict{set(failures): dict{switch: dict{host: dict{"nexthops": [str], "lfa": str}}}}
                dict{set(failures): dict{switch: dict{host: Rlfa}}
        """
        failure_rts = {}
        failure_rlfas = {}
        with open(config_file, 'r') as f:
            for entry in json.load(f)["map"]:
                failures = frozenset(entry["failures"])
                failure_rts[failures] = entry["routing_tbl"]
                failure_rlfas[failures] = entry["Rlfas"]
        return failure_rts, failure_rlfas


    def __init__(self, topo: Graph, links_fail_file: str):

        if not os.path.exists(links_fail_file):
            print("[!] link_fail_map not found at:" + links_fail_file)
            raise FileNotFound()

        self.failure_rts = {}
        self.failure_rlfas = {}
        self.failure_rts, self.failures_rlfas = Fast_Recovery_Manager.__load_link_fail_map(links_fail_file)
        self.topo: Graph = topo  # passed by controller
        self.switches: List[str] = self.topo.get_p4switches().keys()
        self.hosts: List[str] = self.topo.get_hosts().keys()


    ##############################
    #                            #                           
    # Methods for precomputation #                           
    #                            #
    ##############################
    """
    compute_nexthops, compute_lfas and compute_Rlfas should be called before runtime, i.e used
    to build the links_fail_file.json structure
    """

    # used before runtime
    @staticmethod
    def dijkstra(graph: Graph, failures: Set[Tuple[str, str]] = None):
        """Compute shortest paths.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            tuple(dict, dict): First dict: distances, second: paths.
        """
        if failures is not None:
            graph = graph.copy()
            for failure in failures:
                graph.remove_edge(*failure)

        paths = {}
        distances = {}
        for sw in graph.get_p4switches().keys():
            paths[sw] = {}
            distances[sw] = {}
            d = {}
            p = {}
            for h in graph.get_hosts().keys():
                # add only path with different first hop
                all_paths = [path for path in all_shortest_paths(graph, sw, h, 'delay_w')]
                nexthops = set()
                ecmps = []
                for path in all_paths:
                    if path[1] not in nexthops:
                        nexthops.add(path[1])
                        ecmps.append(path)
                paths[sw][h] = ecmps
                #if len(paths[sw][h]) > 1:
                    #print(f"ECMP PATH {sw}->{h}\nNexthops:\n")
                    #for path in paths[sw][h]:
                    #    print("-"+path[1]+"\n")
                distances[sw][h] = shortest_path_length(graph, sw, h, 'delay_w')
            #add distances between switches
            for sw2 in graph.get_p4switches().keys():
                if sw == sw2:
                    continue
                distances[sw][sw2] = shortest_path_length(graph, sw2, h, 'delay_w')
        return distances, paths

    @staticmethod
    def compute_nexthops(shortest_paths, switches, hosts, failures=None):
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
                nexthops = list(set([path[1] for path in paths]))  # path[0] is the switch itself.
                switch_results.append((host, nexthops))

        return results

    @staticmethod
    def compute_lfas(graph: Graph, switches, hosts, distances, nexthops, failures=None):
        """
        Compute per-destination LFA  for all nexthops.
        
        Returns lfas = dict{str: dict{str: str}} -> dict{Switch: dict{dest: LFA}}
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

                # retain only candidates for alternative next hop, i.e remove current primary hop
                alt_neighs = neighs - set(nexthops)

                # try to find LFA
                #   for host
                #   from current sw

                loop_free = []
                for alt in alt_neighs:
                    # D(N, D) < D(N, S) + D(S, D) triangle condition
                    if (distances[alt][host] < distances[alt][sw] + distances[sw][host]):
                        total_dist = distances[sw][alt] + distances[alt][host]
                        loop_free.append((alt, total_dist))

                if not loop_free:
                    continue
                # LFA with shortest distance
                lfas[sw][host] = min(loop_free, key=lambda x: x[1])[0]

        return lfas

    @staticmethod
    def compute_Rlfas(graph: Graph, switches, failures=None):
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
            # per-link calculation -> failed link is sw-neigh
            Rlfas[sw] = {}
            for neigh in neighs:
                nodes = all_nodes - set([sw, neigh])
                P = set()
                #compute the P set, i.e all nodes reachable without going through sw-neigh
                for n in nodes:
                    paths_to_n = all_shortest_paths(graph, sw, n, weight='delay_w')
                    skips_protected = True
                    for path in paths_to_n:
                        path = '-'.join(path)
                        #print(f"P: failure {sw}-{neigh}, path from {sw} to {n}: {path}")
                        if sw+"-"+neigh in path or neigh+"-"+sw in path:
                            skips_protected = False
                            break
                    if skips_protected:
                        P.add(n)
                Q = set()
                # Q set, i.e all nodes from which neigh is reacheable without going through sw-neigh
                for n in nodes:
                    paths_to_d = all_shortest_paths(graph, n, neigh, weight='delay_w')
                    skips_protected = True
                    for path in paths_to_d:
                        path = '-'.join(path)
                        #print(f"Q: failure {sw}-{neigh}, path from {n} to {neigh}: {path}")
                        if sw+"-"+neigh in path or neigh+"-"+sw in path:
                            skips_protected = False
                            break
                    if skips_protected:
                        Q.add(n)
                PQ = list(P.intersection(Q))
                #take the alternative with shortest metric
                if len(PQ) > 1:
                    distances = [shortest_path_length(graph, sw, n, weight='delay_w') for n in PQ]
                    sorted_alt = [x for _,x in sorted(zip(distances, PQ))]
                    Rlfas[sw][neigh] = sorted_alt[0]
                elif len(PQ) == 1:
                    Rlfas[sw][neigh] = PQ[0]
                else:
                    Rlfas[sw][neigh] = ""
        print("Rlfas:\n",Rlfas)
        return Rlfas

    @staticmethod
    def load_failures(all_fails: str) -> List[List[Tuple[str, str]]]:
        """Loads all possible failures from config"""
        all_failures = []
        with open(all_fails, 'r') as f:
            data = json.load(f)
            for failures in data["failures"]:
                all_failures.append(Fast_Recovery_Manager.parse_failures(failures))
        return all_failures
    
    @staticmethod
    def __form_routing(graph, switches, hosts, failures=None):
        """
            Forms the routing state for the current failure scenario
            Returns a scenario data structure
        """
        
        #dijkstra handles removing the failed links here
        distances, shortest_paths = Fast_Recovery_Manager.dijkstra(graph, failures)
        nexthops = Fast_Recovery_Manager.compute_nexthops(shortest_paths, switches, hosts, failures)
        lfas = Fast_Recovery_Manager.compute_lfas(graph, switches, hosts, distances, nexthops, failures)
        Rlfas = Fast_Recovery_Manager.compute_Rlfas(graph, switches, failures)
        
        routing_tbl = {}
        for sw in switches:
            routing_tbl[sw] = {}
            for host, this_nexthops in nexthops[sw]:
                try:
                    lfa = lfas[sw][host]
                except:
                    #no lfa
                    lfa = ""
                routing_tbl[sw][host] = {"nexthops":this_nexthops, "lfa":lfa}
        scenario = {"failures": [Fast_Recovery_Manager.edge_to_string(x) for x in failures],\
                            "routing_tbl": routing_tbl,\
                            "Rlfas": Rlfas}
        return scenario

    @staticmethod
    def precompute_routing(graph: Graph, switches: List[str], hosts, all_failures: List[List[Tuple[str, str]]] = None):
        """
            Given a (sub)set of all possible failures from config, computes the routing table for all switches
            and dumps it into config
        """
        #dumps into this file
        with open("./configs/link_failure_map_generated.json", 'w') as f:
            map = {"map": []}
            scenarios = []
            if not all_failures:
                all_failures = [None]
            for failures in all_failures:
                scenario = Fast_Recovery_Manager.__form_routing(graph, switches, hosts, failures)
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
            print(f"Recovery: loaded routing tables and rlfas from config for failures {failures}")
            return rt, rlfa
        except KeyError:
            scenario = Fast_Recovery_Manager.__form_routing(self.topo, self.switches, self.hosts, failures)
            print(f"Scenario not found in config. Recomputing...")
            print("[*] Scenario:\n")
            print(scenario)
            return scenario["routing_tbl"], scenario["Rlfas"]

    
def main(argv, argc):
    no_failures = False
    if argc > 1 and argv[1] == "nofailures":
        no_failures = True
    print("[*] Generating Configurations...")
    graph = load_topo("../topology.json")
    failure_path = "./configs/failures_generated.json"
    # done
    #Fast_Recovery_Manager.generate_possible_failures(graph, failure_path)
    print("[*] Failures computed, computing routing scenarios...")
    if no_failures:
        all_failures = [[]]
    else:
        all_failures = Fast_Recovery_Manager.load_failures(failure_path)
    Fast_Recovery_Manager.precompute_routing(graph, graph.get_p4switches().keys(), graph.get_hosts().keys(), all_failures)


# recovery = Fast_Recovery_Manager('example_link_failure_map.json')
if __name__ == "__main__":
    main(sys.argv, len(sys.argv))