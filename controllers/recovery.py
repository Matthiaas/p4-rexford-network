""" Define classes and methods for links failure recovery here"""
from networkx.algorithms import all_pairs_dijkstra, bridges
from networkx.algorithms.shortest_paths.generic import shortest_path
from p4utils.utils.topology import NetworkGraph as Graph
from p4utils.utils.helper import load_topo
from scapy.all import *
import json
import os
from pickle import loads, dumps

from errors import *
from typing import List, Set, Tuple, Dict


class Fast_Recovery_Manager(object):

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

    def load_link_fail_map(self, links_fail_file: str) -> List[Dict[str, object]]:
        """
            Args:
                links_fail_file:path to link_fail.json
            Returns:
                Array of JSON. "failures" is converted to a set for ease of lookup
        """
        with open(links_fail_file, 'r') as f:
            data = json.load(f)
            return [{"failures": set(self.parse_failures(x["failures"])), "routing_tbl": x["routing_tbl"]} for x in data["map"]]

    def __init__(self, topo: Graph, links_fail_file: str):

        if not os.path.exists(links_fail_file):
            print("[!] link_fail_map not found")
            raise FileNotFound()

        self.fail_map: List[Dict[str, object]] = self.load_link_fail_map(links_fail_file)
        # example of access to the structure
        # print(fail_map[0]["failures"])
        # print(fail_map[0]["routing_tbl"]["switch1"]["host1"])
        self.topo: Graph = topo  # passed by controller
        self.switches: List[str] = self.topo.get_p4switches().keys()
        self.hosts: List[str] = self.topo.get_hosts()
        self.failures: Set[Tuple[str, str]] = set()

    def query_map(self, failures: List[Tuple[str, str]]):
        """
            Query the failure map given the failures to recover the state that should be applied
            
            Args:
                failures: list(tuple(str,str))
            Returns:
                routing_tbl: dict{str: dict{str: str}} -> dict{switch: {host: nh}}
        """
        failures = set(failures)
        for scenario in self.fail_map:
            if scenario["failures"] == failures:
                return scenario["routing_tbl"]
        raise ScenarioNotFound()

    def load_nexthops_and_lfas(self, failures: List[Tuple[str, str]] = None) -> Dict[str, List[Tuple[str, int, str]]]:
        """
        Load nexthops and lfas from state

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            dict{str, dict{str: [(str, int, str)]}} -> dict{switch:
                                                                    dict{
                                                                        host: 
                                                                            [
                                                                                (primary_nh, port, mac),
                                                                                (secondary_nh,port,mac)
                                                                            ]
                                                                    }
                                                                }
        """
        
        nexthops = {}
        routing_tbl = self.query_map(failures)
        for sw in self.switches:
            d = {}
            for host in self.hosts:
                hops = routing_tbl[sw][host]  # nh, lfa
                state = []
                for hop in hops:
                    if hop == "":
                        # no nexthop (should not be possible...) or no lfa :(
                        state.append(("", -1, ""))
                    else:
                        mac = self.topo.get_node_to_node_mac(hop, sw)
                        port = self.topo.node_to_node_port_num(sw, hop)
                        state.append((hop, port, mac))
                d[host] = state
            nexthops[sw] = d
        return nexthops

    def get_nexthop(nexthops, switch, host):
        # Get the next hop for host from switch given nexthops=load_nexthops_and_lfas()
        return nexthops[switch][host][0]

    def get_lfa(nexthops, switch, host):
        # Get the lfa for host from switch given nexthops=load_nexthops_and_lfas()
        return nexthops[switch][host][1]

    ##############################
    #                            #                           
    # Methods for precomputation #                           
    #                            #
    ##############################
    """
    compute_nexthops and compute_lfas should be called before runtime, i.e used
    to build the links_fail_file.json structure
    """

    # used before runtime
    @staticmethod
    def dijkstra(graph: Graph, failures: Set[Tuple[str, str]] = None):
        """Compute shortest paths and distances.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            tuple(dict, dict): First dict: distances, second: paths.
        """
        if failures is not None:
            graph = graph.copy()
            for failure in failures:
                graph.remove_edge(*failure)

        # Compute the shortest paths from switches to hosts.
        dijkstra = dict(all_pairs_dijkstra(graph, weight='weight'))

        distances = {node: data[0] for node, data in dijkstra.items()}
        paths = {node: data[1] for node, data in dijkstra.items()}

        return distances, paths

    @staticmethod
    def compute_nexthops(shortest_paths, switches, hosts, failures=None):
        """Compute the best nexthops for all switches to each host.

        Optionally, a link can be marked as failed. This link will be excluded
        when computing the shortest paths.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            dict(str, list(str, str))):
                Mapping from all switches to [host,nexthop].
        """

        # Translate shortest paths to mapping from host to nexthop node
        # (per switch).
        results = {}
        for switch in switches:
            switch_results = results[switch] = []
            for host in hosts:
                try:
                    path = shortest_paths[switch][host]
                except KeyError:
                    print("WARNING: The graph is not connected!")
                    print("'%s' cannot reach '%s'." % (switch, host))
                    raise NotConnected()
                nexthop = path[1]  # path[0] is the switch itself.
                switch_results.append((host, nexthop))

        return results

    @staticmethod
    def compute_lfas(graph: Graph, switches, hosts, distances, nexthops, failures=None):
        """Compute LFA (loop-free alternates) for all nexthops."""
        lfas = {}
        # for every switch...
        for sw, destinations in nexthops.items():
            lfas[sw] = {}
            neighs = set(graph.get_p4switches_connected_to(sw))
            # for every host we want to reach
            for host, nexthop in destinations:
                if nexthop == host:
                    # direct link to host
                    continue

                # retain only candidates for alternative next hop, i.e remove current primary hop
                alt_neighs = neighs - {nexthop}

                # try to find LFA
                #   for host
                #   from current sw

                loop_free = []
                for alt in alt_neighs:
                    # D(N, D) < D(N, S) + D(S, D)
                    if (distances[alt][host] < distances[alt][sw] + distances[sw][host]):
                        total_dist = distances[sw][alt] + distances[alt][host]
                        loop_free.append((alt, total_dist))

                if not loop_free:
                    continue
                # LFA with shortest distance
                lfas[sw][host] = min(loop_free, key=lambda x: x[1])[0]

        return lfas

    @staticmethod
    def load_failures(all_fails: str) -> List[List[Tuple[str, str]]]:
        all_failures = []
        with open(all_fails, 'r') as f:
            data = json.load(f)
            for failures in data["failures"]:
                all_failures.append(Fast_Recovery_Manager.parse_failures(failures))
        return all_failures

    @staticmethod
    def precompute_routing(graph: Graph, switches: List[str], hosts, all_failures: List[List[Tuple[str, str]]] = None):
        print("configs/link_failure_map_generated.json")
        with open("configs/link_failure_map_generated.json", 'w') as f:
            map = {"map": [], "_comment": []}
            scenarios = []
            if not all_failures:
                all_failures = [None]
            for failures in all_failures:
                distances, shortest_paths = Fast_Recovery_Manager.dijkstra(graph, failures)
                nexthops = Fast_Recovery_Manager.compute_nexthops(shortest_paths, switches, hosts, failures)
                lfas = Fast_Recovery_Manager.compute_lfas(graph, switches, hosts, distances, nexthops, failures)
                routing_tbl = {}
                for sw in switches:
                    routing_tbl[sw] = {}
                    for host in hosts:
                        routing_tbl[sw][host] = []
                        for h, nh in nexthops[sw]:
                            if h == host:
                                routing_tbl[sw][host].append(nh)
                                try:
                                    lfa = lfas[sw][host]
                                except:
                                    # no lfa
                                    lfa = ""
                                routing_tbl[sw][host].append(lfa)
                scenario = {"failures": [Fast_Recovery_Manager.edge_to_string(x) for x in failures], "routing_tbl": routing_tbl}
                scenarios.append(scenario)
            map["map"] = scenarios
            json.dump(map, f)


def main():
    print("Generating Configurations...")
    graph = load_topo("../topology.json")
    failure_path = "./configs/failures_generated.json"
    Fast_Recovery_Manager.generate_possible_failures(graph, failure_path)
    all_failures = Fast_Recovery_Manager.load_failures(failure_path)
    Fast_Recovery_Manager.precompute_routing(graph, graph.get_p4switches().keys(), graph.get_hosts().keys(), all_failures)


# recovery = Fast_Recovery_Manager('example_link_failure_map.json')
if __name__ == "__main__":
    main()
