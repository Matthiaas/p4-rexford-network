""" Define classes and methods for links failure recovery here"""
from networkx.algorithms import all_pairs_dijkstra
from p4utils.utils.topology import NetworkGraph as Graph
from scapy.all import *
import json
import os

from errors import *

def load_link_fail_map(links_fail_file):
    """
        Args:
            links_fail_file:path to link_fail.json
        Returns:
            Array of JSON. "failures" is converted to a set for ease of lookup
    """
    with open(links_fail_file, 'r') as f:
        data = json.load(f)
        return [{"failures":set(x["failures"]),"routing_tbl":x["routing_tbl"]} for x in data["map"]]

class Fast_Recovery_Manager(object):

    def __init__(self, topo: Graph, links_fail_file: str):
        
        if not os.path.exists(links_fail_file):
            print("[!] link_fail_map not found")
            raise FileNotFound()

        self.fail_map = load_link_fail_map(links_fail_file)
        #example of access to the structure
        #print(fail_map[0]["failures"])
        #print(fail_map[0]["routing_tbl"]["switch1"]["host1"])
        self.topo = topo #passed by controller
        self.switches = self.topo.get_p4switches().keys()
        self.hosts = self.topo.get_hosts()
        self.failures = set()

    def query_map(self, failures):
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

    def load_nexthops_and_lfas(self, failures=None):
        """Load nexthops and lfas from state

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            dict{str, dict{str: [(str, int, str)]}} -> dict{switch, 
                                                                dict
                                                                    {host: 
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
            for host in self.hosts:
                hops = routing_tbl[sw][host] #nh, lfa
                state = []
                for hop in hops:
                    if hop == "":
                        #no nexthop (should not be possible...) or no lfa :(
                        state.append(("", -1, ""))
                    else:
                        mac = self.topo.get_node_to_node_mac(hop,sw)
                        port = self.topo.node_to_node_port_num(sw,hop)
                        state.append((hop, port, mac))    
                nexthops[sw] = {host: state}
        return nexthops

    def get_nexthop(nexthops, switch, host):
        #Get the next hop for host from switch given nexthops=load_nexthops_and_lfas()
        return nexthops[switch][host][0]
    
    def get_lfa(nexthops, switch, host):
        #Get the lfa for host from switch given nexthops=load_nexthops_and_lfas()
        return nexthops[switch][host][1]

    """
    compute_nexthops and compute_lfas should be called before runtime, i.e used
    to build the links_fail_file.json structure
    """
    def compute_nexthops(self, failures=None):
        """Compute the best nexthops for all switches to each host.

        Optionally, a link can be marked as failed. This link will be excluded
        when computing the shortest paths.

        Args:
            failures (list(tuple(str, str))): List of failed links.

        Returns:
            dict(str, list(str, str, int))):
                Mapping from all switches to subnets, MAC, port.
        """
        # Compute the shortest paths from switches to hosts.
        all_shortest_paths = self.dijkstra(failures=failures)[1]

        # Translate shortest paths to mapping from host to nexthop node
        # (per switch).
        results = {}
        for switch in self.switches:
            switch_results = results[switch] = []
            for host in self.hosts:
                try:
                    path = all_shortest_paths[switch][host]
                except KeyError:
                    print("WARNING: The graph is not connected!")
                    print("'%s' cannot reach '%s'." % (switch, host))
                    continue
                nexthop = path[1]  # path[0] is the switch itself.
                switch_results.append((host, nexthop))

        return results
    
    def compute_lfas(self, nexthops, failures=None):
        """Compute LFA (loop-free alternates) for all nexthops."""
        lfas = {}
        distances = self.dijkstra(failures=failures)[0]
        #for every switch...
        for sw, destinations in nexthops.items():
            lfas[sw] = {}
            neighs = set(self.topo.get_p4switches_connected_to(sw))
            #for every host we want to reach
            for host, nexthop in destinations:
                if nexthop == host:
                    # direct link to host
                    continue
                
                #retain only candidates for alternative next hop, i.e remove current primary hop
                alt_neighs = neighs - {nexthop}

                #try to find LFA
                    # for host 
                    # from current sw
                
                loop_free = []
                for alt in alt_neighs:
                    # D(N, D) < D(N, S) + D(S, D)
                    if (distances[alt][host] < distances[alt][sw] + distances[sw][host]):
                        total_dist = distances[sw][alt] + distances[alt][host]
                        loop_free.append((alt, total_dist))

                if not loop_free:
                    continue
                #LFA with shortest distance
                lfas[sw][host] = min(loop_free, key=lambda x: x[1])[0]

        return lfas

    # used before runtime
    def dijkstra(graph, failures=None):
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
    

recovery = Fast_Recovery_Manager('example_link_failure_map.json')
