
import time
import threading
from multiprocessing.pool import ThreadPool
from recovery import Fast_Recovery_Manager as FRM
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from rexfordutils import RexfordUtils
import numpy as np
import time

class RoutingTableManager(object):
    def __init__(self, time_interval, controllers, topo, recovery_manager):
        """Initializes the topology and data structures."""
        self.time_interval = time_interval
        self.controllers = controllers
        self.topo = topo 
        self.recovery_manager = recovery_manager
        self.workers = ThreadPool(16) # One worker for each switch     
        self.has_changed = False 
        self.failed_links = set()
        self.failures_of_current_rt = set()
        self.lock = threading.Lock()
        self.t = None
       
    def fail_link(self, failed_link):
        self.lock.acquire()
        if failed_link not in self.failed_links and failed_link in FRM.get_non_bridges(self.topo):
            self.failed_links.add(failed_link)
            self.has_changed = True
        self.lock.release()

    def restore_link(self, restored_link):
        self.lock.acquire()
        if restored_link in self.failed_links:
            self.failed_links.remove(restored_link)
            self.has_changed = True
        self.lock.release()

    def __check_changed(self):
        while True:
            print("Investigating changes.")
            self.lock.acquire()
            if self.has_changed:
                print("Change found. Getting routing tables for failure: ", self.failed_links)
                self.has_changed = False
                routing_tables, Rlfas = self.recovery_manager.query_routing_state(self.failed_links)
                self.lock.release()
                print(f"Got routing table and rlfas. Loading...")
                self.update_all_routing_tables(routing_tables, Rlfas, False)
                print(f"Loading completed.")
            else:
                self.lock.release()
                time.sleep(self.time_interval)


    def update_all_routing_tables(self, routing_tables, Rlfas, init=False): 
        def update_singel_routing_table(p4switch):    
            cont = self.controllers[p4switch]            
            rt = routing_tables[p4switch]
            ecmp_group_id = 0
            print("Loading routing tables for ", p4switch)
            for host_name, routs in rt.items():
                host_addr = RexfordUtils.get_rexford_addr(self.topo, host_name)               
                nexthopports = [ 
                    str(self.topo.node_to_node_port_num(p4switch, nexthop)) 
                        for nexthop in routs["nexthops"]]
                scmp_nexthopports = [
                    str(self.topo.node_to_node_port_num(p4switch, nexthop))
                        for nexthop in routs.get("scmps", [])]
                nexthop_escmp_ports = nexthopports + [p for p in scmp_nexthopports if p not in nexthopports]


                lfa = routs["lfa"]
                lfa_port = None
                if lfa != "":
                    lfa_port = str(self.topo.node_to_node_port_num(p4switch, lfa))                 
                
                print("Adding nexthops and lfa:")
                print([nexthop_escmp_ports, lfa_port])
            
                if len(nexthop_escmp_ports) == 1:
                    # We only need to set the nexthop and not any ESCP stuff.
                    self.__add_set_next_hop(cont, "ipv4_forward", 
                            match_keys=[host_addr], 
                            next_port=nexthop_escmp_ports[0], 
                            lfa_port=lfa_port, init=init)
                else:
                    self.__modifiy_or_add(cont=cont,
                            table_name="ipv4_forward", 
                            action_name="escmp_group", 
                            match_keys=[host_addr],
                            action_params=[str(ecmp_group_id), str(len(nexthopports)), str(len(nexthop_escmp_ports))])
                    port_hash = 0
                    for nextport in nexthop_escmp_ports:
                        # Why are we setting lfa if ecmp?
                        self.__add_set_next_hop(cont, "escmp_group_to_nhop", 
                            match_keys=[str(ecmp_group_id), str(port_hash)], 
                            next_port=nextport, 
                            lfa_port=lfa_port,
                            init=init)
                        port_hash = port_hash + 1 
                    ecmp_group_id = ecmp_group_id + 1
                
            #set Rlfas
            for neigh, rlfa in Rlfas[p4switch].items():
                if rlfa != "":
                    link_port = self.topo.node_to_node_port_num(p4switch, neigh)
                    #get nexthop for getting to the rlfa
                    rlfa_host = RexfordUtils.get_rexford_addr(
                        self.topo, RexfordUtils.get_host_of_switch(rlfa))
                    rlfa_host_nexthops = rt[RexfordUtils.get_host_of_switch(rlfa)]["nexthops"]
                    rlfa_port = 0
                    for nh in rlfa_host_nexthops:
                        #clearly has to be different than the neigh for which the link fails
                        if nh != neigh:
                            rlfa_port = self.topo.node_to_node_port_num(p4switch, nh)
                    print(f"Adding Rlfa link {p4switch}--{neigh} rlfa: {rlfa} port: {rlfa_port}")
                    self.__modifiy_or_add(cont=cont,
                            table_name="final_forward",
                            action_name="set_nexthop_lfa_rlfa",
                            match_keys=[str(link_port)],
                            action_params=[rlfa_host, str(rlfa_port)])
            print("Loaded routing tables for ", p4switch)
                           
        self.workers.map(update_singel_routing_table, self.topo.get_p4switches())

    def __modifiy_or_add(self, cont, table_name, action_name, match_keys, action_params=[], init=False):
            entry_handle = None
            if not init:
                # No need to try to update the entry when we init.
                entry_handle = cont.get_handle_from_match(table_name, match_keys)
            if entry_handle is not None:
                cont.table_modify(table_name, action_name, entry_handle, action_params)
            else:
                cont.table_add(table_name, action_name, match_keys, action_params)

    # maps refxord addr or ecmp group to nexthop port and lfa if possible
    def __add_set_next_hop(self, cont, table_name, match_keys, next_port, lfa_port=None, init=False):
        if lfa_port:
            self.__modifiy_or_add(cont=cont,
                table_name=table_name, action_name="set_nhop_and_lfa", 
                    match_keys=match_keys, action_params=[next_port, lfa_port])
        else:
            self.__modifiy_or_add(cont=cont,
                table_name=table_name, action_name="set_nhop", 
                    match_keys=match_keys, action_params=[next_port])

    def run(self):
        """Main runner"""
        # Load default table.
        routing_tables, Rlfas = self.recovery_manager.query_routing_state()
        self.update_all_routing_tables(routing_tables, Rlfas, False)
        self.t = threading.Thread(target=self.__check_changed, args=(), daemon=True)
        self.t.start()
