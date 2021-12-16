import time
import threading
from multiprocessing.pool import ThreadPool
from recovery import Fast_Recovery_Manager as FRM
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from rexfordutils import RexfordUtils
import numpy as np
import time
import failure_generator


class RoutingTableManager(object):
    def __init__(
        self, time_interval, controllers, topo, recovery_manager, global_interface_lock
    ):
        """Initializes the topology and data structures."""
        self.time_interval = time_interval
        self.controllers = controllers
        self.topo = topo
        self.recovery_manager = recovery_manager
        self.workers = ThreadPool(16)  # One worker for each switch
        self.has_changed = False
        self.failed_links = set()
        self.failures_of_current_rt = set()
        self.lock = threading.Lock()
        self.global_interface_lock = global_interface_lock
        self.t = None
        self.non_bridges = failure_generator.get_non_bridges(self.topo)

    def fail_link(self, failed_link):
        """
        Given a failed_link (notified from data plane), check if it is a valid
        entry to failures pool.
        Args: tuple(str,str)
        """
        self.lock.acquire()
        if failed_link not in self.failed_links and failed_link in self.non_bridges:
            self.failed_links.add(failed_link)
            print(f"Failure: updated failed links: {self.failed_links}")
            self.has_changed = True
        self.lock.release()

    def restore_link(self, restored_link):
        """
        Given a failed_link (notified from data plane), check if it is in failed 
        pool and removes it.
        Args: tuple(str,str)
        """
        self.lock.acquire()
        if restored_link in self.failed_links:
            self.failed_links.remove(restored_link)
            print(f"Recovery: updated failed links: {self.failed_links}")
            self.has_changed = True
        self.lock.release()

    def __check_changed(self):
        """
        To be called in a thread. Periodically checks if there has been a change 
        in the failure pool and loads/recompute routing tables.
        """
        while True:
            self.lock.acquire()
            if self.has_changed:
                print(
                    "Change found. Getting routing tables for failure: ",
                    self.failed_links,
                )
                self.has_changed = False
                routing_tables, Rlfas = self.recovery_manager.query_routing_state(
                    self.failed_links
                )
                self.lock.release()
                print(f"Got routing table and rlfas. Loading...")
                self.global_interface_lock.acquire()
                self.update_all_routing_tables(routing_tables, Rlfas, False)
                self.global_interface_lock.release()
                print(f"Loading completed.")
            else:
                self.lock.release()
                time.sleep(self.time_interval)

    def update_all_routing_tables(self, routing_tables, Rlfas, init=False):
        """
        Updates all the routing tables by loading into switches tables.
        Args:
            routing_tables:

        """
        # Helper
        def update_single_routing_table(p4switch):
            cont = self.controllers[p4switch]
            rt = routing_tables[p4switch]
            ecmp_group_id = 0

            print("Loading routing tables for ", p4switch)

            for host_name, routs in rt.items():
                host_addr = RexfordUtils.get_rexford_addr(self.topo, host_name)

                nexthops = routs["nexthops"]
                scmp_nexthops = routs.get("scmps", [])

                nexthopports = [
                    str(self.topo.node_to_node_port_num(p4switch, nexthop))
                    for nexthop in nexthops
                ]
                scmp_nexthopports = [
                    str(self.topo.node_to_node_port_num(p4switch, nexthop))
                    for nexthop in scmp_nexthops
                ]

                nexthop_escmp_ports = nexthopports + [
                    p for p in scmp_nexthopports if p not in nexthopports
                ]

                lfa = routs["lfa"]
                lfa_ports = None
                # Normalize the lfa list to be at most of len 2.
                if len(lfa) > 0:
                    lfa_ports = [
                        str(self.topo.node_to_node_port_num(p4switch, l)) for l in lfa
                    ]
                    if len(lfa_ports) == 1:
                        lfa_ports.append(str(0))
                else:
                    lfa_ports = [str(0), str(0)]

                print("Adding nexthops,lfas and rlfas:")
                print([nexthop_escmp_ports, lfa_ports])

                if len(nexthop_escmp_ports) == 1:
                    # We only need to set the nexthop and not any ESCP stuff.
                    self.__set_next_hop_lfas(
                        cont,
                        "ipv4_forward",
                        match_keys=[host_addr],
                        next_port=nexthop_escmp_ports[0],
                        lfa_ports=lfa_ports,
                        init=init,
                    )
                else:
                    self.__modify_or_add(
                        cont=cont,
                        table_name="ipv4_forward",
                        action_name="escmp_group",
                        match_keys=[host_addr],
                        action_params=[
                            str(ecmp_group_id),
                            str(len(nexthopports)),
                            str(len(nexthop_escmp_ports)),
                        ],
                    )
                    port_hash = 0
                    for nextport in nexthop_escmp_ports:
                        self.__set_next_hop_lfas(
                            cont,
                            "escmp_group_to_nhop",
                            match_keys=[str(ecmp_group_id), str(port_hash)],
                            next_port=nextport,
                            lfa_ports=lfa_ports,
                            init=init,
                        )
                        port_hash = port_hash + 1
                    ecmp_group_id = ecmp_group_id + 1

            # set Rlfas
            for neigh, rlfa in Rlfas[p4switch].items():
                # Rlfa protects the link sw--neigh
                rlfa_port = 0
                rlfa_host = "0"
                link_port = self.topo.node_to_node_port_num(p4switch, neigh)
                if rlfa != "":
                    # This is the port to protect
                    # Get nexthop for getting to the rlfa.
                    rlfa_host = RexfordUtils.get_rexford_addr(
                        self.topo, RexfordUtils.get_host_of_switch(rlfa)
                    )
                    rlfa_host_nexthops = rt[RexfordUtils.get_host_of_switch(rlfa)][
                        "nexthops"
                    ]
                    for nh in rlfa_host_nexthops:
                        # Clearly has to be different than the neighbor for 
                        # which the link fails.
                        if nh != neigh:
                            rlfa_port = self.topo.node_to_node_port_num(p4switch, nh)
                            break
                    print(
                        f"Adding Rlfa link {p4switch}--{neigh} rlfa: {rlfa} port: {rlfa_port}"
                    )
                    self.__modify_or_add(
                        cont=cont,
                        table_name="final_forward",
                        action_name="set_backup_routs",
                        match_keys=[str(link_port)],
                        action_params=[rlfa_host, str(rlfa_port)],
                    )
                else:
                    self.__modify_or_add(
                        cont=cont,
                        table_name="final_forward",
                        action_name="set_backup_routs_no_rlfa",
                        match_keys=[str(link_port)],
                        action_params=[],
                    )

            print("Loaded routing tables for ", p4switch)

        self.workers.map(update_single_routing_table, self.topo.get_p4switches())

    def __modify_or_add(
        self, cont, table_name, action_name, match_keys, action_params=[], init=False
    ):

        entry_handle = None
        if not init:
            # No need to try to update the entry when we init.
            entry_handle = cont.get_handle_from_match(table_name, match_keys)
        if entry_handle is not None:
            cont.table_modify(table_name, action_name, entry_handle, action_params)
        else:
            cont.table_add(table_name, action_name, match_keys, action_params)

    # Maps refxord addr or ecmp group to nexthop port and lfa if possible.
    def __set_next_hop_lfas(
        self, cont, table_name, match_keys, next_port, lfa_ports, init=False
    ):
        lfa_port_1 = lfa_ports[0]
        lfa_port_2 = lfa_ports[1]
        self.__modify_or_add(
            cont=cont,
            table_name=table_name,
            action_name="set_nhop_lfas",
            match_keys=match_keys,
            action_params=[next_port, lfa_port_1, lfa_port_2],
            init=init,
        )

    def run(self):
        """Main runner"""
        # Load default table.
        routing_tables, Rlfas = self.recovery_manager.query_routing_state()
        self.update_all_routing_tables(routing_tables, Rlfas, False)
        self.t = threading.Thread(target=self.__check_changed, args=(), daemon=True)
        self.t.start()
