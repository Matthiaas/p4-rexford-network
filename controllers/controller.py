import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from recovery import Fast_Recovery_Manager as FRM
from heartbeat import HeartBeatGenerator as HBG
from queulengthestimator import QueueLengthEstimator as QLE
import json
from scapy.all import *
import pathlib
import sys
import os
import way_point_reader as wpr
from errors import *

#define here table names
TABLES = ["ipv4_forward", "escmp_group_to_nhop", "final_forward"]

class Controller(object):

    def __init__(self, base_traffic, slas):
        
        self.base_traffic_file = base_traffic
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.rexford_addr_lookup = {}
        self.failed_links = set() #current set of failed links
        path = sys.argv[0]
        self.base_path  = "/".join(path.split("/")[:-1])
        self.recovery_manager = FRM(
            self.topo, self.base_path + "/configs/link_failure_map_generated.json")
        # Settings:
        self.settings = self.read_settings(self.base_path + "/configs/settings.json")
        self.hb_manager = HBG(self.settings["heartbeat_freq"], self.topo)
        self.qle = QLE(self.settings["queue_len_estimator_sample_freq"], self.controllers)
        self.init()


    def read_settings(self, settings_filename):
         with open(settings_filename, 'r') as f:
            return json.load(f)


    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()


    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]


    def get_port_and_mac_of_host(self, switch_name):
        host_name = switch_name + "_h0"
        host_port = self.topo.node_to_node_port_num(switch_name, host_name)
        host_mac = self.topo.node_to_node_mac(host_name, switch_name)
        return str(host_port), host_mac


    def get_switch_of_host(self, host_name):
        return host_name.split("_")[0]


    def get_host_of_switch(self, sw_name):
        return sw_name+"_h0"


    def get_rexford_addr(self, host_name):
        switch_name = self.get_switch_of_host(host_name)
        ipstr = self.topo.node_to_node_interface_ip(host_name, switch_name)
        # Ipaddress has format: 10.0.rexfordAddr.1/24
        # They enumerate from 1 to 16. 
        # Since our address is 4 bit "16" should be mapped to "0".
        addr = ipstr.split(".")[2]
        if addr == "16":
            # TODO: This is an awfull hack. We should either use tables or use 5 bit as adresses or so.
            # See switch.p4
            addr = "0"
        self.rexford_addr_lookup[int(addr)] = host_name
        return addr


    def configure_host_port(self, p4switch):
        host_port, host_mac = self.get_port_and_mac_of_host(p4switch)
        cont = self.controllers[p4switch]
        cont.pvs_add("MyParser.host_port", host_port)
        cont.table_add(
            "host_port_to_mac", action_name="reconstruct_packet", 
            match_keys=[host_port], action_params=[host_mac])
        cont.register_write("host_port_reg", 0, int(host_port))


    def configure_host_address(self, p4switch):
        host_name = p4switch + "_h0"
        host_addr = self.get_rexford_addr(host_name)
        cont = self.controllers[p4switch]
        cont.register_write("host_address_reg", 0, int(host_addr))


    def setup_way_points(self, way_point_file_name):
        wps = wpr.get_way_points(way_point_file_name)
        for src, dst, wp in wps:
            src_switch = self.get_switch_of_host(src)
            dst_addr = self.get_rexford_addr(dst)
            wp_addr = self.get_rexford_addr(wp + "_h0")
            print("Waypoint")
            print(str(dst_addr))
            print(str(wp_addr))
            self.controllers[src_switch].table_add(
                "udp_waypoint", action_name="set_waypoint", 
                match_keys=[dst_addr], action_params=[wp_addr])
    

    def load_routing_table(self, routing_tables, Rlfas):
        """Loads routing tables into switch"""
        ###########
        #         #
        # HELPERS #
        #         #
        ###########

        # maps refxord addr or ecmp group to nexthop port and lfa if possible
        def add_set_next_hop(table_name, match_keys, next_port, lfa_port=None):
            if lfa_port:
                self.controllers[p4switch].table_add(
                        table_name, action_name="set_nhop_and_lfa", 
                            match_keys=match_keys, action_params=[next_port, lfa_port])
            else: 
                self.controllers[p4switch].table_add(
                        table_name, action_name="set_nhop", 
                            match_keys=match_keys, action_params=[next_port])

        def clear_tables(controller, table_names):
            for table_name in table_names:
                controller.table_clear(table_name)
        
        ############
        #          #
        #   CODE   #
        #          #
        ############
        for p4switch in self.topo.get_p4switches():
            #reset default state of tables
            clear_tables(self.controllers[p4switch], TABLES)
            
            rt = routing_tables[p4switch]
            ecmp_group_id = 0
            for host_name, routs in rt.items():
                host_addr = self.get_rexford_addr(host_name)               
                nexthopports = [ 
                    str(self.topo.node_to_node_port_num(p4switch, nexthop)) 
                        for nexthop in routs["nexthops"]]

                lfa = routs["lfa"]
                lfa_port = None
                if lfa != "":
                    lfa_port = str(self.topo.node_to_node_port_num(p4switch, lfa))                 
                
                print("Adding nexthops and lfa:")
                print([nexthopports, lfa_port])
            
                if len(nexthopports) == 1:
                    add_set_next_hop("ipv4_forward", 
                            match_keys=[host_addr], 
                            next_port=nexthopports[0], 
                            lfa_port=lfa_port)
                else:
                    self.controllers[p4switch].table_add(
                            "ipv4_forward", 
                            action_name="escmp_group", 
                            match_keys=[host_addr], action_params=[str(ecmp_group_id), str(len(nexthopports)), str(len(nexthopports))])
                    port_hash = 0
                    for nextport in nexthopports:
                        # Why are we setting lfa if ecmp?
                        add_set_next_hop("escmp_group_to_nhop", 
                            match_keys=[str(ecmp_group_id), str(port_hash)], 
                            next_port=nextport, 
                            lfa_port=lfa_port)
                        port_hash = port_hash + 1 
                    ecmp_group_id = ecmp_group_id + 1
                
            #set Rlfas
            for neigh, rlfa in Rlfas[p4switch].items():
                if rlfa != "":
                    link_port = self.topo.node_to_node_port_num(p4switch, neigh)
                    #get nexthop for getting to the rlfa
                    rlfa_host = self.get_rexford_addr(self.get_host_of_switch(rlfa))
                    rlfa_host_nexthops = rt[self.get_host_of_switch(rlfa)]["nexthops"]
                    rlfa_port = 0
                    for nh in rlfa_host_nexthops:
                        if nh != neigh:
                            rlfa_port = self.topo.node_to_node_port_num(p4switch, nh)
                    print(f"Adding Rlfa link {p4switch}--{neigh} rlfa: {rlfa} port: {rlfa_port}")
                    self.controllers[p4switch].table_add(\
                            table_name="final_forward",
                            action_name="set_nexthop_lfa_rlfa",
                            match_keys=[str(link_port)],
                            action_params=[rlfa_host, str(rlfa_port)])

                
    def setup_meters(self):
        commited_queue_length = self.settings["commited_queue_length"]
        commited_rate = self.settings["commited_rate"]

        peak_queue_length = self.settings["peak_queue_length"]
        peak_rate = self.settings["peak_rate"]

        packet_size = self.settings["packet_size"]

        for controller in self.controllers.values():
            cir =  commited_rate                         # commited information rate [bytes/s]
            cbs =  commited_queue_length * packet_size   # commited burst size       [bytes]
            pir =  peak_rate                             # peak information rate     [bytes/s]
            pbs =  peak_queue_length * packet_size       # peak burst size           [bytes]
            yellow = (cir, cbs)
            red = (pir, pbs)
            controller.meter_array_set_rates("port_congestion_meter", [yellow, red])


    def connect_to_switches(self):
        """Connects to switches"""
        
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)


    def set_mirroring_sessions(self):
        """Set mirroring sessions for cloned packets"""
        for p4switch in self.topo.get_p4switches():
            cpu_port = self.topo.get_cpu_port_index(p4switch)
            self.controllers[p4switch].mirroring_add(100, cpu_port)

    def process_packet(self, pkt):
        """Processes received packets to detect failure notifications"""

        interface = pkt.sniffed_on
        switch_name = interface.split("-")[0]
        pkt_raw = raw(pkt)
        pkt_bin = format(int.from_bytes(pkt, byteorder='big'), '0112b')
        eth_type = int(pkt_bin[-16:], 2)
        if eth_type == 4660:
            port = int(pkt_bin[0:9],2)
            failed = int(pkt_bin[10],2)
            recovered = int(pkt_bin[11],2)
            neighbor = self.topo.port_to_node(switch_name, port)
            failed_link = tuple(sorted([switch_name, neighbor]))
            #print(f"[!] Heartbeat: {switch_name} {neighbor} {port}")
            if failed == 1:
                # get other side of the link using port
                # detect the failed link
                # if it is not a duplicated notification
                print("Notification for link failure {} received", format(failed_link))
                if failed_link not in self.failed_links and failed_link in FRM.get_non_bridges(self.topo):
                    self.failed_links.add(failed_link)
                    routing_tables, Rlfas = self.recovery_manager.query_routing_state(self.failed_links)
                    print(f"Got routing table and rlfas. Loading...")
                    while True:
                        try:
                            self.load_routing_table(routing_tables, Rlfas)
                            break
                        except:
                            time.sleep(0.0001)
                            continue
            if recovered == 1:
                print("Notification for link restored {} received", format(failed_link))
                if failed_link in self.failed_links:
                    self.failed_links.remove(failed_link)
                    routing_tables, Rlfas = self.recovery_manager.query_routing_state(self.failed_links)
                    print(f"Got routing table and rlfas. Loading...")
                    while True:
                        try:
                            self.load_routing_table(routing_tables, Rlfas)
                            break
                        except:
                            time.sleep(0.0001)
                            continue
                #else:
                #    raise FailureNotFound()

    def run_cpu_port_loop(self):
        """Sniffs traffic coming from switches"""
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        print(cpu_interfaces)
        sniff(iface=cpu_interfaces, prn=self.process_packet)

    def run(self):
        """Run function"""
        # Setup tables and varsets.
        for p4switch in self.topo.get_p4switches():
            self.configure_host_port(p4switch)
            self.configure_host_address(p4switch)
        self.setup_way_points(self.base_path + "/configs/full.slas")
        routing_tables, Rlfas = self.recovery_manager.query_routing_state()
        self.load_routing_table(routing_tables, Rlfas)
        self.setup_meters()

        # Configure mirroring session to cpu port for failure notifications
        self.set_mirroring_sessions()
        self.qle.run()
        #start heartbeat traffic
        self.hb_manager.run()
        self.run_cpu_port_loop()
        time.sleep(1000000)


    def main(self):
        """Main function"""
        self.run()



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic',
    type=str, required=False, default='')
    parser.add_argument('--slas', help='Path to scenario.slas',
    type=str, required=False, default='') 
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    Controller(args.base_traffic, args.slas).main()
