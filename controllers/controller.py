"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from recovery import Fast_Recovery_Manager as FRM
from heartbeat import HeartBeatGenerator as HBG
from queulengthestimator import QueueLengthEstimator as QLE
import json
from scapy.all import *

import way_point_reader as wpr


class Controller(object):

    def __init__(self, base_traffic, slas):
        
        self.base_traffic_file = base_traffic
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.failure_rts = {}
        # TODO: Uncomment when it works.
        # self.recovery_manager = FRM(self.topo, 'example_link_failure_map.json')
        # Settings:
        self.settings = self.read_settings("controllers/configs/settings.json")
        self.hb_manager = HBG(self.settings["heartbeat_freq"], self.topo)
        self.qle = None
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

    def load_routing_table(self, routing_tables):
        for p4switch in self.topo.get_p4switches():
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

                def add_set_next_hop(table_name, match_keys, next_port, lfa_port=None):
                    if lfa_port:
                        self.controllers[p4switch].table_add(
                                table_name, action_name="set_nhop_and_lfa", 
                                    match_keys=match_keys, action_params=[next_port, lfa_port])
                    else: 
                        self.controllers[p4switch].table_add(
                                table_name, action_name="set_nhop", 
                                    match_keys=match_keys, action_params=[next_port])


                if len(nexthopports) == 1:
                    add_set_next_hop("ipv4_forward", 
                            match_keys=[host_addr], 
                            next_port=nexthopports[0], 
                            lfa_port=lfa_port)
                else:
                    self.controllers[p4switch].table_add(
                            "ipv4_forward", 
                            action_name="ecmp_group", 
                            match_keys=[host_addr], action_params=[str(ecmp_group_id), str(len(nexthopports))])
                    port_hash = 0
                    for nextport in nexthopports:
                        add_set_next_hop("ecmp_group_to_nhop", 
                            match_keys=[str(ecmp_group_id), str(port_hash)], 
                            next_port=nextport, 
                            lfa_port=lfa_port)
                        port_hash = port_hash + 1 
                    ecmp_group_id = ecmp_group_id + 1

                
    def setup_routing_lfa(self, config_file):
        with open(config_file, 'r') as f:
            for entry in json.load(f)["map"]:
                failures = frozenset(entry["failures"])
                self.failure_rts[failures] = entry["routing_tbl"]
        self.load_routing_table(self.failure_rts[frozenset()])
                

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

    def process_packet(self, pkt):
        """Processes received packets to detect failure notifications"""

        interface = pkt.sniffed_on
        switch_name = interface.split("-")[0]
        packet = Ether(raw(pkt))
        # check if it is a heartbeat packet
        if packet.type == 0x1234:
            # parse the heartbeat header
            payload = struct.unpack("!H", packet.payload.load)[0]
            failed_flag = (payload & 0x0020) >> 5
            port = (payload & 0xff80) >> 7

            # only if it is a failure notification packet.
            if failed_flag == 1:
                # get port
                port = (payload & 0xff80) >> 7
                # get other side of the link using port
                neighbor = self.topo.port_to_node(switch_name, port)
                # detect the failed link
                failed_link = tuple(sorted([switch_name, neighbor]))
                # if it is not a duplicated notification
                if failed_link not in self.failed_links:
                    print("Notification for link failure {} received", format(failed_link))
                    self.failed_links.add(failed_link)
                    print("Updating for link failure {}".format(self.failed_links))
                    self.failure_notification(list(self.failed_links))

    def run_cpu_port_loop(self):
        """Sniffs traffic coming from switches"""
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        sniff(iface=cpu_interfaces, prn=self.process_packet)

    

    
    def run(self):
        """Run function"""
        # Setup tables and varsets.
        for p4switch in self.topo.get_p4switches():
            self.configure_host_port(p4switch)
            self.configure_host_address(p4switch)
        self.setup_way_points("controllers/configs/full.slas")
        self.setup_routing_lfa("controllers/configs/link_failure_map_generated.json")
        self.setup_meters()
        #start heartbeat traffic
        self.hb_manager.run()
        #
        self.qle = QLE(self.settings["queue_len_estimator_sample_freq"], self.controllers)
        self.qle.run()
        time.sleep(60)


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
