"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from recovery import Fast_Recovery_Manager as FRM
from heartbeat import HeartBeatGenerator as HBG
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
        hb_freq = 0.1 #must be lower than threshold in switch.p4
        self.hb_manager = HBG(hb_freq, self.topo)
        self.init()

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

    def configure_host_address(self, p4switch):
        host_name = p4switch + "_h0"
        host_addr = self.get_rexford_addr(host_name)
        cont = self.controllers[p4switch]
        cont.register_write("host_address", 0, int(host_addr))

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
            
            for host_name, routs in rt.items():
                
                host_addr = self.get_rexford_addr(host_name)
                 # TODO: Use the nexthops for ECMP routing.
                nexthops = routs["nexthops"]
                nexthop = nexthops[0]
                lfa = nexthops[1] if len(nexthops) > 1 else routs["lfa"]
                nexthop_port = str(self.topo.node_to_node_port_num(p4switch, nexthop))
                lfa_port = nexthop_port
                if lfa != nexthop and lfa != "":
                    lfa_port = str(self.topo.node_to_node_port_num(p4switch, lfa))
                self.controllers[p4switch].table_add(
                  "ipv4_forward", action_name="set_nhop", 
                    match_keys=[host_addr], action_params=[nexthop_port])  
                print("routes")
                print([nexthop_port, lfa_port])

    def setup_routing_lfa(self, config_file):
        with open(config_file, 'r') as f:
            for entry in json.load(f)["map"]:
                failures = frozenset(entry["failures"])
                self.failure_rts[failures] = entry["routing_tbl"]
        self.load_routing_table(self.failure_rts[frozenset()])
                

    # Delete this when we have proper routing tabels.
    def setup_test_tables_from_FRA_to_MUC(self):
        self.controllers["FRA"].table_add(
            "ipv4_forward", action_name="set_nhop", 
            match_keys=["6"], action_params=["7"])
        self.controllers["FRA"].table_add(
            "ipv4_forward", action_name="set_nhop", 
            match_keys=["13"], action_params=["4"])
        print("Thirftprot FRA::", self.topo.get_thrift_port("FRA"))
        self.controllers["MUN"].table_add(
            "ipv4_forward", action_name="set_nhop", 
            match_keys=["6"], action_params=["3"])
        self.controllers["MUN"].table_add(
            "ipv4_forward", action_name="set_nhop", 
            match_keys=["13"], action_params=["5"])

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
        #start heartbeat traffic
        self.hb_manager.run()


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
