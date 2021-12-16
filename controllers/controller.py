import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from multiprocessing.pool import ThreadPool
from recovery import Fast_Recovery_Manager as FRM
from heartbeat import HeartBeatGenerator as HBG
from queuelengthestimator import QueueLengthEstimator
from routingtablemanager import RoutingTableManager
from rexfordutils import RexfordUtils
import json
from scapy.all import *
import threading
import sys
import time
import way_point_reader as wpr
from errors import *

# define here table names
TABLES = ["ipv4_forward", "escmp_group_to_nhop", "final_forward"]


class Controller(object):
    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.topo = load_topo("topology.json")
        FRM.add_delay_weight(self.topo)
        self.controllers = {}
        self.failed_links = set()  # current set of failed links
        path = sys.argv[0]
        self.base_path = "/".join(path.split("/")[:-1])
        self.global_interface_lock = threading.Lock()
        self.recovery_manager = FRM(
            self.topo, self.base_path + "/configs/link_failure_map_generated.json"
        )
        # Settings:
        self.settings = self.read_settings(self.base_path + "/configs/settings.json")
        self.hb_manager = HBG(self.settings["heartbeat_freq"], self.topo)
        self.qle = QueueLengthEstimator(
            self.settings["queue_len_estimator_sample_freq"],
            self.controllers,
            self.global_interface_lock,
        )
        self.rt_manager = RoutingTableManager(
            self.settings["rt_manager_freq"],
            self.controllers,
            self.topo,
            self.recovery_manager,
            self.global_interface_lock,
        )

        # self.workers = ThreadPool(16) # One worker for each thread
        self.init()

    def read_settings(self, settings_filename):
        with open(settings_filename, "r") as f:
            return json.load(f)

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()

    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]

    def get_port_and_mac_of_host(self, switch_name):
        """Gets the port through which switch connects to host and host mac"""
        host_name = switch_name + "_h0"
        host_port = self.topo.node_to_node_port_num(switch_name, host_name)
        host_mac = self.topo.node_to_node_mac(host_name, switch_name)
        return str(host_port), host_mac

    def configure_host_port(self, p4switch):
        """Configure host port value in the p4 parser and adds table entry for reconstructing packets"""
        host_port, host_mac = self.get_port_and_mac_of_host(p4switch)
        cont = self.controllers[p4switch]
        cont.pvs_add("MyParser.host_port", host_port)
        cont.table_add(
            "host_port_to_mac",
            action_name="reconstruct_packet",
            match_keys=[host_port],
            action_params=[host_mac],
        )
        cont.register_write("host_port_reg", 0, int(host_port))

    def configure_host_address(self, p4switch):
        """Saves the host rexford address into register in p4"""
        host_name = p4switch + "_h0"
        host_addr = RexfordUtils.get_rexford_addr(self.topo, host_name)
        cont = self.controllers[p4switch]
        cont.register_write("host_address_reg", 0, int(host_addr))

    def setup_way_points(self, way_point_file_name):
        self.global_interface_lock.acquire()
        wps = wpr.get_way_points(way_point_file_name)
        for src, dst, wp in wps:
            src_switch = RexfordUtils.get_switch_of_host(src)
            dst_addr = RexfordUtils.get_rexford_addr(self.topo, dst)
            wp_addr = RexfordUtils.get_rexford_addr(self.topo, wp + "_h0")
            print("Waypoint")
            print(str(dst_addr))
            print(str(wp_addr))
            self.controllers[src_switch].table_add(
                "udp_waypoint",
                action_name="set_waypoint",
                match_keys=[dst_addr],
                action_params=[wp_addr],
            )
        self.global_interface_lock.release()

    def setup_meters(self):
        committed_queue_length = self.settings["committed_queue_length"]
        committed_rate = self.settings["committed_rate"]

        peak_queue_length = self.settings["peak_queue_length"]
        peak_rate = self.settings["peak_rate"]

        packet_size = self.settings["packet_size"]

        self.global_interface_lock.acquire()
        for controller in self.controllers.values():
            cir = committed_rate  # committed information rate [bytes/s]
            cbs = (
                committed_queue_length * packet_size
            )  # committed burst size       [bytes]
            pir = peak_rate  # peak information rate     [bytes/s]
            pbs = peak_queue_length * packet_size  # peak burst size           [bytes]
            yellow = (cir, cbs)
            red = (pir, pbs)
            controller.meter_array_set_rates("port_congestion_meter", [yellow, red])

            # Color Yellow does not matter for the following meters since only the colors red
            # is used for the queue length estimation. For more information look at egress.p4
            yellow = (cir, cbs)
            red = (peak_rate, 5 * packet_size)
            controller.meter_array_set_rates("queue_len_5", [yellow, red])

            red = (peak_rate, 10 * packet_size)
            controller.meter_array_set_rates("queue_len_10", [yellow, red])

            red = (peak_rate, 15 * packet_size)
            controller.meter_array_set_rates("queue_len_15", [yellow, red])

            red = (peak_rate, 20 * packet_size)
            controller.meter_array_set_rates("queue_len_20", [yellow, red])

            red = (peak_rate, 25 * packet_size)
            controller.meter_array_set_rates("queue_len_25", [yellow, red])

            red = (peak_rate, 30 * packet_size)
            controller.meter_array_set_rates("queue_len_30", [yellow, red])

            red = (peak_rate, 35 * packet_size)
            controller.meter_array_set_rates("queue_len_35", [yellow, red])

            red = (peak_rate, 40 * packet_size)
            controller.meter_array_set_rates("queue_len_40", [yellow, red])
        self.global_interface_lock.release()

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def set_mirroring_sessions(self):
        """Set mirroring sessions for cloned packets"""
        self.global_interface_lock.acquire()
        for p4switch in self.topo.get_p4switches():
            cpu_port = self.topo.get_cpu_port_index(p4switch)
            self.controllers[p4switch].mirroring_add(100, cpu_port)
        self.global_interface_lock.release()

    def process_packet(self, pkt):
        """Processes received packets to detect failure notifications"""
        interface = pkt.sniffed_on
        switch_name = interface.split("-")[0]
        pkt_raw = raw(pkt)
        pkt_bin = format(int.from_bytes(pkt_raw, byteorder="big"), "0112b")
        eth_type = int(pkt_bin[-16:], 2)
        if eth_type == 4661: #0x1235
            port = int(pkt_bin[0:9], 2)
            failed = int(pkt_bin[10], 2)
            recovered = int(pkt_bin[11], 2)
            neighbor = self.topo.port_to_node(switch_name, port)
            failed_link = tuple(sorted([switch_name, neighbor]))
            if failed == 1:
                print(f"[!] Notification for link failure {failed_link} received")
                self.rt_manager.fail_link(failed_link)
            if recovered == 1:
                print(f"[!] Notification for link restored {failed_link} received")
                self.rt_manager.restore_link(failed_link)

    def run_cpu_port_loop(self):
        """Sniffs traffic coming from switches"""
        cpu_interfaces = [
            str(self.topo.get_ctl_cpu_intf(sw_name)).replace("eth1", "eth0")
            for sw_name in self.controllers
        ]
        sniff(
            iface=cpu_interfaces, filter="ether proto 0x1235", prn=self.process_packet
        )

    def run(self):
        """Run function"""
        # Setup tables and varsets.
        for p4switch in self.topo.get_p4switches():
            self.configure_host_port(p4switch)
            self.configure_host_address(p4switch)
        self.setup_way_points(self.base_path + "/configs/full.slas")
        self.setup_meters()
        self.rt_manager.run()

        self.qle.run()
        # start thread for listening heartbeats
        self.set_mirroring_sessions()
        t = threading.Thread(target=self.run_cpu_port_loop, daemon=True)
        t.start()
        # start heartbeat traffic
        self.hb_manager.run()
        time.sleep(1000)

    def main(self):
        """Main function"""
        self.run()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-traffic",
        help="Path to scenario.base-traffic",
        type=str,
        required=False,
        default="",
    )
    parser.add_argument(
        "--slas", help="Path to scenario.slas", type=str, required=False, default=""
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    Controller(args.base_traffic, args.slas).main()
