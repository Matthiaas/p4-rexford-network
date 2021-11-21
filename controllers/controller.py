"""Template of an empty global controller"""
import argparse
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from recovery import Fast_Recovery_Manager as FRM
class Controller(object):

    def __init__(self, base_traffic):
        self.base_traffic_file = base_traffic
        self.topo = load_topo('topology.json')
        self.controllers = {}
        # TODO: Uncomment when it works.
        # self.recovery_manager = FRM(self.topo, 'example_link_failure_map.json') 
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

    def configure_host_port(self, cont, p4switch):
        host_port, host_mac = self.get_port_and_mac_of_host(p4switch)
        print(host_port, host_mac)
        cont.pvs_add("MyParser.host_port", host_port)
        cont.table_add(
            "host_port_to_mac", action_name="reconstruct_packet", 
            match_keys=[host_port], action_params=[host_mac])

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

    def run(self):
        """Run function"""
        # Setup tables and varsets.
        for p4switch in self.topo.get_p4switches():
            self.configure_host_port(self.controllers[p4switch], p4switch)

    def main(self):
        """Main function"""
        self.run()



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic',
                        type=str, required=False, default='')
    return parser.parse_args()

if __name__ == "__main__":
    args = get_args()
    controller = Controller(args.base_traffic)
    controller.main()
