class RexfordUtils(object):
    @staticmethod
    def get_switch_of_host(host_name):
        return host_name.split("_")[0]

    @staticmethod
    def get_host_of_switch(sw_name):
        return sw_name + "_h0"

    @staticmethod
    def get_rexford_addr(topo, host_name):
        switch_name = RexfordUtils.get_switch_of_host(host_name)
        ipstr = topo.node_to_node_interface_ip(host_name, switch_name)
        # Ipaddress has format: 10.0.rexfordAddr.1/24
        # They enumerate from 1 to 16.
        # Since our address is 4 bit "16" should be mapped to "0".
        addr = ipstr.split(".")[2]
        if addr == "16":
            addr = "0"
        return addr
