"""Heartbeat generator that periodically sends probes to all switches. One probe
per port connected to a switch. 
"""

#!/usr/bin/env python3

import os
import socket
import struct
import time
import threading
import codecs

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


def build_packet(src_mac, dst_mac, heartbeat_port):
    """Builds raw heart beat packet to send to switches"""
    heartbeat_port = format(heartbeat_port, '09b')
    from_cp = '1'
    pad = '0' * 86
    eth = format(0x1234, '016b')
    pkt = heartbeat_port + from_cp + pad + eth
    pkt = int(pkt, 2).to_bytes(14, byteorder='big')
    heartbeat = struct.pack("!14s", pkt)
    return heartbeat

def send_thread(intf_name, neighs_src_dst_port, time_interval):
    #intf_name = tup[0]
    #neighs_src_dst_port = tup[1]
    #time_interval = tup[2]
    """Periodically sends one packet to `intf_name` every `time_interval`"""
    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    send_socket.bind((intf_name, 0))
    while True:
        for src_mac, dst_mac, port in neighs_src_dst_port:
            # build packet
            pkt = build_packet(src_mac, dst_mac, port)
            send_socket.send(pkt)
        time.sleep(time_interval)

class HeartBeatGenerator(object):
    """Heart beat Generator."""

    def __init__(self, time_interval, topo):
        """Initializes the topology and data structures."""

        self.topo = topo
        self.traffic_threads = []
        self.time_interval = time_interval

    def run(self):
        """Main runner"""
        all_neighs = []
        # for each switch
        for switch in self.topo.get_p4switches():
            # gets the ethernet interface name of the cpu port of a given switch.
            # this can be used to either receive from or send packets to the switch. 
            cpu_intf = self.topo.get_cpu_port_intf(switch)
            neighs_src_dst_port = []
            # get all direct hosts and add direct entry
            for neighbor_switch in self.topo.get_p4switches_connected_to(switch):
                # get port to specific neighbor
                sw_port = self.topo.node_to_node_port_num(switch, neighbor_switch)
                src_mac = self.topo.node_to_node_mac(switch, neighbor_switch)
                dst_mac = self.topo.node_to_node_mac(neighbor_switch, switch)
                neighs_src_dst_port.append((src_mac, dst_mac, sw_port))
                #if neighbor_switch == "PAR":
                #    print(switch)
            all_neighs.append(neighs_src_dst_port)
        
        args = [(self.topo.get_cpu_port_intf(switch), all_neighs[i], self.time_interval) for i,switch in enumerate(self.topo.get_p4switches())]
        for i in range(0,len(args)):
            # each thread is responsible for sending heartbeat from switch to ALL its neighs (~ N.switch threads)
            t = threading.Thread(target=send_thread, args=(args[i]), daemon=True)
            t.start()
            # save all threads (currently not used)
            self.traffic_threads.append(t)
        #with Pool(16) as p:
        #    args = [(self.topo.get_cpu_port_intf(switch), all_neighs[i], self.time_interval) for i,switch in enumerate(self.topo.get_p4switches())]
        #    p.imap_unordered(send_thread, args)