"""Heartbeat generator that periodically sends probes to all switches. One probe
per port connected to a switch. 
"""

#!/usr/bin/env python3


import socket
import struct
import time
import threading
from multiprocessing.pool import ThreadPool

class HeartBeatGenerator(object):
    """Heart beat Generator."""

    def __init__(self, time_interval, topo):
        """Initializes the topology and data structures."""

        self.topo = topo
        self.time_interval = time_interval
        self.workers = ThreadPool(16)


    def __build_packet(self, heartbeat_port):
        """Builds raw heart beat packet to send to switches"""
        heartbeat_port = format(heartbeat_port, '09b')
        from_cp = '1'
        pad = '0' * 86
        eth = format(0x1234, '016b')
        pkt = heartbeat_port + from_cp + pad + eth
        pkt = int(pkt, 2).to_bytes(14, byteorder='big')
        heartbeat = struct.pack("!14s", pkt)
        return heartbeat


    def __send_thread(self, args):
        intf_name = args[0]
        neighs_ports = args[1]
        time_interval = args[2]
        """Periodically sends one packet to `intf_name` every `time_interval`"""
        print(f"Thread for sending heartbeats to {intf_name} started!")
        send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        send_socket.bind((intf_name, 0))
        while True:
            for port in neighs_ports:
                # build packet
                pkt = self.__build_packet(port)
                send_socket.send(pkt)
            time.sleep(time_interval)

    def run(self):
        """Main runner"""
        print("Running Heartbeat Manager!")
        all_neighs = []
        # for each switch
        for switch in self.topo.get_p4switches():
            neighs_ports = []
            # get all direct switches and add direct entry
            for neighbor_switch in self.topo.get_p4switches_connected_to(switch):
                # get port to specific neighbor
                sw_port = self.topo.node_to_node_port_num(switch, neighbor_switch)
                neighs_ports.append(sw_port)

            all_neighs.append(neighs_ports)
        
        args = [(self.topo.get_ctl_cpu_intf(switch), all_neighs[i], self.time_interval) for i,switch in enumerate(self.topo.get_p4switches())]
        #for i in range(0,len(args)):
        #    # each thread is responsible for sending heartbeat from switch to ALL its neighs (~ N.switch threads)
        #    t = threading.Thread(target=send_thread, args=(args[i]), daemon=True)
        #    t.start()
        #    # save all threads (currently not used)
        #    self.traffic_threads.append(t)

        # each thread is responsible for sending heartbeat from switch to ALL its neighs (~ N.switch threads)
        print("Starting Heartbeat sending threads")
        self.workers.map(self.__send_thread, args)