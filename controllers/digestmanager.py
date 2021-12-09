import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from multiprocessing.pool import ThreadPool


class DigestManager(object):

    def __init__(self, topo, switches, controllers, rt_manager):
        self.topo = topo
        self.switches = switches
        self.controllers = controllers
        self.workers = ThreadPool(16) # One worker for each switch   
        self.rt_manager = rt_manager


    def __unpack_digest(self, msg, num_samples):
        print(f"Unpacking {num_samples} samples")
        digest = []
        starting_index = 32
        fields_bytes = 3 #defined each field (they are 3) in digest_t as 8 bits
        for sample in range(num_samples):
            print(f"Raw msg: {msg[starting_index:starting_index+fields_bytes]}")
            port, failed, recovered = struct.unpack("!BBB", msg[starting_index:starting_index+fields_bytes])
            print(f"Sample:: {port} f:{failed} r:{recovered}")
            starting_index += fields_bytes
            digest.append((port,failed,recovered))
        return digest


    def __recv_msg_digest(self, msg, switch, controller):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        print(f"Reading digest...")
        digest = self.__unpack_digest(msg, num)
        #ack
        controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)
        
        failed_links = set()
        recovered_links = set()
        
        print("Notification::", digest)
        
        for notification in digest:
            port = notification[0]
            failed = notification[1]
            recovered = notification[2]
            
            neighbor = self.topo.port_to_node(switch, port)
            failed_link = tuple(sorted([switch, neighbor]))
            
            if failed == 1 and failed_link not in failed_links:
                print("Notification for link failure {} received", format(failed_link))
                failed_links.add(failed_link)
            
            if recovered == 1:
                print("Notification for link restored {} received", format(failed_link))
                
                if failed_link in failed_links:
                    failed_links.remove(failed_link)
                else:
                    recovered_links.add(failed_link)
        
        for failed_link in failed_links:
            self.rt_manager.fail_link(failed_link)
        
        for recovered_link in recovered_links:
            self.rt_manager.restore_link(recovered_link)


    def __run_digest_loop(self, arg):
        switch = arg[0]
        controller = arg[1]
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = controller.client.bm_mgmt_get_info().notifications_socket
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
        print(f"Thread started listening for {switch}")
        while True:
            msg = sub.recv()
            print(f"{switch} sent a notification!")
            self.__recv_msg_digest(msg, switch, controller)
    

    def run(self):
        args = zip(self.switches, self.controllers)
        print(f"Digest Manager started!")
        self.workers.imap(self.__run_digest_loop, args)
