
import time
import threading
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import numpy as np
import time

max_ports = 10

def current_sec_time():
    return time.time() 

def estimate_queu_len_thread(name, cont, time_interval):
    last_counts = np.zeros(max_ports)
    last_timestamp = np.full(max_ports, current_sec_time())
    est_queue_len = np.zeros(max_ports)
    # This is a rough estimate on the max queulength 
    # asuming there are not a lot of heartbeats or similar in there.
    max_queu_len = 1500 * 100
    while True:
        for i in range(max_ports):
            curr_time = current_sec_time()
            newbyte_count, _ = cont.counter_read("port_bytes_out", i) 
            time_passed = curr_time - last_timestamp[i]
            last_timestamp[i] = curr_time
            added = newbyte_count - last_counts[i]
            last_counts[i] = newbyte_count
            lost = 1250000 * time_passed 
            est_queue_len[i] = min(max(0,est_queue_len[i] + added - lost), max_queu_len)
            cont.register_write("estimated_queue_len", i, int(est_queue_len[i] / 1500 ))
            #if added > 0:
            #print("estimated_queue_len", name, i, added, lost, est_queue_len[i])
        time.sleep(time_interval)

class QueueLengthEstimator(object):
    """Heart beat Generator."""

    def __init__(self, time_interval, controllers):
        """Initializes the topology and data structures."""

        self.time_interval = time_interval
        self.controllers = controllers
        self.traffic_threads = []
       

    def run(self):
        """Main runner"""
        # for each switch
        for name, cont in self.controllers.items():
            t = threading.Thread(target=estimate_queu_len_thread, args=(name, cont, self.time_interval), daemon=True)
            t.start()
            # save all threads (currently not used)
            self.traffic_threads.append(t)