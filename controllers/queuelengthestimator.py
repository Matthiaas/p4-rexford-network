import time
import threading
import numpy as np
import time

max_ports = 11


def current_sec_time():
    return time.time()


def estimate_queue_len_thread(cont, time_interval, global_interface_lock):
    """
    This gives an estimate of the current queue length for each port for a given controller.
    The result is then written into the counter_based_estimated_queue_len register which then can be accessed
    by the p4 code.
    The calculation is based on a counter that is increased in the egresspipeline for every
    packet.

    Args:
        cont: controller
        time_interval: float in seconds on how often to re-estimate the queue length.
    """
    last_counts = np.zeros(max_ports)
    last_timestamp = np.full(max_ports, current_sec_time())
    est_queue_len = np.zeros(max_ports)
    # This is a rough estimate on the max queue length
    # assuming there are not a lot of heartbeats or similar in there.
    max_queue_len = 1500 * 100
    while True:
        global_interface_lock.acquire()
        for i in range(max_ports):
            try:
                curr_time = current_sec_time()
                newbyte_count, _ = cont.counter_read("port_bytes_out", i)
                time_passed = curr_time - last_timestamp[i]
                last_timestamp[i] = curr_time
                added = newbyte_count - last_counts[i]
                last_counts[i] = newbyte_count
                lost = 1250000 * time_passed
                est_queue_len[i] = min(
                    max(0, est_queue_len[i] + added - lost), max_queue_len
                )
                cont.register_write(
                    "counter_based_estimated_queue_len", i, int(est_queue_len[i] / 1500)
                )
            except:
                # This should not happen, but just to be sure. It does not matter if it fails one time.
                continue
        global_interface_lock.release()
        time.sleep(time_interval)


class QueueLengthEstimator(object):
    """Queue Length Estimator."""

    """
        Estimates the out quelength for every port on every switch.
    """

    def __init__(self, time_interval, controllers, global_interface_lock):
        """Initializes the topology and data structures."""
        self.time_interval = time_interval
        self.controllers = controllers
        self.global_interface_lock = global_interface_lock
        self.traffic_threads = []

    def run(self):
        """Main runner"""
        # for each switch
        for _, cont in self.controllers.items():
            t = threading.Thread(
                target=estimate_queue_len_thread,
                args=(cont, self.time_interval, self.global_interface_lock),
                daemon=True,
            )
            t.start()
            # save all threads (currently not used)
            self.traffic_threads.append(t)
