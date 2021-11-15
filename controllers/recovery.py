""" Define classes and methods for links failure recovery here"""
from networkx.algorithms import all_pairs_dijkstra
from scapy.all import *
import json
import os

from errors import *

def load_link_fail_map(links_fail_file):
    with open(links_fail_file, 'r') as f:
        data = json.load(f)
        return data["map"]

class Fast_Recovery_Manager(object):

    def __init__(self, links_fail_file: str):
        
        if not os.path.exists(links_fail_file):
            print("[!] link_fail_map not found")
            raise FileNotFoundError()

        fail_map = load_link_fail_map(links_fail_file)
        print(fail_map[0]["routing_tbl"]["switch1"]["host1"])

recovery = Fast_Recovery_Manager('example_link_failure_map.json')
