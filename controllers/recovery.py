""" Define classes and methods for links failure recovery here"""
from networkx.algorithms import all_pairs_dijkstra
from scapy.all import *

class Fast_Recovery_Manager(object):

    def __init__(self, links_fail_file):
        
