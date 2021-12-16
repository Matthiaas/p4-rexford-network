from networkx.algorithms.components.connected import is_connected
from p4utils.utils.topology import NetworkGraph as Graph
from typing import List, Set, Tuple
from networkx.algorithms import all_pairs_dijkstra, bridges
import json
from itertools import chain, combinations
import os


def powerset(iterable):
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))


def edge_to_string(e: Tuple[str, str]):
    return "{}-{}".format(e[0], e[1])


def get_non_bridges(g: Graph):
    return [x for x in list(g.edges) if x not in list(bridges(g))]


def __generate_possible_failures_helper(
    g: Graph, found_failure_sets: Set[str], cur_failure_set: List[str]
):
    non_bridges = get_non_bridges(g)
    for e in non_bridges:
        e_string = edge_to_string(e)
        cur_failure_set.append(e_string)
        cur_failure_set.sort()
        cur_failure_set_string = ",".join(cur_failure_set)

        if cur_failure_set_string in found_failure_sets:
            cur_failure_set.remove(e_string)
            continue
        found_failure_sets.add(cur_failure_set_string)

        g_copy = g.copy()
        g_copy.remove_edge(e[0], e[1])
        __generate_possible_failures_helper(g_copy, found_failure_sets, cur_failure_set)
        cur_failure_set.remove(e_string)
    return found_failure_sets

def parse_failures(failures: List[str]) -> List[Tuple[str, str]]:
    """
    Takes failures like ["s1-s2", "s2-s3"] and returns [(s1,s2),(s2,s3)]
    """
    f = []
    for link in failures:
        nodes = link.split("-")
        f.append((nodes[0], nodes[1]))
    return f

def load_failures(all_fails: str) -> List[List[Tuple[str, str]]]:
        """Loads all possible failures from config"""
        all_failures = []
        with open(all_fails, "r") as f:
            data = json.load(f)
            for failures in data["failures"]:
                all_failures.append(parse_failures(failures))
        return all_failures

def generate_possible_failures(g: Graph, failures_opath: str):
    default_edges = [
        ("LON", "MAN"),
        ("LON", "GLO"),
        ("LON", "BRI"),
        ("AMS", "LON"),
        ("FRA", "LON"),
        ("PAR", "LON"),
        ("MAD", "LON"),
        ("LIS", "LON"),
        ("GLO", "BRI"),
        ("PAR", "AMS"),
        ("AMS", "EIN"),
        ("FRA", "AMS"),
        ("FRA", "BER"),
        ("FRA", "MUN"),
        ("FRA", "PAR"),
        ("BER", "MUN"),
        ("PAR", "LIL"),
        ("PAR", "REN"),
        ("PAR", "BAR"),
        ("BAR", "MAD"),
        ("MAD", "POR"),
        ("LIS", "POR"),
    ]
    host_edges = [
        (x, x + "_h0")
        for x in [
            "MAN",
            "GLO",
            "BRI",
            "LON",
            "AMS",
            "EIN",
            "BER",
            "FRA",
            "MUN",
            "LIL",
            "PAR",
            "REN",
            "BAR",
            "MAD",
            "POR",
            "LIS",
        ]
    ]

    nw = g.copy()
    nw.remove_edges_from(host_edges)
    additional_edges = [
        e
        for e in nw.edges
        if e not in default_edges and (e[1], e[0]) not in default_edges
    ]
    nw.remove_edges_from(additional_edges)

    possible_failures_str = __generate_possible_failures_helper(nw, set(), [])
    possible_failures_tmp = [x.split(",") for x in possible_failures_str]

    possible_failures = []
    for x in possible_failures_tmp:
        for ae in powerset(additional_edges):
            edges = [edge_to_string(e) for e in ae]
            possible_failures.append(edges + x)

    with open(failures_opath, "w") as f:
        json.dump({"failures": possible_failures}, f)


def overlap(a_start, a_end, b_start, b_end):
    max_start = max(a_start, b_start)
    min_end = min(a_end, b_end)
    return max_start <= min_end

def merge_failure_scenarios(failure_scenarios: List[Tuple[Set[str], int, int]], new_failure: Tuple[Set[str], int, int]):
    new_scenarios = []
    for fs in failure_scenarios:
        a_failures = fs[0]
        a_start = fs[1]
        a_end = fs[2]
        b_failures = new_failure[0]
        b_start = new_failure[1]
        b_end = new_failure[2]

        n_start = max(a_start, b_start)
        n_end = min(a_end, b_end)

        # print(fs, new_failure, overlap(a_start, a_end, b_start, b_end))

        if overlap(a_start, a_end, b_start, b_end):
            new_scenarios.append((a_failures.union(b_failures), n_start, n_end))

    return failure_scenarios + new_scenarios


def calc_failure_scenarios(failures: List[Tuple[Set[str], int, int]]):
    failure_scenarios_with_times = failures
    for failure in failures:
        failure_scenarios_with_times = merge_failure_scenarios(failure_scenarios_with_times, failure)

    # print("DEBUG1", failure_scenarios_with_times)
    failure_scenarios = set()
    for sc in failure_scenarios_with_times:
        failure_scenarios.add(frozenset(sc[0]))

    # print("DEBUG2", failure_scenarios)
    return failure_scenarios


def generate_most_likely_failures(graph: Graph, failure_in_dir: str, additional_links_ipath: str, failures_opath: str):
    additional_links = {}
    with open(additional_links_ipath, 'r') as file:
        first = True
        for i, line in enumerate(file):
            if first:
                first = False
                continue
            s = line.split(",")
            additional_links["ADDED_" + str(i)] = edge_to_string((s[0].strip(), s[1].strip()))

    all_failures = set()
    for filename in os.listdir(failure_in_dir):
        failures = []
        if not filename.endswith(".failure"):
            continue
        with open(os.path.join(failure_in_dir, filename), 'r') as file:
            first = True
            for line in file:
                if first or not line.strip():
                    first = False
                    continue
                s = line.split(",")
                if s[0].startswith("ADDED_"):
                    link = additional_links[s[0]]
                else:
                    link = edge_to_string((s[0].strip(), s[1].strip()))
                failure = ({link}, int(s[-2]), int(s[-2]) + int(s[-1]))
                failures.append(failure)
        all_failures.update(calc_failure_scenarios(failures))

    possible_failures = [[]]
    for x in all_failures:
        links = list(x)
        links_tuples = [tuple(f.split("-")) for f in links]
        g = graph.copy()
        g.remove_edges_from(links_tuples)
        if not is_connected(g):
            print(links, " disconnects the graph ... ignoring")
            continue

        possible_failures.append(links)

    print(len(possible_failures))
    with open(failures_opath, 'w') as f:
        json.dump({"failures": possible_failures}, f)
