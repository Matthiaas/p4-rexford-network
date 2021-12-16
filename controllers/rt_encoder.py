import recovery

vertex_names = [
    "MAN",
    "MAN_h0",
    "GLO",
    "GLO_h0",
    "BRI",
    "BRI_h0",
    "LON",
    "LON_h0",
    "AMS",
    "AMS_h0",
    "EIN",
    "EIN_h0",
    "BER",
    "BER_h0",
    "FRA",
    "FRA_h0",
    "MUN",
    "MUN_h0",
    "LIL",
    "LIL_h0",
    "PAR",
    "PAR_h0",
    "REN",
    "REN_h0",
    "BAR",
    "BAR_h0",
    "MAD",
    "MAD_h0",
    "POR",
    "POR_h0",
    "LIS",
    "LIS_h0",
]


def encode_edge(e):
    return (int(vertex_names.index(e[0])) << 5) + int(vertex_names.index(e[1]))


def decode_edge(e: int):
    edge = int(e)
    if edge == -1:
        return ""
    f = edge >> 5
    t = edge & (31)
    return (vertex_names[f], vertex_names[t])


def encode_vertex(v: str):
    try:
        return int(vertex_names.index(v))
    except:
        return -1


def decode_vertex(v: int):
    vertex = int(v)  # Oh lord, do I hate python.
    if vertex == -1:
        return ""
    return vertex_names[vertex]


def form_routing_enc(graph, switches, hosts, scmp_threshold, failures=None):
    """
    Forms the routing state for the current failure scenario
    Returns a scenario data structure
    """

    # dijkstra handles removing the failed links here
    costs, shortest_paths = recovery.Fast_Recovery_Manager.dijkstra(graph, failures)
    nexthops = recovery.Fast_Recovery_Manager.compute_nexthops(
        shortest_paths, switches, hosts
    )
    lfas = recovery.Fast_Recovery_Manager.compute_lfas(
        graph, switches, hosts, costs, nexthops
    )
    sim_cost_paths = recovery.Fast_Recovery_Manager.compute_scmps(
        lfas, costs, scmp_threshold
    )
    Rlfas = recovery.Fast_Recovery_Manager.compute_Rlfas(
        graph, switches, costs, nexthops, lfas
    )

    routing_tbl = {}
    for sw in switches:
        routing_tbl[encode_vertex(sw)] = {}
        for host, this_nexthops in nexthops[sw]:
            try:
                lfa = [encode_vertex(l) for l in lfas[sw][host][:2]]
                scmp = [encode_vertex(x) for x in sim_cost_paths[sw][host]]
            except:
                # no lfa
                lfa = []
                scmp = []
            routing_tbl[encode_vertex(sw)][encode_vertex(host)] = {
                "n": [encode_vertex(v) for v in this_nexthops],
                "l": lfa,
                "s": scmp,
            }
    Rlfas_enc = {
        encode_vertex(k): {
            encode_vertex(e_k): encode_vertex(e_v) for e_k, e_v in e.items()
        }
        for k, e in Rlfas.items()
    }
    scenario = {
        "f": [encode_edge(x) for x in failures],
        "t": routing_tbl,
        "R": Rlfas_enc,
    }
    return scenario


def decode_routing_table(rt_enc):
    rt = {}
    try:
        for switch, m in rt_enc.items():
            sw = decode_vertex(switch)
            rt[sw] = {}
            for h, entry in m.items():
                host = decode_vertex(h)
                this_nexthops = [decode_vertex(v) for v in entry["n"]]
                if entry["l"]:
                    lfa = [decode_vertex(l) for l in entry["l"]]
                else:
                    lfa = []
                scmps = [decode_vertex(s) for s in entry["s"]]
                rt[sw][host] = {
                    "nexthops": this_nexthops,
                    "lfa": lfa,
                    "scmps": scmps,
                }
    except KeyError as err:
        print("An Error occurred while decoding the routing table: ", err)
    return rt


def decode_rlfas(rlfas_enc):
    return {
        decode_vertex(k): {
            decode_vertex(e_k): decode_vertex(e_v) for e_k, e_v in e.items()
        }
        for k, e in rlfas_enc.items()
    }
