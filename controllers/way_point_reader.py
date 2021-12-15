from collections import namedtuple
import pandas as pd

Waypoint = namedtuple("Waypoint", "src dst waypoint")


def get_way_points(way_point_file_name):
    df = pd.read_csv(way_point_file_name)
    way_points = df[df["type"] == "wp"]
    res = []
    for index, row in way_points.iterrows():
        res.append(Waypoint(row["src"], row["dst"], row["target"]))
    return res
