# Fast Recovery
## TO DO:
1 - Switch from json to pickle
2 - Load states to switch trough controller
3 - Maybe add secondary LFA (maybe isn't worth it, it should be really rare plus it's only transient state)
4 - what about RLFA?
# Load Balancing
## TO DO:
Algo:
- if ecmp > 1 => implement Flowlet
- if ecmp = 1 => use LFA with probabilistic load balancing

# Resources
## ECMP + LFA + RLFA
https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6231351