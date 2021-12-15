> This is a template for your project README, you should replace its content with an actual description of your project, but make sure to include all required information outlined below. After these three compulsory sections, you are free to use the rest of your README file as you see most useful.
> 

## Group info

| Group name | 13_REXFORD |  |  |
| --- | --- | --- | --- |
| Member 1 | Francesco Intoci  | fintoci | fintoci@ethz.ch |
| Member 2 | Westermann Floris | wfloris | wfloris@ethz.ch |
| Member 3 | Bungeroth Matthias | mbungeroth | mbungeroth@ethz.ch |

## Overview

This project implements dynamic failure aware routing for the claranet network.
We support routing table calculations using both delay and number of hops as a weight metric.
To avoid congestion the switches use local load-balancing by means of flowlets and Equal Cost Multi-Path (ECMP).
In addition to the equal cost paths we also allow the switches to use Similar Cost Paths (SCMP).
This allows us to distribute the load even further over the network.

Should this still not suffice to handle the incoming packets, the switches will start dropping select packets to stop congestion and avoid TCP synchronisation.
To this end, we implement a queue length estimator using meters that approximates the congestion of each link.

Furthermore, we put a lot of thought into failure detection and handling.
Since the network is small, we can precompute all possible failures and according routing tables ahead of time.
However, computing all possible failures will still take up a non-negligible amount of storage (>1GB).
We thus only precompute common failure scenarios and compute the others at runtime if necessary.

Failure detections work by sending heartbeats on all individual links.
Because of the special properties of the links which penalize sending a lot of small packets we allow normal packets to also function as heartbeats.
We thus only send heartbeats when there is no other traffic on the link.

Whenever a failure is detected, the switch will temporarily re-route the packets over a Loop Free Alternative switch (LFA).
If this is not possible, it will use a remote LFA.
The controller, in the meantime, fetches the precomputed or computes the new routing table and updates the switch.


## Individual Contributions

In this section, note down 1 or 2 sentences *per team member* outlining everyone's contribution to the project. We want to see that everybody contributed, but you don't need to get into fine details. For example, write who contributed to which feature of your solution, but do *not* write who implemented a particular function. 

### Francesco Intoci
- Routing table computation, including first version of ECMP paths.
- Implementation of per-destination LFAs.
- Implementation of PQ algorithm for RLFAs.
- Failure detection and recovery through heartbeat messages.

### Westermann Floris
- Precomputation of Failure Configurations
- Initial naive congestion detection using Meters
- Similar Cost Multi-Path routing

### Bungeroth Matthias

- Parsing/ Deparsing of headers to internal headers without ethernet (at entry/ exit ports).
- Waypointing for UDP waypointed traffic.
- First version ECMP-flowlet routing
- TCP Global Synchronization Protection based on this [paper](https://www.researchgate.net/publication/301857331_Global_Synchronization_Protection_for_Bandwidth_Sharing_TCP_Flows_in_High-Speed_Links)
- Queue-length estimator
- QOS with Random Early Detection based on priorities.

