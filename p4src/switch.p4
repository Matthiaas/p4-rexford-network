/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"
#include "include/checksum.p4"


#define MAX_PORTS 11 //max index is 10
//#define THRESHOLD 48w1000000 // 1s
//hb frequency from controller = 0.12s

// 150ms -> if we don't see traffic for more than > fail
#define THRESHOLD_REC 48w156000 

// 48ms -> if we haven't seen traffic for more than > send
#define THRESHOLD_SENT 48w48000 
#define REGISTER_SIZE 8192
#define FLOWLET_TIMEOUT 48w80000 // 0.08s
#define DROP_FLOWLET_TIMEOUT 48w100000 // 0.1s
#define MAX_SCMP_SPLITS 3

// Globals:
register<bit<32>>(MAX_PORTS) meter_based_estimated_queue_len;

#include "ingress.p4"
#include "egress.p4"

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;
