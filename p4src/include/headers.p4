/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Define constants
const bit<9> HOST_INGRESS_PORT = 0;
const bit<4> HEARTBEAT_VERSION = 1;
const bit<4> IPV4_VERSION = 4;

const bit<16> ETHER_TYPE_IPV4 = 0x800;
const bit<16> ETHER_TYPE_INTERNAL = 0x823;
// This is the same as the real Ipv4 ether type on purpose
const bit<16> ETHER_TYPE_INTERNAL_WAYPOINT = 0x800;
const bit<16> ETHER_TYPE_HEARTBEAT = 0x1234;


const bit<8> TCP_PROTOCOL = 6;
const bit<8> UDP_PROTOCOL = 17;



typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<4>  rexfordAddr_t;
typedef bit<16> port_t;


// Define headers
struct host_port_t {
    @match(exact)
    bit<9> port;
}

// Instantiate metadata fields
struct metadata {
    rexfordAddr_t next_destination;
    bit<3> traffic_class;
    // Heartbeat and fail management stuff
    bit<1> linkState; //OK | FAIL
    bit<32> nextHop; // egress port for nh
    bit<32> index; // TBD
    bit<48> timestamp; //placeholder for reading last seen timestamp
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header heartbeat_t {
    bit<9>    port;
    bit<1>    from_cp;
    bit<1>    failed_link;
    bit<5>    padding;
}

header waypoint_t {
    rexfordAddr_t waypoint;
    bit<4> padding;
}

// Size = 9 B
header rexford_ipv4_t {
    bit<4>    version;      // 4
    bit<4>    ihl;          // 8
    bit<6>    dscp;         // 14
    bit<2>    ecn;          // 16
    bit<16>   totalLen;     // 32
    bit<3>    flags;        // 35
    bit<1>    padding;      // 36
    bit<8>    protocol;     // 44
    bit<16>   hdrChecksum;  // 60
    rexfordAddr_t srcAddr;  // 64
    rexfordAddr_t dstAddr;  // 68
    bit<28>   padding2;     // 96
    bit<16>   etherType;    // 112
}

// // Size = 20 B
// header ipv4_t {
//     bit<4>    version;
//     bit<4>    ihl;
//     bit<6>    dscp;
//     bit<2>    ecn;
//     bit<16>   totalLen;
//     bit<3>    flags;
//     bit<1>    padding;
//     bit<8>    protocol;
//     bit<16>   hdrChecksum;
//     rexfordAddr_t srcAddr;
//     rexfordAddr_t dstAddr;
//     // Waypoint is equal to dstAddr if there is no waypoint.
//     rexfordAddr_t wayPoint;
// }

// Size = 20 B
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    
    // Src Ip_addr:
    bit<16> src_network; // Always 10.0.
    bit<8>  src_rexford_addr;
    bit<8>  src_host_num; // Always 1 

    // Dst Ip_addr:
    bit<16> dst_network; // Always 10.0.
    bit<8>  dst_rexford_addr;
    bit<8>  dst_host_num; // Always 1 
}


header tcp_t {
    port_t  srcPort;
    port_t  dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    port_t  srcPort;
    port_t  dstPort;
    bit<16> len;
    bit<16> checksum;
}

// Instantiate packet headers
struct headers {
    ethernet_t      ethernet;
    heartbeat_t     heartbeat;
    ipv4_t          ipv4;
    waypoint_t      waypoint;
    rexford_ipv4_t  rexford_ipv4;
    tcp_t           tcp;
    udp_t           udp;
}