/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Define constants

const bit<9> HOST_INGRESS_PORT = 0;
const bit<4> HEARTBEAT_VERSION = 1;
const bit<4> IPV4_VERSION = 4;
const bit<16> TYPE_IPV4 = 0x800;


const bit<8> TCP_PROTOCOL = 6;
const bit<8> UDP_PROTOCOL = 17;



typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;

typedef bit<4> rexfordAddr_t;


// Define headers

struct host_port_t {
    @match(exact)
    bit<9> port;
}

// Instantiate metadata fields
struct metadata {

}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header rexford_t {
    bit<4>    version;
    // This is unused for the internal protocol but not for ipv4.
    // This is required because we need to have structs in multiple of 8.
    bit<4>    ihl;
}

// Size = 9 B
header rexford_ipv4_t {
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<3>    flags;
    bit<1>    padding;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    rexfordAddr_t srcAddr;
    rexfordAddr_t dstAddr;
    // Waypoint is equal to dstAddr if there is no waypoint.
    rexfordAddr_t wayPoint;
}

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
    bit<16> srcPort;
    bit<16> dstPort;
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
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

// Instantiate packet headers
struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    rexford_t       rexford;
    rexford_ipv4_t  rexford_ipv4;
    tcp_t           tcp;
    udp_t           udp;
}