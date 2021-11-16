/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Define constants

const bit<9> HOST_INGRESS_PORT = 0;
const bit<4> HEARTBEAT_VERSION = 1;
const bit<4> IPV4_VERSION = 4;
const bit<16> TYPE_IPV4 = 0x800;

// Define headers

struct host_port_t {
    @match(exact)
    bit<9> port;
}

// Instantiate metadata fields
struct metadata {

}


typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header rexford_ipv4_t {
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// Instantiate packet headers
struct headers {
    ethernet_t      ethernet;
    rexford_t       rexford;
    rexford_ipv4_t  rexford_ipv4;
}