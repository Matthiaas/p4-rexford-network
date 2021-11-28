/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define MAX_PORTS 8

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t std_meta) {

    register<bit<4>>(1) host_address;
    register<bit<7>>(MAX_PORTS) congestion;
    
    action drop() {
        mark_to_drop(std_meta);
    }

    action set_nhop(egressSpec_t port) {
        std_meta.egress_spec = port;
    }

    action set_prim () {}

    action set_waypoint(rexfordAddr_t waypoint) {
        hdr.ethernet.setValid();
        hdr.ipv4.setValid();
        hdr.waypoint.setValid();
        hdr.rexford_ipv4.setInvalid();
        hdr.waypoint.waypoint = waypoint;
    }

    table ipv4_forward {
        key = { meta.next_destination : exact; }
        actions =  {
            set_nhop;
            drop;
        }
        default_action = drop();
    }

    table udp_waypoint{
        actions = {
            set_waypoint;
            NoAction;
        }
        key = {
            meta.next_destination: exact;
        }
        size = 16;
        default_action = NoAction();
    } 

    action construct_rexford_headers() {
        hdr.rexford_ipv4.setValid(); 
        hdr.rexford_ipv4.version    = hdr.ipv4.version;
        hdr.rexford_ipv4.ihl        = hdr.ipv4.ihl;
        hdr.rexford_ipv4.dscp       = hdr.ipv4.dscp;
        hdr.rexford_ipv4.ecn        = hdr.ipv4.ecn;
        hdr.rexford_ipv4.totalLen   = hdr.ipv4.totalLen;
        hdr.rexford_ipv4.flags      = hdr.ipv4.flags;
        hdr.rexford_ipv4.protocol   = hdr.ipv4.protocol;

        hdr.rexford_ipv4.srcAddr = (bit<4>) hdr.ipv4.src_rexford_addr;
        hdr.rexford_ipv4.dstAddr = (bit<4>) hdr.ipv4.dst_rexford_addr;   

        hdr.rexford_ipv4.etherType = ETHER_TYPE_INTERNAL;
    }

    action set_traffic_class() {
        // Get Traffic Class.
        port_t srcPort = 0;
        port_t dstPort = 0;
        if (hdr.tcp.isValid()) {
            srcPort = hdr.tcp.srcPort;
            dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            srcPort = hdr.udp.srcPort;
            dstPort = hdr.udp.dstPort;
        } 

        if( !hdr.tcp.isValid() && !hdr.udp.isValid()) {
            // Internal traffic like heartbeats.
            meta.traffic_class = 0;
        } else if( srcPort <= 100 && dstPort <= 100) {
            meta.traffic_class = 1;
        } else if( srcPort <= 200 && dstPort <= 200) {
            meta.traffic_class = 2;
        } else if( srcPort <= 300 && dstPort <= 300) {
            meta.traffic_class = 3;
        } else if( srcPort <= 400 && dstPort <= 400) {
            meta.traffic_class = 4;
        } else if( srcPort <= 65000 && dstPort <= 65000 &&
                    60001 <= srcPort && 60001 <= dstPort) {
            // This is the additional Traffic
            meta.traffic_class = 5;
        } else {
            // Traffic is not considered in any SLA.
            // --> Drop it.
            // TODO: This is not possible by calling an action.
        }
    }

    apply {
        set_traffic_class();

        // Read the address of the host.
        rexfordAddr_t host_addr;
        host_address.read(host_addr, 0);

        if(hdr.ethernet.isValid() && hdr.udp.isValid()) {
            meta.next_destination = (bit<4>) hdr.ipv4.dst_rexford_addr;   
            // Maybe setup waypoint.
            udp_waypoint.apply();           
        }

        bool reached_waypoint = false;
        // Check if the packet is a waypointed one.
        if (hdr.waypoint.isValid()) {
            // Check if we reached the waypoint.
            if (hdr.waypoint.waypoint == host_addr) {
                // We reached the waypoint.
                reached_waypoint = true;
            }
        }

        if ((!hdr.waypoint.isValid() && hdr.ethernet.isValid()) || reached_waypoint) {
            // Packet comes from host or reached the waypoint, remove the ethernet hdr.
            // Only consider packets that come from a host that are not waypointed.

            // First invalidate all unused headers.
            hdr.ethernet.setInvalid();
            hdr.ipv4.setInvalid();
            hdr.waypoint.setInvalid();
            construct_rexford_headers();
        }

        // This is used for the routing table lookup.
        // Either rexford_ipv4 is valid or the next destination is a waypoint.
        if (hdr.rexford_ipv4.isValid()) {
            meta.next_destination = hdr.rexford_ipv4.dstAddr;
            ipv4_forward.apply();
        } else if(hdr.waypoint.isValid()) {
            meta.next_destination = hdr.waypoint.waypoint;
            ipv4_forward.apply();
        }    
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {
    
    action reconstruct_packet(macAddr_t dstAddr) {
        // Ethernet:
        hdr.ethernet.setValid();
        hdr.ethernet.dstAddr = dstAddr;
        // TODO: Set src address to the mac of the switch.
        hdr.ethernet.srcAddr = dstAddr;
        hdr.ethernet.etherType = ETHER_TYPE_IPV4;

        // Ipv4:
        hdr.ipv4.setValid();
        hdr.rexford_ipv4.setInvalid();
        hdr.ipv4.version    = hdr.rexford_ipv4.version;
        hdr.ipv4.ihl        = hdr.rexford_ipv4.ihl;
        hdr.ipv4.dscp       = hdr.rexford_ipv4.dscp;
        hdr.ipv4.ecn        = hdr.rexford_ipv4.ecn;
        hdr.ipv4.totalLen   = hdr.rexford_ipv4.totalLen;
        hdr.ipv4.identification   = 0;
        hdr.ipv4.flags      = hdr.rexford_ipv4.flags;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.protocol   = hdr.rexford_ipv4.protocol;

        hdr.ipv4.src_network      = 0x0A00;
        hdr.ipv4.src_rexford_addr = (bit<8>) hdr.rexford_ipv4.srcAddr;
        // TODO: This is an awfull hack. We should either use tables or use 5 bit as adresses or so.
        if (hdr.ipv4.src_rexford_addr == 0) {
            hdr.ipv4.src_rexford_addr = 16;
        }
        hdr.ipv4.src_host_num      = 0x1;
        
        hdr.ipv4.dst_network      = 0x0A00;
        hdr.ipv4.dst_rexford_addr = (bit<8>) hdr.rexford_ipv4.dstAddr;
        // TODO: This is an awfull hack. We should either use tables or use 5 bit as adresses or so.
        if (hdr.ipv4.dst_rexford_addr == 0) {
            hdr.ipv4.dst_rexford_addr = 16;
        }
        hdr.ipv4.dst_host_num      = 0x1; 
    }

    table host_port_to_mac {
        key =  {
            std_meta.egress_port: exact;  
        }
        actions = {
            reconstruct_packet;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    apply {
        host_port_to_mac.apply();

        bit<4> va;
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
	        hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_network,
                hdr.ipv4.src_rexford_addr,
                hdr.ipv4.src_host_num,
                hdr.ipv4.dst_network,
                hdr.ipv4.dst_rexford_addr,
                hdr.ipv4.dst_host_num
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        // TODO: Update internal checksum.
    }
}

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