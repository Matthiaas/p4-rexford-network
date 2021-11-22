/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

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
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_waypoint(rexfordAddr_t wayPoint) {
        hdr.rexford_ipv4.wayPoint = wayPoint;
    }

    action set_no_waypoint() {
        hdr.rexford_ipv4.wayPoint = hdr.rexford_ipv4.dstAddr;
    }

    table ipv4_forward {
        key = { hdr.rexford_ipv4.dstAddr : exact; }
        actions =  {
            set_nhop;
            drop;
        }
        default_action = drop();
    }

    table udp_waypoint{
        actions = {
            set_waypoint;
            set_no_waypoint;
        }
        key = {
            hdr.ipv4.dst_rexford_addr: exact;
        }
        size = 16;
        default_action = set_no_waypoint();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            // Packet comes from host, remove the ethernet hdr.
            hdr.ethernet.setInvalid();
            // Create rexford_ipv4
            hdr.ipv4.setInvalid();

            hdr.rexford.setValid();
            hdr.rexford_ipv4.setValid();
            
            hdr.rexford.version         = hdr.ipv4.version;
            hdr.rexford.ihl             = hdr.ipv4.ihl;
            hdr.rexford_ipv4.dscp       = hdr.ipv4.dscp;
            hdr.rexford_ipv4.ecn        = hdr.ipv4.ecn;
            hdr.rexford_ipv4.totalLen   = hdr.ipv4.totalLen;
            hdr.rexford_ipv4.flags      = hdr.ipv4.flags;
            hdr.rexford_ipv4.protocol   = hdr.ipv4.protocol;

            hdr.rexford_ipv4.srcAddr = (bit<4>) hdr.ipv4.src_rexford_addr;
            hdr.rexford_ipv4.dstAddr = (bit<4>) hdr.ipv4.dst_rexford_addr;

            
        }

        if (hdr.rexford_ipv4.isValid()) {
            ipv4_forward.apply();
        }

        if(hdr.udp.isValid()) {
            udp_waypoint.apply();
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
        hdr.ethernet.setValid();
        
        // Ethernet:
        hdr.ethernet.dstAddr = dstAddr;
        // TODO: Set src address to the mac of the switch.
        hdr.ethernet.srcAddr = dstAddr;
        hdr.ethernet.etherType = TYPE_IPV4;

        // Ipv4:
        hdr.ipv4.setValid();
        hdr.rexford.setInvalid();
        hdr.rexford_ipv4.setInvalid();

        hdr.ipv4.version    = hdr.rexford.version;
        hdr.ipv4.ihl        = hdr.rexford.ihl;
        hdr.ipv4.dscp       = hdr.rexford_ipv4.dscp;
        hdr.ipv4.ecn        = hdr.rexford_ipv4.ecn;
        hdr.ipv4.totalLen   = hdr.rexford_ipv4.totalLen;
        hdr.ipv4.identification   = 0;
        hdr.ipv4.flags      = hdr.rexford_ipv4.flags;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.protocol   = hdr.rexford_ipv4.protocol;

        hdr.ipv4.src_network      = 0x0A00;
        hdr.ipv4.src_rexford_addr = (bit<8>) hdr.rexford_ipv4.srcAddr;
        hdr.ipv4.src_host_num      = 0x1;
        
        hdr.ipv4.dst_network      = 0x0A00;
        hdr.ipv4.dst_rexford_addr = (bit<8>) hdr.rexford_ipv4.dstAddr;
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