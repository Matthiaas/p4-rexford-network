/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define MAX_PORTS 11
//#define THRESHOLD 48w1000000 // 1s 
#define THRESHOLD_REC 48w600000 // 0.6s -> if we don't see traffic for more than > fail
#define THRESHOLD_SENT 48w200000 // 0.2s -> if we haven't seen traffic for more than > send
#define REGISTER_SIZE 8192
#define FLOWLET_TIMEOUT 48w200000 // 0.2s

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

    register<bit<4>>(1) host_address_reg;
    register<bit<9>>(1) host_port_reg;

    meter((bit<32>) MAX_PORTS, MeterType.bytes) port_congestion_meter;
    register<bit<2>>(MAX_PORTS) port_congestions;
    register<bit<64>>(1) dropped;

    register<flowlet_id_t>(REGISTER_SIZE) flowlet_to_id;
    register<timestamp_t>(REGISTER_SIZE) flowlet_time_stamp;


    // This is filled by the controller and uses the port_bytes_out information for it.
    register<bit<32>>(MAX_PORTS) estimated_queue_len;

    // port -> last seen timestamp for rec/sent packet
    register<bit<48>>(MAX_PORTS) rec_tstp;
    register<bit<48>>(MAX_PORTS) sent_tstp;
    register<bit<9>>(MAX_PORTS) debug;

    // port(link) -> 0(OK) | 1(FAIL)
    register<bit<1>>(MAX_PORTS) linkState;

    action random_drop(in bit<32> p) {
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)100);
        if(random_t < p) {
            meta.drop_packet = true;
        } 
    }

    action drop() {
        meta.drop_packet = true;
        bit<64> dr;
        dropped.read(dr, 0);
        dropped.write(0, dr + 1);

    }

    action set_waypoint(rexfordAddr_t waypoint) {
        hdr.ethernet.setValid();
        hdr.ipv4.setValid();
        hdr.waypoint.setValid();
        hdr.rexford_ipv4.setInvalid();
        hdr.waypoint.waypoint = waypoint;
    }

    //Heartbeat related actions
    action get_rec_tstp_for_port(bit<9> port){
        rec_tstp.read(meta.timestamp,(bit<32>)port);
    }
    action set_rec_tstp_for_port(bit<9> port){
        rec_tstp.write((bit<32>)port, std_meta.ingress_global_timestamp);
    }
    action get_sent_tstp_for_port(bit<9> port){
        sent_tstp.read(meta.timestamp,(bit<32>)port);
    }
    action set_sent_tstp_for_port(bit<9> port){
        sent_tstp.write((bit<32>)port, std_meta.ingress_global_timestamp);
    }
    action update_linkState(bit<9> port){
        linkState.write((bit<32>)port, (bit<1>)1);
    }

    action set_nhop(egressSpec_t port) {
        std_meta.egress_spec = port;
        // This means there is no lfa.
        meta.lfa = 0;
    }

    action set_nhop_and_lfa(egressSpec_t port, egressSpec_t lfa) {
        std_meta.egress_spec = port;
        meta.lfa = lfa;
    }


    action read_tcp_flowlet_registers(){
        //compute register index
        hash(meta.flowlet_register_index, HashAlgorithm.crc16,
            (bit<16>)0,
            { 
                hdr.rexford_ipv4.srcAddr, 
                hdr.rexford_ipv4.dstAddr, 
                hdr.tcp.srcPort, 
                hdr.tcp.dstPort,
                hdr.rexford_ipv4.protocol
            },
            (bit<14>)8192);

        //Read previous time stamp
        flowlet_time_stamp.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        //Read previous flowlet id
        flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_register_index);

        //Update timestamp
        flowlet_time_stamp.write((bit<32>)meta.flowlet_register_index, std_meta.ingress_global_timestamp);
    }

    action update_udp_flowlet_id(){
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)65000);
        meta.flowlet_id = (bit<16>)random_t;
    }

    action update_tcp_flowlet_id(){
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)65000);
        meta.flowlet_id = (bit<16>)random_t;
        // Only make this permanent for TCP. The next UDP packet can go whereever.
        flowlet_to_id.write((bit<32>)meta.flowlet_register_index, (bit<16>)meta.flowlet_id);
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_hash,
	            HashAlgorithm.crc16,
	            (bit<1>)0,
                { 
                    hdr.rexford_ipv4.srcAddr,
                    hdr.rexford_ipv4.dstAddr,
                    meta.srcPort, // This can be either TCP or UDP port
                    meta.dstPort, // This can be either TCP or UDP port
                    hdr.rexford_ipv4.protocol,
                    meta.flowlet_id // For UDP this is actually the only neccessary one.
                },
	            num_nhops);
	    meta.ecmp_group_id = ecmp_group_id;
    }

    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_group_id:    exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            drop;
            set_nhop;
            set_nhop_and_lfa;
        }
        size = 1024;
    }

    table ipv4_forward {
        key = { meta.next_destination : exact; }
        actions =  {
            set_nhop;
            set_nhop_and_lfa;
            ecmp_group;
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
        if (hdr.tcp.isValid()) {
            meta.srcPort = hdr.tcp.srcPort;
            meta.dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.srcPort = hdr.udp.srcPort;
            meta.dstPort = hdr.udp.dstPort;
        } 

        if(!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            // Internal traffic like heartbeats.
            meta.traffic_class = 0;
        } else if( meta.srcPort <= 100 && meta.dstPort <= 100) {
            meta.traffic_class = 1;
        } else if( meta.srcPort <= 200 && meta.dstPort <= 200) {
            meta.traffic_class = 2;
        } else if( meta.srcPort <= 300 && meta.dstPort <= 300) {
            meta.traffic_class = 3;
        } else if( meta.srcPort <= 400 && meta.dstPort <= 400) {
            meta.traffic_class = 4;
        } else if( meta.srcPort <= 65000 && meta.dstPort <= 65000 &&
                    60001 <= meta.srcPort && 60001 <= meta.dstPort) {
            // This is the additional Traffic
            meta.traffic_class = 5;
        } else {
            // Traffic is not considered in any SLA.
            // --> Drop it.
            // TODO: This is not possible by calling an action.
        }
    }

    apply {
        if (hdr.heartbeat.isValid()){
            if (hdr.heartbeat.from_cp == 1){
                // From cont -> check last rec timestamp
                
                get_rec_tstp_for_port(hdr.heartbeat.port);
                if (meta.timestamp != 0 && (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_REC)){
                    //Update linkstate -> notify cont
                    update_linkState(hdr.heartbeat.port);
                    hdr.heartbeat.failed_link = 1;
                    clone(CloneType.I2E, 100);
                }
                //check last time we sent something to this port
                get_sent_tstp_for_port(hdr.heartbeat.port); 
                if (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_SENT){
                    //Send heartbeat to port
                    hdr.heartbeat.from_cp = 0;
                    set_sent_tstp_for_port(hdr.heartbeat.port);
                    std_meta.egress_spec = hdr.heartbeat.port;
                } else {
                    // no need to forward the heartbeat -> drop
                    drop();
                }
            } else {
                // From neigh -> update last seen timestamp
                set_rec_tstp_for_port(std_meta.ingress_port);
                drop();
            }
        } else {
        //Normal traffic

            set_rec_tstp_for_port(std_meta.ingress_port);
            set_traffic_class();
            meta.drop_packet = false;

            // Read the address of the host.
            rexfordAddr_t host_addr;
            host_address_reg.read(host_addr, 0);
            bit<9> host_port;
            host_port_reg.read(host_port, 0);

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
            } else if(hdr.waypoint.isValid()) {
                meta.next_destination = hdr.waypoint.waypoint;
            }    

            // Flowlet ECMP switching.
            @atomic {
                if (hdr.tcp.isValid()) {
                    read_tcp_flowlet_registers();

                    bit<48> flowlet_time_diff = std_meta.ingress_global_timestamp - meta.flowlet_last_stamp;

                    //check if inter-packet gap is > 100ms
                    if (flowlet_time_diff > FLOWLET_TIMEOUT){
                        update_tcp_flowlet_id();
                    }
                } else {
                    update_udp_flowlet_id();
                }
            }

            switch (ipv4_forward.apply().action_run){
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }


            port_congestion_meter.execute_meter((bit<32>) std_meta.egress_spec, meta.congestion_tag);
            // TODO: This register is only for debug purpose. Delte sometime.
            port_congestions.write((bit<32>) std_meta.egress_spec, meta.congestion_tag);
            if(meta.congestion_tag == V1MODEL_METER_COLOR_YELLOW) {
                if(hdr.tcp.isValid()) {
                    random_drop(80);
                } else  {
                    random_drop(20);
                }

            } else if(meta.congestion_tag == V1MODEL_METER_COLOR_RED) {
               drop();
            }
            // Only drop if packet is not going to the host.
            if (meta.drop_packet && std_meta.egress_spec != host_port) {
                mark_to_drop(std_meta);
            }
            if (!meta.drop_packet){
                set_sent_tstp_for_port(std_meta.egress_spec);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {

    counter(MAX_PORTS, CounterType.bytes) port_bytes_out;

    
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
        if (hdr.heartbeat.isValid() && std_meta.instance_type == 1){
            // set failed link flag for the clone we send to the cp
            hdr.heartbeat.failed_link = 1;
        } else {
            port_bytes_out.count((bit<32>) std_meta.egress_port);

        }
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
