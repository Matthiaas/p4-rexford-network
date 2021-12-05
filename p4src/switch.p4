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
#define DROP_FLOWLET_TIMEOUT 48w100000 // 0.1s

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

    register<flowlet_id_t>(REGISTER_SIZE) flowlet_to_id;
    register<timestamp_t>(REGISTER_SIZE) flowlet_time_stamp;

    // This is used to only drop one packet every DROP_FLOWLET_TIMEOUT when the
    // meter turns yellow.
    register<bit<1>>(REGISTER_SIZE) flowlet_dropped;
    register<timestamp_t>(REGISTER_SIZE) flowlet_lastdrop_time_stamp;


    // This is filled by the controller and uses the port_bytes_out information for it.
    register<bit<32>>(MAX_PORTS) estimated_queue_len;

    // port -> last seen timestamp for rec/sent packet
    register<bit<48>>(MAX_PORTS) rec_tstp;
    register<bit<48>>(MAX_PORTS) sent_tstp;

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
    }

    // Heartbeat related actions:

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
    action fail_linkState(bit<9> port){
        linkState.write((bit<32>)port, (bit<1>)1);
    }
    action check_linkState(bit<9> port){
        linkState.read(meta.linkState, (bit<32>)port);
    }
    action recover_linkState(bit<9> port){
        linkState.write((bit<32>)port, (bit<1>)0);
    }

    // Flowlet related actions:

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
        flowlet_lastdrop_time_stamp.read(meta.flowlet_lastdropped_stamp, (bit<32>)meta.flowlet_register_index);

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

    // Actions for table ecmp_group_to_nhop:

    action set_nhop(egressSpec_t port) {
        std_meta.egress_spec = port;
        // This means there is no lfa.
        meta.lfa = 0;
    }

    action set_nhop_and_lfa(egressSpec_t port, egressSpec_t lfa) {
        std_meta.egress_spec = port;
        meta.lfa = lfa;
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

    // Actions for table ipv4_forward:

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

    // Actions for table udp_waypoint:

    action set_waypoint(rexfordAddr_t waypoint) {
        hdr.ethernet.setValid();
        hdr.ipv4.setValid();
        hdr.waypoint.setValid();
        hdr.rexford_ipv4.setInvalid();
        hdr.waypoint.waypoint = waypoint;
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

    // Actions for the main Ingresspipeline:

    action set_meta_ports() {
        if (hdr.tcp.isValid()) {
            meta.srcPort = hdr.tcp.srcPort;
            meta.dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.srcPort = hdr.udp.srcPort;
            meta.dstPort = hdr.udp.dstPort;
        } 
    }

    action construct_rexford_headers() {
        // First invalidate all unused headers.
        hdr.ethernet.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.waypoint.setInvalid();

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

    action get_drop_probability_based_on_queue_length_and_traffic_class(out bit<32> dropProbability) {
        bit<32> queueLen;
        estimated_queue_len.read(queueLen, (bit<32>) std_meta.egress_spec);
        
        // This line for whatever reason lets the compiler give up.
        // dropProbability = 0;

        if(!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            // Internal traffic like heartbeats.
            // Never drop them.
            dropProbability = 0;
        } else if( meta.srcPort <= 100 && meta.dstPort <= 100) {
            if (queueLen > 30 && hdr.tcp.isValid()) {
                dropProbability = queueLen + queueLen + queueLen - 90;
                dropProbability = dropProbability + dropProbability + dropProbability;
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 200 && meta.dstPort <= 200) {
            if (queueLen > 20) {
                dropProbability = queueLen + queueLen + queueLen - 60;
                dropProbability = dropProbability + dropProbability + dropProbability;
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 300 && meta.dstPort <= 300) {
            if (queueLen > 1) {
                dropProbability = queueLen + queueLen + queueLen + queueLen;
                dropProbability = dropProbability + dropProbability + dropProbability;
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 400 && meta.dstPort <= 400) {
            if (queueLen > 7) {
                dropProbability = queueLen + queueLen + queueLen + queueLen - 21;
                dropProbability = dropProbability + dropProbability + dropProbability;
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 65000 && meta.dstPort <= 65000 &&
                    60001 <= meta.srcPort && 60001 <= meta.dstPort) {
            // TODO: Set this correctly.
            dropProbability = 0;
        } else {
            // Traffic is not considered in any SLA.
            dropProbability = 1;
        }
    }

    apply {
        if (hdr.heartbeat.isValid()){
            if (hdr.heartbeat.from_cp == 1){
                // From cont -> check last rec timestamp
                get_rec_tstp_for_port(hdr.heartbeat.port);
                if (meta.timestamp != 0 && (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_REC)){
                    //Update linkstate -> notify cont
                    fail_linkState(hdr.heartbeat.port);
                    meta.hb_port = hdr.heartbeat.port;
                    meta.hb_failed_link = 1;
                    meta.hb_recovered_link = 0;
                    clone3(CloneType.I2E, 100, meta);
                }
                //check last time we sent something to this port
                get_sent_tstp_for_port(hdr.heartbeat.port); 
                if (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_SENT){
                    //Send heartbeat to port
                    set_sent_tstp_for_port(hdr.heartbeat.port);
                    std_meta.egress_spec = hdr.heartbeat.port;
                } else {
                    // no need to forward the heartbeat -> drop
                    drop();
                }
            } else {
                // From neigh -> update last seen timestamp
                set_rec_tstp_for_port(std_meta.ingress_port);
                check_linkState(std_meta.ingress_port);
                if (meta.linkState == 1){
                    recover_linkState(std_meta.ingress_port);
                    meta.hb_port = std_meta.ingress_port;
                    meta.hb_failed_link = 0;
                    meta.hb_recovered_link = 1;
                    clone3(CloneType.I2E, 100, meta);
                }
                drop();
            }
        } else {
            //Normal traffic
            set_rec_tstp_for_port(std_meta.ingress_port);
    
            meta.drop_packet = false;

            // Read the address and port of the host.
            rexfordAddr_t host_addr;
            bit<9> host_port;

            host_address_reg.read(host_addr, 0);
            host_port_reg.read(host_port, 0);

            set_meta_ports();

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
                // Packet comes from host or just reached the waypoint here.
                // Only consider packets that come from a host that are not waypointed.
                // This is because waypointed traffic is not allowed to change the headers to be recognised by the tests.
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
                    //check if inter-packet gap is > FLOWLET_TIMEOUT
                    if (flowlet_time_diff > FLOWLET_TIMEOUT){
                        update_tcp_flowlet_id();
                    }

                    bit<48> flowlet_droptime_diff = std_meta.ingress_global_timestamp - meta.flowlet_last_stamp;
                    // If the drop is longer than DROP_FLOWLET_TIMEOUT ago, possibly allow a new drop on this flow.
                    if (meta.flowlet_lastdropped_stamp > DROP_FLOWLET_TIMEOUT) {
                        flowlet_dropped.write((bit<32>)meta.flowlet_register_index, 0);
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
            
            // This applies the meter. 
            // - Yellow: Defines a threshold where we drop a single packet in order to make sure the TCP flow does not 
            //           further increase its rate in the future. This is based on:
            //            https://www.researchgate.net/publication/301857331_Global_Synchronization_Protection_for_Bandwidth_Sharing_TCP_Flows_in_High-Speed_Links
            // - Red: We exceed the max bandwith with the max queulength 
            //      --> We are forced to drop every packet to not increase the delay by to much. 
            // (This can not be put into its own action since its conditionally calls actions.)
            bit<2> congestion_tag;
            port_congestion_meter.execute_meter((bit<32>) std_meta.egress_spec, congestion_tag);
            if(congestion_tag == V1MODEL_METER_COLOR_YELLOW) {
                if(hdr.tcp.isValid()) {
                    bit<1> dopped_flowlet;
                    flowlet_dropped.read(dopped_flowlet, (bit<32>)meta.flowlet_register_index);
                    if(dopped_flowlet == 0) {
                        meta.drop_packet = true;
                        flowlet_dropped.write((bit<32>)meta.flowlet_register_index, 1);
                        flowlet_lastdrop_time_stamp.write((bit<32>)meta.flowlet_register_index, std_meta.ingress_global_timestamp);
                    }
                }
            } else if(congestion_tag == V1MODEL_METER_COLOR_RED) {
                meta.drop_packet = true;
            }

            bit<32> dropProbability;
            get_drop_probability_based_on_queue_length_and_traffic_class(dropProbability);
            random_drop(dropProbability);
         
            // Only drop if packet is not going to the host.
            if (meta.drop_packet && std_meta.egress_spec != host_port) {
                mark_to_drop(std_meta);
            } else {
                // If we dont drop it, mark it as a heartbeat.
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
        if (hdr.heartbeat.isValid()){
            if (std_meta.instance_type != 1){
                //not cloned
                hdr.heartbeat.from_cp = 0;
            }
            hdr.heartbeat.failed_link = meta.hb_failed_link;
            hdr.heartbeat.recovered_link = meta.hb_recovered_link;
            hdr.heartbeat.port = meta.hb_port;
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
