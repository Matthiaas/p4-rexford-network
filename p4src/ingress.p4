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
    register<bit<1>>(MAX_PORTS) debug;


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

    // Actions for table escmp_group_to_nhop:

    action set_nhop(egressSpec_t port) {
        std_meta.egress_spec = port;
        // This means there is no lfa.
        meta.lfa = 0;
    }

    action set_nhop_and_lfa(egressSpec_t port, egressSpec_t lfa) {
        std_meta.egress_spec = port;
        meta.lfa = lfa;
    }

    table escmp_group_to_nhop {
        key = {
            meta.escmp_group_id:    exact;
            meta.escmp_nhop_id: exact;
        }
        actions = {
            drop;
            set_nhop;
            set_nhop_and_lfa;
        }
        size = 1024;
    }

    // Actions for table ipv4_forward:

    action escmp_group(bit<14> escmp_group_id, bit<16> num_ecmp_nhops, bit<16> num_scmp_nhops){
        bit<16> num_nhops = num_scmp_nhops;
        if (hdr.rexford_ipv4.scmp_splits == MAX_SCMP_SPLITS) {
            num_nhops = num_ecmp_nhops;
        }
        hash(meta.escmp_nhop_id,
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

	    meta.escmp_group_id = escmp_group_id;
        if (meta.escmp_nhop_id >= num_ecmp_nhops) {
            hdr.rexford_ipv4.scmp_splits = hdr.rexford_ipv4.scmp_splits + 1;
        }
    }

    table ipv4_forward {
        key = { meta.next_destination : exact; }
        actions =  {
            set_nhop;
            set_nhop_and_lfa;
            escmp_group;
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

    action set_nexthop_lfa_rlfa(rexfordAddr_t rlfa_host, egressSpec_t rlfa_port){
        //to be called after ipv4_forward
        //check the status of nexthop link and decide wt to use lfa or rlfa
        check_linkState(std_meta.egress_spec);
        if (meta.linkState == 1){
            //debug.write((bit<32>)1,(bit<1>)1);
            //nexthop link down -> protect...
            //using lfa
            if (meta.lfa != 0){
                std_meta.egress_spec = meta.lfa;
            }
            //using rlfa
            else if (rlfa_port != 0){
                std_meta.egress_spec = rlfa_port;
                if (hdr.rexford_ipv4.isValid()){
                    hdr.rexford_ipv4.original_dstAddr = meta.next_destination;
                    hdr.rexford_ipv4.dstAddr = rlfa_host;
                    hdr.rexford_ipv4.rlfa_protected = 1;
                }
                else if (hdr.waypoint.isValid()){
                    hdr.waypoint.original_dstAddr = meta.next_destination;
                    hdr.waypoint.waypoint = rlfa_host;
                    hdr.waypoint.rlfa_protected = 1;
                }
            }
        }
    }

    table final_forward{
        key = {std_meta.egress_spec: exact;}
        actions = {
            set_nexthop_lfa_rlfa;
            NoAction;
        }
        size = MAX_PORTS;
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
        hdr.rexford_ipv4.scmp_splits = 0;
    }

    action times_ten(in bit<32> val, out bit<32> res) {
        res = (val << 3) + (val << 1);
    }

    action drop_based_on_queue_length_and_traffic_class() {
        bit<32> queueLen;
        estimated_queue_len.read(queueLen, (bit<32>) std_meta.egress_spec);
        bit<32> queueLen2;
        estimated_queue_len_v2.read(queueLen2, (bit<32>) std_meta.egress_spec);
        if(queueLen2 > queueLen) {
            queueLen = queueLen2;
        }
        
        // This line for whatever reason lets the compiler give up.
       bit<32> dropProbability = 0;

    /*
        // The values in here are pretty arbitrary. But tweeked by testing different numbers.
        if(!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            // Priority 0.
            // Internal traffic like heartbeats.
            // Never drop them.
            dropProbability = 0;
        } else if( meta.srcPort <= 100 && meta.dstPort <= 100) {
            // Priority 1.
            if (queueLen > 25 && hdr.tcp.isValid()) {
                times_ten(queueLen - 25, dropProbability);
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 200 && meta.dstPort <= 200) {
            // Priority 2.
            if (queueLen > 20) {
                times_ten(queueLen - 20, dropProbability);
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 300 && meta.dstPort <= 300) {
            // Priority 3.
            if (queueLen > 15 ) {
                times_ten(queueLen - 15, dropProbability);
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 400 && meta.dstPort <= 400) {
            // Priority 4.
            if (queueLen > 0) {
                times_ten(queueLen, dropProbability);
            } else {
                dropProbability = 0;
            }
        } else if( meta.srcPort <= 65000 && meta.dstPort <= 65000 &&
                    60001 <= meta.srcPort && 60001 <= meta.dstPort) {
            // Lowest priority (Its only 3SLAs and we dont know how weird it is going to be).
            // Priority 5.
            dropProbability = 0;
            if (queueLen > 0) {
                dropProbability = 100;
            } else {
                dropProbability = 0;
            }
            
        } else {
            // Traffic is not considered in any SLA.
            dropProbability = 1;
        }
        */
        // This seems to outperfrom the priority stuff.
        // TODO: Test this for failures.
        if(!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            // Priority 0.
            // Internal traffic like heartbeats.
            // Never drop them.
            dropProbability = 0;
        } else if( meta.srcPort <= 65000 && meta.dstPort <= 65000 
                    && 60001 <= meta.srcPort && 60001 <= meta.dstPort
                        && queueLen > 0) {
            dropProbability = 100;           
        } else {
            if(queueLen > 7) {
                queueLen = queueLen - 7;
                dropProbability = (queueLen << 2) + (queueLen);
            }
        }
        random_drop(dropProbability);
    }

    action update_queue_length_estimate_v2() {
        @atomic {
            bit<32> queueLen = 0;
            estimated_queue_len_v2.read(queueLen, (bit<32>) hdr.heartbeat.port);
            if(queueLen >= 1) {
                queueLen = queueLen - 1;
            }
            if(queueLen >= 1) {
                queueLen = queueLen - 1;
            }
            estimated_queue_len_v2.write((bit<32>) hdr.heartbeat.port, queueLen);
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
                    //host_address_reg.read(meta.hb_switch_addr, 0);
                    clone3(CloneType.I2E, 100, meta); //this yields a compilation error due to a bug in their src code
                }
                //check last time we sent something to this port
                get_sent_tstp_for_port(hdr.heartbeat.port); 
                if (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_SENT){
                    //Send heartbeat to port
                    set_sent_tstp_for_port(hdr.heartbeat.port);
                    std_meta.egress_spec = hdr.heartbeat.port;
                } else {
                    // no need to forward the heartbeat -> drop
                    meta.drop_packet = true;
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
                    //host_address_reg.read(meta.hb_switch_addr, 0);
                    clone3(CloneType.I2E, 100, meta);
                }
                meta.drop_packet = true;
            }
            if (meta.drop_packet == true){
                mark_to_drop(std_meta);
            }
        } else {
            //Normal traffic
            set_rec_tstp_for_port(std_meta.ingress_port);
    
            meta.drop_packet = false;

            // Read the address and port of the host.
            rexfordAddr_t host_addr;
            bit<9> host_port;
            bool from_host;

            host_address_reg.read(host_addr, 0);
            host_port_reg.read(host_port, 0);
            from_host = host_port == std_meta.ingress_port;

            // first thing first, check if packet is protected
            if (hdr.rexford_ipv4.isValid()){
                //debug.write((bit<32>)0,(bit<1>)1);
                if (hdr.rexford_ipv4.rlfa_protected == 1){
                    if (hdr.rexford_ipv4.dstAddr == host_addr){
                        // reached rlfa -> set real destination
                        hdr.rexford_ipv4.dstAddr = hdr.rexford_ipv4.original_dstAddr;
                        hdr.rexford_ipv4.rlfa_protected = 0;
                    }
                }
            }

            if (hdr.waypoint.isValid()){
                //debug.write((bit<32>)1,(bit<1>)1);
                if (hdr.waypoint.rlfa_protected == 1){
                    if (hdr.waypoint.waypoint == host_addr){
                        // reached rlfa -> set real destination
                        hdr.waypoint.waypoint = hdr.waypoint.original_dstAddr;
                        hdr.waypoint.rlfa_protected = 0;
                    }
                }
            }

            set_meta_ports();

            
            if(from_host && hdr.udp.isValid()) {
                // Maybe setup waypoint if packet comes from host.
                meta.next_destination = (bit<4>) hdr.ipv4.dst_rexford_addr;   
                udp_waypoint.apply();    
            }

            // Check if the waypoint was reached.
            bool reached_waypoint = false;
            if (hdr.waypoint.isValid()) {
                if (hdr.waypoint.waypoint == host_addr) {
                    reached_waypoint = true;
                }
            }

            if ((!hdr.waypoint.isValid() && from_host) || reached_waypoint) {
                // Packet comes from host and is not waypointed, or just reached the waypoint here.
                // Only consider packets that come from a host that are not waypointed.
                // This is because waypointed traffic is not allowed to change the headers to be recognised by the tests.
                debug.write((bit<32>)2,(bit<1>)1);
                construct_rexford_headers();
            }

            // This is used for the routing table lookup.
            // Either rexford_ipv4 is valid or the next destination is a waypoint.
            if (hdr.rexford_ipv4.isValid()) {
                meta.next_destination = hdr.rexford_ipv4.dstAddr;
            } else if(hdr.waypoint.isValid()) {
                meta.next_destination = hdr.waypoint.waypoint;
            }    

            // Flowlet ECMP & SCMP switching.
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
                escmp_group: {
                    escmp_group_to_nhop.apply();
                }
            }
            //check nexthop status and in case route using the lfa or rlfa
            final_forward.apply();

            drop_based_on_queue_length_and_traffic_class();
            
            if(!meta.drop_packet) {
                // This applies the meter. 
                // - Yellow: Defines a threshold where we drop a single packet in order to make sure the TCP flow does not 
                //           further increase its rate in the future. This is based on:
                //            https://www.researchgate.net/publication/301857331_Global_Synchronization_Protection_for_Bandwidth_Sharing_TCP_Flows_in_High-Speed_Links
                // - Red: We exceed the max bandwith with the max queulength 
                //      --> We are forced to drop every packet to not increase the delay by to much. 
                // (This can not be put into its own action since it conditionally calls actions.) -> We can feel the pain
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
            }
         
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
