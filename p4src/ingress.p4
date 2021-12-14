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
    register<timestamp_t>(REGISTER_SIZE) flowlet_last_drop_time_stamp;


    // This is filled by the controller and uses the port_bytes_out information for it.
    register<bit<32>>(MAX_PORTS) counter_based_estimated_queue_len;

    // port -> last seen timestamp for rec/sent packet
    register<bit<48>>(MAX_PORTS) recv_timestamp;
    register<bit<48>>(MAX_PORTS) sent_timestamp;

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

    action get_recv_timestamp_for_port(bit<9> port){
        recv_timestamp.read(meta.timestamp,(bit<32>)port);
    }
    action set_recv_timestamp_for_port(bit<9> port){
        recv_timestamp.write((bit<32>)port, std_meta.ingress_global_timestamp);
    }
    action get_sent_timestamp_for_port(bit<9> port){
        sent_timestamp.read(meta.timestamp,(bit<32>)port);
    }
    action set_sent_timestamp_for_port(bit<9> port){
        sent_timestamp.write((bit<32>)port, std_meta.ingress_global_timestamp);
    }
    action fail_linkState(bit<9> port){
        linkState.write((bit<32>)port, (bit<1>)1);
    }
    action check_linkState(out bit<1> result, bit<9> port){
        linkState.read(result, (bit<32>)port);
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
        flowlet_last_drop_time_stamp.read(meta.flowlet_last_dropped_stamp, (bit<32>)meta.flowlet_register_index);

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
        // Only make this permanent for TCP. The next UDP packet can go wherever.
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
                    meta.flowlet_id, // For UDP this is actually the only necessary one.
                    std_meta.ingress_port
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
        bit<1> link_down;
        bit<1> lfa_down;
        bit<1> rlfa_down;
        check_linkState(link_down, std_meta.egress_spec);
        check_linkState(link_down, std_meta.egress_spec);
        check_linkState(link_down, std_meta.egress_spec);

        if (link_down == 1){
            //nexthop link down -> protect...
            //using lfa
            if (meta.lfa != 0 && lfa_down != 1){
                std_meta.egress_spec = meta.lfa;
            }
            //using rlfa
            else if (rlfa_port != 0){
                std_meta.egress_spec = rlfa_port;
                if (rlfa_down == 1){
                    meta.drop_packet = true;
                }
                else if (hdr.rexford_ipv4.isValid()){
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
    // Actions for the main Ingress pipeline:
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

    // This performs RED. If a certain queue length (=7) is reached we start dropping packets with 
    // The probability min(100, (queue_length-7) * 5) in percent.
    action random_early_detection() {
        bit<32> queueLen;
        counter_based_estimated_queue_len.read(queueLen, (bit<32>) std_meta.egress_spec);
        bit<32> meterBasedQueueLen;
        meter_based_estimated_queue_len.read(meterBasedQueueLen, (bit<32>) std_meta.egress_spec);

        // The maximum of both estimates leads to a good estimate of the actual queue length.
        if(meterBasedQueueLen > queueLen) {
            queueLen = meterBasedQueueLen;
        }
        
       bit<32> dropProbability = 0;
        if(!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            // Internal traffic like heartbeats. --> Never drop them.
            dropProbability = 0;
        } else if( meta.srcPort <= 65000 && meta.dstPort <= 65000 
                    && 60001 <= meta.srcPort && 60001 <= meta.dstPort
                        && queueLen > 0) {
            // Always drop this traffic when we start up building queues.
            // There are also no bursts since its UDP only, so its fine.
            // So we only transmit this if there is no other traffic needing the bandwidth.
            dropProbability = 100;           
        } else {
            if(queueLen > 7) {
                queueLen = queueLen - 7;
                dropProbability = (queueLen << 2) + (queueLen);
            }
        }
        random_drop(dropProbability);
    }

    action update_meter_based_queue_length_estimate() {
        @atomic {
            bit<32> queueLen = 0;
            meter_based_estimated_queue_len.read(queueLen, (bit<32>) hdr.heartbeat.port);
            // This is called every 1.2 ms so decrease the queue length by one.
            if(queueLen >= 1) {
                queueLen = queueLen - 1;
            }
            meter_based_estimated_queue_len.write((bit<32>) hdr.heartbeat.port, queueLen);
        }
    }

    action notify_controller(in bit<9> port, in bit<1> failed_link, in bit<1> recovered_link ) {
        meta.hb_port = port;
        meta.hb_failed_link = failed_link;
        meta.hb_recovered_link = recovered_link;
        log_msg("HB Ingress: port {} f {} r {}",{meta.hb_port, meta.hb_failed_link, meta.hb_recovered_link});
        clone3(CloneType.I2E, 100, meta);
    }

    apply {
        if (hdr.heartbeat.isValid()){
            if (hdr.heartbeat.from_cp == 1){
                // Update the queue length estimation every 1.2ms (The heartbeat_freq in settings.json)
                update_meter_based_queue_length_estimate();
                // From cont -> check last rec timestamp
                get_recv_timestamp_for_port(hdr.heartbeat.port);
                if (meta.timestamp != 0 && (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_REC)){
                    //Update linkstate -> notify cont
                    bit<1> linkStatus;
                    check_linkState(linkStatus, hdr.heartbeat.port);
                    //if not already failed
                    if (linkStatus != 1){
                        fail_linkState(hdr.heartbeat.port);
                        notify_controller(hdr.heartbeat.port, 1, 0);
                    }
                }
                //check last time we sent something to this port
                get_sent_timestamp_for_port(hdr.heartbeat.port); 
                if (std_meta.ingress_global_timestamp - meta.timestamp > THRESHOLD_SENT){
                    //Send heartbeat to port
                    set_sent_timestamp_for_port(hdr.heartbeat.port);
                    std_meta.egress_spec = hdr.heartbeat.port;
                } else {
                    // no need to forward the heartbeat -> drop
                    meta.drop_packet = true;
                }
            } else {
                // From neigh -> update last seen timestamp
                set_recv_timestamp_for_port(std_meta.ingress_port);
                bit<1> linkStatus;
                check_linkState(linkStatus, std_meta.ingress_port);
                if (linkStatus == 1){
                    recover_linkState(std_meta.ingress_port);
                    notify_controller(std_meta.ingress_port, 0, 1);
                }
                meta.drop_packet = true;
            }
            if (meta.drop_packet == true){
                mark_to_drop(std_meta);
            }
        } else {
            //Normal traffic
            set_recv_timestamp_for_port(std_meta.ingress_port);
            bit<1> linkStatus;
            check_linkState(linkStatus, std_meta.ingress_port);
            if (linkStatus == 1){
                recover_linkState(std_meta.ingress_port);
                log_msg("Recovered with normal traffic");
                notify_controller(std_meta.ingress_port, 0, 1);
            }
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
                if (hdr.rexford_ipv4.rlfa_protected == 1){
                    if (hdr.rexford_ipv4.dstAddr == host_addr){
                        // reached rlfa -> set real destination
                        hdr.rexford_ipv4.dstAddr = hdr.rexford_ipv4.original_dstAddr;
                        hdr.rexford_ipv4.rlfa_protected = 0;
                    }
                }
            }

            if (hdr.waypoint.isValid()){
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
                // This is because waypointed traffic is not allowed to change the headers to be recognized by the tests.
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

                    bit<48> flowlet_drop_time_diff = std_meta.ingress_global_timestamp - meta.flowlet_last_stamp;
                    // If the drop is longer than DROP_FLOWLET_TIMEOUT ago, possibly allow a new drop on this flow.
                    if (meta.flowlet_last_dropped_stamp > DROP_FLOWLET_TIMEOUT) {
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

            /*
            if (meta.srcPort <= 300 && meta.srcPort > 200 && from_host) {
                if (hdr.tcp.isValid()) {
                    meta.drop_packet = true;
                } else {
                    random_drop(99);
                }  
            }
            if (meta.srcPort <= 100 && meta.srcPort > 0 && from_host) {
                if (hdr.udp.isValid()) {
                   random_drop(99);
                } 
            }
*/

            random_early_detection();
            
            if(!meta.drop_packet) {
                // This applies the meter. 
                // - Yellow: Defines a threshold where we drop a single packet in order to make sure the TCP flow does not 
                //           further increase its rate in the future. This is based on:
                //            https://www.researchgate.net/publication/301857331_Global_Synchronization_Protection_for_Bandwidth_Sharing_TCP_Flows_in_High-Speed_Links
                // - Red: We exceed the max bandwidth with the max queue length 
                //      --> We are forced to drop every packet to not increase the delay by to much. 
                // (This can not be put into its own action since it conditionally calls actions.) -> We can feel the pain
                bit<2> congestion_tag;
                port_congestion_meter.execute_meter((bit<32>) std_meta.egress_spec, congestion_tag);
                if(congestion_tag == V1MODEL_METER_COLOR_YELLOW) {
                    // This is the TCP Global sync protection.
                    if(hdr.tcp.isValid()) {
                        bit<1> dropped_flowlet;
                        flowlet_dropped.read(dropped_flowlet, (bit<32>)meta.flowlet_register_index);
                        if(dropped_flowlet == 0) {
                            meta.drop_packet = true;
                            flowlet_dropped.write((bit<32>)meta.flowlet_register_index, 1);
                            flowlet_last_drop_time_stamp.write((bit<32>)meta.flowlet_register_index, std_meta.ingress_global_timestamp);
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
                // If we don't drop it, mark it as a heartbeat.
                set_sent_timestamp_for_port(std_meta.egress_spec);
            }
        }
    }
}
