/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {

    counter(MAX_PORTS, CounterType.bytes) port_bytes_out;

    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_5;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_10;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_15;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_20;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_25;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_30;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_35;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queue_len_40;


    action estimate_queue_len_v2() {
        /*
            This is the Queue Length Estimator Version 2.
            It sets up a couple of meters all with the same peak bandwidth but different
            burst sizes (= queue lengths). Whenever a meter is hits Red (we are not using
            the color yellow here), we assume that the burst size of this meter equals the 
            current length of the queue behind our switch.

            This only provides this invariant:
                Meter x hits read ---implies---> Queue length is at least x

            In order to get an even better estimate we only update the estimated_queue_len_v2
            if the current estimate is smaller than the new one (because of our invariant). 
            To decrease the queue length estimate we decrease the counter whenever we receive 
            a heartbeat from the controller by one for every 1.2ms that have passed.
            The heartbeat frequency should be a multiple of 1.2ms to easily achieve this.            
        */
        bit<2> congestion_tag;
        queue_len_5.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        
        bit<32> queueLen = 0;

        queue_len_10.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 5;
        }

        queue_len_15.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 15;
        }
        
        queue_len_20.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 20;
        }
        
        queue_len_25.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 25;
        }
        
        queue_len_30.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 30;
        }
        
        queue_len_35.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 35;
        }
        
        queue_len_40.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 40;
        }

        @atomic {
            bit<32> oldQueueLen = 0;
            estimated_queue_len_v2.read(oldQueueLen, (bit<32>) std_meta.egress_port);
            if(oldQueueLen > queueLen) {
                queueLen = oldQueueLen;
            }
            estimated_queue_len_v2.write((bit<32>) std_meta.egress_port, queueLen);
        }
        
    }

    
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
        hdr.ipv4.ttl = 5;
        hdr.ipv4.protocol   = hdr.rexford_ipv4.protocol;

        hdr.ipv4.src_network      = 0x0A00;
        hdr.ipv4.src_rexford_addr = (bit<8>) hdr.rexford_ipv4.srcAddr;
        // TODO: This is an awful hack. We should either use tables or use 5 bit as addresses or so.
        if (hdr.ipv4.src_rexford_addr == 0) {
            hdr.ipv4.src_rexford_addr = 16;
        }
        hdr.ipv4.src_host_num      = 0x1;
        
        hdr.ipv4.dst_network      = 0x0A00;
        hdr.ipv4.dst_rexford_addr = (bit<8>) hdr.rexford_ipv4.dstAddr;
        // TODO: This is an awful hack. We should either use tables or use 5 bit as addresses or so.
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
            hdr.heartbeat.etherType = 0x1235;
            log_msg("HB Egress: port {} f {} r {} cloned {}",{hdr.heartbeat.port, hdr.heartbeat.failed_link, hdr.heartbeat.recovered_link, std_meta.instance_type});
            port_bytes_out.count((bit<32>) std_meta.egress_port);
        } else {
            port_bytes_out.count((bit<32>) std_meta.egress_port);
            estimate_queue_len_v2();
        }   
    }
}