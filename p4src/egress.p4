/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {

    counter(MAX_PORTS, CounterType.bytes) port_bytes_out;

    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_5;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_10;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_15;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_20;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_25;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_30;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_35;
    meter((bit<32>) MAX_PORTS, MeterType.bytes) queu_len_40;


    action estimat_queue_len_v2() {
        /*
            This is the Queue Lengt Estimator Version 2.
            It sets up a couple of meters all with the same peak bandwith but different
            burst sizes (= queue lengths). Whenever a meter is hits Red (we are not using
            the color yellow here), we assume that the burst size of this meter equlas the 
            current length of the queue behing our switch.

            This only provides this invariante:
                Meter x hits read ---implies---> Queulength is at least x

            In order to get an even better estimate we only upate the estimated_queue_len_v2
            if the current estimate is smaller than the new one (because of our invariante). 
            To decrease the queulength estimate we decrease the counter whenever we receive 
            a heartbeat from the controller by one for every 1.2ms that have passed.
            The heartbeat frequeny should be a mulpile of 1.2ms to easily achuive this.            
        */
        bit<2> congestion_tag;
        queu_len_5.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        
        bit<32> queueLen = 0;

        queu_len_10.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 5;
        }

        queu_len_15.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 15;
        }
        
        queu_len_20.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 20;
        }
        
        queu_len_25.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 25;
        }
        
        queu_len_30.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 30;
        }
        
        queu_len_35.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
        if(congestion_tag == V1MODEL_METER_COLOR_RED) {
            queueLen = 35;
        }
        
        queu_len_40.execute_meter((bit<32>) std_meta.egress_port, congestion_tag);
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
            estimat_queue_len_v2();
        }   
    }
}