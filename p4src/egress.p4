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

        }
    }
}