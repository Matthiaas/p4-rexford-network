/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/




// TODO: What about the default: accepts??
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t std_meta) {

    // 1 is enough because there can only be on host per switch.
    value_set<host_port_t>(1) host_port;

    state start {
        transition select(std_meta.ingress_port) {
            host_port: parse_host_traffic;
            default: parse_internal_traffic;
        }
    }

    state parse_host_traffic {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            // Packets without ethernet look exactly like internal packages.
            TYPE_IPV4: parse_internal_traffic;
            default: accept;
        }
    }

    state parse_internal_traffic {
        packet.extract(hdr.rexford);
        transition select(hdr.rexford.version) {
            IPV4_VERSION: parse_rexford_ipv4;
            HEARTBEAT_VERSION: parse_hearth_beat;
            default: accept;
        }
    }

    state parse_rexford_ipv4 {
        packet.extract(hdr.rexford_ipv4);
        transition accept;
    }

    state parse_hearth_beat {
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // The ethernet part of the packet will not be valid for internal 
        // traffic.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.rexford);
        packet.emit(hdr.rexford_ipv4);
     }
}