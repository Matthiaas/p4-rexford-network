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
      ETHER_TYPE_IPV4: parse_ipv4_traffic;
      default: accept;
    }
  }

  state parse_ipv4_traffic {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol){
      TCP_PROTOCOL: parse_tcp;
      UDP_PROTOCOL: parse_udp;
      default: accept;
    }
  }

  state parse_internal_traffic {
    bit<16> ether_type = (bit<16>) packet.lookahead<bit<112>>();
    transition select(ether_type) {
      ETHER_TYPE_INTERNAL: parse_rexford_ipv4;
      ETHER_TYPE_INTERNAL_WAYPOINT: parse_way_pointed_traffic;
      ETHER_TYPE_HEARTBEAT: parse_hearthbeat;
      default: accept;
    }
  }

  state parse_rexford_ipv4 {
    packet.extract(hdr.rexford_ipv4);
    transition select(hdr.rexford_ipv4.protocol){
      TCP_PROTOCOL: parse_tcp;
      UDP_PROTOCOL: parse_udp;
      default: accept;
    }
  }

  state parse_way_pointed_traffic {
    packet.extract(hdr.ethernet);
    packet.extract(hdr.ipv4);
    packet.extract(hdr.waypoint);
    transition select(hdr.ipv4.protocol){
      TCP_PROTOCOL: parse_tcp;
      UDP_PROTOCOL: parse_udp;
      default: accept;
    }
  }

  state parse_udp {
    packet.extract(hdr.udp);
    transition accept;
  }

  state parse_tcp {
    packet.extract(hdr.tcp);
    transition accept;
  }

  state parse_hearthbeat {
    packet.extract(hdr.heartbeat);
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
    packet.emit(hdr.heartbeat);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.waypoint);
    packet.emit(hdr.rexford_ipv4);
    packet.emit(hdr.tcp);
    packet.emit(hdr.udp);
   }
}
