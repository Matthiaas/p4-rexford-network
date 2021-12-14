/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
  apply { 
    verify_checksum(
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
    verify_checksum(
      hdr.rexford_ipv4.isValid(),
      {
        hdr.rexford_ipv4.version,
        hdr.rexford_ipv4.ihl,
        hdr.rexford_ipv4.dscp,
        hdr.rexford_ipv4.ecn,
        hdr.rexford_ipv4.totalLen,
        hdr.rexford_ipv4.flags,
        hdr.rexford_ipv4.protocol,
        hdr.rexford_ipv4.srcAddr,
        hdr.rexford_ipv4.dstAddr,
        hdr.rexford_ipv4.original_dstAddr,
        hdr.rexford_ipv4.rlfa_protected,
        hdr.rexford_ipv4.etherType
      },
      hdr.rexford_ipv4.hdrChecksum,
    HashAlgorithm.csum16);
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
    update_checksum(
      hdr.rexford_ipv4.isValid(),
      {
        hdr.rexford_ipv4.version,
        hdr.rexford_ipv4.ihl,
        hdr.rexford_ipv4.dscp,
        hdr.rexford_ipv4.ecn,
        hdr.rexford_ipv4.totalLen,
        hdr.rexford_ipv4.flags,
        hdr.rexford_ipv4.protocol,
        hdr.rexford_ipv4.srcAddr,
        hdr.rexford_ipv4.dstAddr,
        hdr.rexford_ipv4.original_dstAddr,
        hdr.rexford_ipv4.rlfa_protected,
        hdr.rexford_ipv4.etherType
      },
      hdr.rexford_ipv4.hdrChecksum,
      HashAlgorithm.csum16);
  }
}
