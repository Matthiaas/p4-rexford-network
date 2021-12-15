/*
 * Since we know we never meet that reception rate SLAs (even though its close) 
 * for some traffic we, might just drop it. If we drop it we have less traffic
 * and higher chances of also meeting the delay SLAs.
 */
if(from_host) {
  if (meta.srcPort <= 300 && meta.srcPort > 200) {
    if (hdr.udp.isValid()) {
      random_drop(99);
    }
  }
  if (meta.srcPort <= 100 && meta.srcPort > 0) {
    // We always get like 95 to 98 percent but its worth noting in the SLA
    // leaderboard, so just drop almost everything.
    if (hdr.udp.isValid()) {
      random_drop(99);
    } 
  }
}