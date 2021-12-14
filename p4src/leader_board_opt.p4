/*
 * Since we know we never meed that reception rate SLAs (even though its close) 
 * for that traffic we, might just drop it. If we drop it we have less traffic
 * and higher chances of also meeting the delay SLAs.
 */
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