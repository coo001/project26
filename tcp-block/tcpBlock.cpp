#include "tcpBlock.h"

int TcpBlock::send_forward_rst(TcpPacket* org_packet) {
  //? Block Packet
  uint32_t ethHdr_hdr_len = sizeof(EthHdr);
  uint32_t org_ipHdr_hdr_len = (uint32_t)org_packet->ipHdr_.hdr_len() << 2;
  uint32_t org_tcpHdr_hdr_len = (uint32_t)org_packet->tcpHdr_.off() << 2;
  TcpPacket* block_packet = (TcpPacket*)malloc(ethHdr_hdr_len + org_ipHdr_hdr_len + org_tcpHdr_hdr_len);  // TODO Free!!!
  memcpy(block_packet, org_packet, ethHdr_hdr_len + org_ipHdr_hdr_len + org_tcpHdr_hdr_len);

  //? TCP
  uint32_t org_seq = org_packet->tcpHdr_.seq();
  uint32_t tcp_data_len = (uint32_t)org_packet->ipHdr_.len() - org_ipHdr_hdr_len - org_tcpHdr_hdr_len;
  block_packet->tcpHdr_.seq_ = htonl(org_seq + tcp_data_len);
  block_packet->tcpHdr_.off_rsvd_ = sizeof(TcpHdr) << 2;  // (header_len>>2)<<4
  block_packet->tcpHdr_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
  block_packet->tcpHdr_.win_ = 0;

  //? IP
  block_packet->ipHdr_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));

  //? Ether
  block_packet->ethHdr_.smac_ = attacker_mac_;

  //? Checksum
  block_packet->ipHdr_.checksum_ = htons(IpHdr::calc_checksum(&block_packet->ipHdr_));
  block_packet->tcpHdr_.checksum_ = htons(TcpHdr::calc_checksum(&block_packet->ipHdr_, &block_packet->tcpHdr_));

  int res = pcap_sendpacket(handle_, (u_char*)block_packet, sizeof(EthHdr) + block_packet->ipHdr_.len());
  free(block_packet);
  return res;
}

int TcpBlock::send_backward_fin(TcpPacket* org_packet, std::string data) {
  //? Block Packet
  uint32_t ethHdr_hdr_len = sizeof(EthHdr);
  uint32_t org_ipHdr_hdr_len = (uint32_t)org_packet->ipHdr_.hdr_len() << 2;
  uint32_t org_tcpHdr_hdr_len = (uint32_t)org_packet->tcpHdr_.off() << 2;
  uint32_t total_hdr_len = ethHdr_hdr_len + org_ipHdr_hdr_len + org_tcpHdr_hdr_len;
  TcpPacket* block_packet = (TcpPacket*)malloc(total_hdr_len + data.size());  // TODO Free !!!
  memcpy(block_packet, org_packet, total_hdr_len);
  memcpy((uint8_t*)block_packet + total_hdr_len, data.c_str(), data.size());

  //? TCP
  uint32_t org_seq = org_packet->tcpHdr_.seq();
  uint32_t org_ack = org_packet->tcpHdr_.ack();
  uint32_t tcp_data_len = (uint32_t)org_packet->ipHdr_.len() - org_ipHdr_hdr_len - org_tcpHdr_hdr_len;
  std::swap(block_packet->tcpHdr_.dport_, block_packet->tcpHdr_.sport_);
  block_packet->tcpHdr_.ack_ = htonl(org_seq + tcp_data_len);
  block_packet->tcpHdr_.seq_ = htonl(org_ack);
  block_packet->tcpHdr_.off_rsvd_ = sizeof(TcpHdr) << 2;  // (header_len>>2)<<4
  block_packet->tcpHdr_.flags_ = TcpHdr::Psh | TcpHdr::Fin | TcpHdr::Ack;

  //? IP
  block_packet->ipHdr_.len_ = htons(uint16_t(sizeof(IpHdr) + sizeof(TcpHdr)) + uint16_t(data.size()));
  block_packet->ipHdr_.ttl_ = 128;
  std::swap(block_packet->ipHdr_.sip_, block_packet->ipHdr_.dip_);

  //? Ether
  block_packet->ethHdr_.smac_ = attacker_mac_;

  //? Checksum
  block_packet->ipHdr_.checksum_ = htons(IpHdr::calc_checksum(&block_packet->ipHdr_));
  block_packet->tcpHdr_.checksum_ = htons(TcpHdr::calc_checksum(&block_packet->ipHdr_, &block_packet->tcpHdr_));

  int res = pcap_sendpacket(handle_, (u_char*)block_packet, sizeof(EthHdr) + block_packet->ipHdr_.len());
  free(block_packet);
  return res;
}