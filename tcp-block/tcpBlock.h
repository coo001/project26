#pragma once
#include <pcap.h>
#include <string.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#pragma pack(push, 1)
struct TcpPacket final {
  EthHdr ethHdr_;
  IpHdr ipHdr_;
  TcpHdr tcpHdr_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TcpBlock final {
  pcap_t* handle_;
  Mac attacker_mac_;
  //
  // constructor
  //
  TcpBlock(pcap_t* handle, Mac attacker_mac) { handle_ = handle, attacker_mac_ = attacker_mac; }

  //
  // int get_mac_by_interface(const char* ifname, uint8_t* mac_addr);
  int send_forward_rst(TcpPacket* org_packet);
  int send_backward_fin(TcpPacket* org_packet, std::string data);
};
#pragma pack(pop)