#include "main.h"
using namespace std;

static const string FIN_DATA = "blocked!!!";
static string PATTERN;

void usage() {
  cout << "syntax : tcp-block <interface> <pattern>\n";
  cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
  return;
}

int get_mac_by_interface(const char* ifname, uint8_t* mac_addr) {
  struct ifreq ifr;
  int sockfd, ret;
  /*
   * 네트워크 인터페이스 소켓을 연다.
   */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    printf("Fail to get interface MAC address - socket() failed\n");
    return -1;
  }
  /*
   * 네트워크 인터페이스의 MAC 주소를 확인한다.
   */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  if (ret < 0) {
    printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed\n");
    close(sockfd);
    return -1;
  }
  memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

  /*
   * 네트워크 인터페이스 소켓을 닫는다.
   */
  close(sockfd);

  return 0;
}

int check_packet(TcpPacket* packet) {
  if (packet->ethHdr_.type() != EthHdr::Ip4) return 0;
  // cout << "\n1\n";
  if (packet->ipHdr_.protocol() != IpHdr::Tcp) return 0;
  // cout << "\n2\n";
  string data = string((char*)&packet->ipHdr_, packet->ipHdr_.len());
  if (data.find(PATTERN) == string::npos) return 0;
  return 1;
}

int main(int argc, char* argv[]) {
  int res;
  if (argc != 3) {
    usage();
    return -1;
  }

  //? Get pattern
  PATTERN = string(argv[2]);

  //? Get handle
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);  // reponse time 1000 -> 1
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }

  //? Get attacker's  mac
  uint8_t attacker_mac[Mac::SIZE];
  if (get_mac_by_interface(dev, attacker_mac) < 0) {
    printf("fail to get attacker mac addres\n");
    return -1;
  };

  //? TcpBlock struct
  TcpBlock tcpBlock(handle, Mac(attacker_mac));

  struct pcap_pkthdr* header;
  const u_char* packet;
  while (1) {
    res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;        // 패킷을 얻지 못함
    if (res == -1 || res == -2) {  // 패킷을 더이상 얻지 못하는 상태
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      break;
    }

    //
    TcpPacket* org_packet = (TcpPacket*)packet;
    res = check_packet(org_packet);
    if (res) {
      printf("pattern captured\n");
      tcpBlock.send_forward_rst(org_packet);
      tcpBlock.send_backward_fin(org_packet, FIN_DATA);
    }
  }
  pcap_close(handle);
  return 0;
}