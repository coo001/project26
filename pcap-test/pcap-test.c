#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		//mine libnet_ethernet_hdr
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet+sizeof(*eth_hdr));
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+sizeof(*eth_hdr)+sizeof(*ipv4_hdr));
		uint8_t* data = (uint8_t*)(packet + sizeof(*eth_hdr)+sizeof(*ipv4_hdr)+sizeof(*tcp_hdr));	
		printf("%d\n",eth_hdr->ether_type);
		if(ntohs(eth_hdr -> ether_type) == 8){
			printf("src mac: ");
			for(int i=0;i<ETHER_ADDR_LEN-1; i++){
				printf("%02x:",eth_hdr->ether_shost[i]);
			}
			printf("%02x\n",eth_hdr->ether_shost[ETHER_ADDR_LEN-1]);
			printf("dst mac: ");
			for(int i=0;i<ETHER_ADDR_LEN-1; i++){
				printf("%02x:",eth_hdr->ether_dhost[i]);
			}
			printf("%02x\n",eth_hdr->ether_dhost[ETHER_ADDR_LEN-1]);
			printf("src ip: ");
			ulong k = ipv4_hdr->ip_src.s_addr;
			for(int i=0;i<3;i++){
				printf("%lu.",k%0x100);
				k /= 0x100;		
			}
			printf("%lu\n",k%0x100);
			printf("dst ip: ");
			k = ipv4_hdr->ip_dst.s_addr;
			for(int i=0;i<3;i++){
				printf("%lu.",k%0x100);
				k /= 0x100;		
			}
			printf("%lu\n",k%0x100);
			printf("src port: ");				
		        printf("%d\n",ntohs(tcp_hdr->th_sport));
			printf("dst port: ");
			printf("%d\n",ntohs(tcp_hdr->th_dport));
			printf("hexadecimal value: ");
			if((tcp_hdr->th_off*4)<=40){
				for(int i=0;i<(tcp_hdr->th_off*4)-20;i++)
					printf("%02x ", *(data+(tcp_hdr->th_off*4)-20-i));
			}
			else{
				for(int i=0;i<20;i++)
					printf("%02x ", *(data+19-i));				
			}
			printf("\n\n");
		}
	}

	pcap_close(pcap);
}
