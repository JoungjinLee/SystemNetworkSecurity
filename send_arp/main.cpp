#include "send_arp.h"

char *dev;
char errbuf[1000];
struct pcap_pkthdr* header;
const u_char *packet;

uint8_t MAC_attack[6];
uint8_t MAC_victim[6];
uint8_t MAC_broad[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t IP_attack[4];
uint8_t IP_victim[4];
uint8_t IP_gateway[4];



void error(const char *message) {
	fprintf(stderr, "\x1b[31mError\x1b[0m : %s\n", message);
	exit(-1);
}

void assert(int cond, const char *message) {
	if(!cond) error(message);
}

int load(pcap_t *h) {
    int res;
    while(!(res = pcap_next_ex(h, &header, &packet))) { }
    return res > 0;
}


int main(int argc, char *argv[]) {
	if (argc < 4) {
		error("Not enough arguments : bin (interface) (victim IP) (gateway IP)");
	}

	dev = argv[1];
	assert(inet_aton(argv[2], (in_addr *)IP_victim) > 0, "Parsing victim ip failed");
	assert(inet_aton(argv[3], (in_addr *)IP_gateway)> 0, "Parsing gateway ip failed");;
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	assert(handle != NULL, "Cannot open interface");

	getMacAddr(MAC_attack, dev);
	getIpAddr(IP_attack, dev);
	
	printf("Attacker Information\n");
	printf("  IP Address\t: "); printIp(IP_attack); printf("\n");
	printf("  MAC Address\t: "); printMac(MAC_attack); printf("\n");	
	

	struct packet_ARP arpReq;

	memcpy(arpReq.MAC_source, MAC_attack, 6);
	memcpy(arpReq.MAC_destin, MAC_broad, 6);

	arpReq.operation = htons(1);

	memcpy(arpReq.hwAddr_source, MAC_attack, 6);
	memcpy(arpReq.ptAddr_source, IP_attack, 4);
	memcpy(arpReq.hwAddr_destin, MAC_broad, 6);
	memcpy(arpReq.ptAddr_destin, IP_victim, 4);
	
	struct packet_ARP *arpRecv = &arpReq;

	int timeout = 0;
	while(	!memcmp(arpRecv->MAC_destin, MAC_attack, 6) &&
		htons(arpRecv->etherType) == 0x0806	&&
		htons(arpRecv->operation) == 0x02	&&
		!memcmp(arpRecv->ptAddr_source, IP_victim, 4) &&
		!memcmp(arpRecv->ptAddr_destin, IP_attack, 4) &&
		!memcmp(arpRecv->hwAddr_destin, MAC_attack, 6)) {
		
		if (!timeout--) {
			timeout = 10;
			printf("Packet sent.\n");
			pcap_sendpacket(handle, (u_char *)&arpReq, sizeof(arpReq));
		}
		assert(load(handle), "packet loading failed");
		arpRecv = (struct packet_ARP *)packet;
	}

	printf("gotit!\n");
	printMac(arpRecv->MAC_source);
	printf("\n");
}



