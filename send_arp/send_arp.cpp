#include "send_arp.h"

void getMacAddr(uint8_t *mac, const char *inf) {
	int s;
	struct ifreq ifr;
	assert((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0, "Failed to open socket in getMacAddr");

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inf);

	assert(ioctl(s, SIOCGIFHWADDR, &ifr) >= 0, "Failed to get Mac Address in getMacAddr");
	close(s);

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(*mac));
}

void getIpAddr(uint8_t *ip, const char *inf) {
	int s;
	struct ifreq ifr;
	assert((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0, "Failed to open socket in getIpAddr");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inf);

	assert(ioctl(s, SIOCGIFADDR, &ifr) >= 0, "Failed to get IP Address in getIpAddr");
	close(s);

	memcpy(ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4 * sizeof(*ip));
}

void printMac(uint8_t *p) {
	for (int i = 0 ; i < 6 ; i++) {
		if(i) printf(":");
		printf("%02X", p[i]);
	}
}

void printIp(uint8_t *p) {
	for (int i = 0 ; i < 4 ; i++) {
		if(i) printf(".");
		printf("%d", p[i]);
	}
}



