#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void error(const char *message) {
    fprintf(stderr, "\x1b[31mError\x1b[0m : %s\n", message);
    exit(-1);
}

struct pcap_pkthdr* header;
const u_char *packet;
int idx = 0;

int load(pcap_t *h) {
    int res;
    while(!(res = pcap_next_ex(h, &header, &packet))) { }
    idx = 0;
    return res > 0;
}

int next(uint8_t *p, int n) {
    for (int i = 0 ; i < n ; i++) {
	p[i] = packet[idx++];
    }
}

void skip(int n) {
    idx += n;
}

void readMAC(const char *tag) {
	printf("%s: ", tag);
	for (int i = 0 ; i < 6 ; i++) {
		if (i) printf(":");
		uint8_t b; next(&b, 1);
		printf("%02X", b);
	}
	printf("\n");
}

void readIP(const char *tag) {
	printf("%s: ", tag);
	for (int i = 0 ; i < 4 ; i++) {
		if (i) printf(":");
		uint8_t b; next(&b, 1);
		printf("%3d", b);
	}
	printf("\n");
}

int main(int argc, char *argv[]) {
   if (argc < 2) {
       error("Not enough arguments");
   } 

   char *dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

   if (handle == NULL) {	   
      error("Could not open device");
   }

   while(true) {
	if (!load(handle)) break;

	printf("----------------------------------\n");

	readMAC("\x1b[32mDestination MAC\x1b[0m\t");
	readMAC("\x1b[32mSource MAC\x1b[0m\t");

	uint16_t b; next((uint8_t *)&b, sizeof(b)); b = ntohs(b);

	if (b != 0x0800) continue;

	uint8_t ipsz; next(&ipsz, sizeof(ipsz)); ipsz &= 0xf;

	skip(1);

	uint16_t psz; next((uint8_t *)&psz, sizeof(psz)); psz = ntohs(psz);

	skip(8);
	
	readIP("\x1b[32mSource IP\x1b[0m\t");
	readIP("\x1b[32mDestination IP\x1b[0m\t");

	uint16_t p1; next((uint8_t *)&p1, sizeof(p1)); p1 = ntohs(p1);
	uint16_t p2; next((uint8_t *)&p2, sizeof(p2)); p2 = ntohs(p2);

	if (ipsz > 4) skip((ipsz << 2) - 20);

	printf("\x1b[32mSource port\x1b[0m\t: %5d\n", p1);
	printf("\x1b[32mDestin port\x1b[0m\t: %5d\n", p2);

	skip(8);

	uint8_t sz; next(&sz, sizeof(sz)); sz >>= 4;

	skip(7);

	if (sz > 4) skip((sz << 2) - 20);


	uint16_t tsz = psz - ipsz - sz;
	if (tsz > 16) tsz = 16;

	printf("\x1b[34mPAYLOAD\x1b[0m(%2d BYTES)\n", tsz);

	for (uint16_t i = 0 ; i < tsz ; i++) {
		if (i) printf(" ");
		uint8_t buf; next(&buf, sizeof(buf));
		printf("%02X", buf);
	}
	printf("\n");
   }

   pcap_close(handle);

   return 0;
}



