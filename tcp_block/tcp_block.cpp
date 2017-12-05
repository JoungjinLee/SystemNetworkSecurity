#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mutex>
#include <thread>
#include <queue>

void error(const char *message) {
    fprintf(stderr, "\x1b[31mError\x1b[0m : %s\n", message);
    exit(-1);
}

struct pcap_pkthdr* header;
const u_char *packet;
int idx = 0;

inline int load(pcap_t *h) {
    int res;
    while(!(res = pcap_next_ex(h, &header, &packet))) { }
    idx = 0;
    return res > 0;
}


std::queue<std::mutex> thq;
std::queue<const u_char *> pkq;

std::mutex thmtx;
std::mutex pkmtx;



const u_char *getpkt() {
	pkmtx.lock();
	const u_char *tr = pkq.front();
	pkmtx.unlock();
	return tr;
}

void thread() {
	printf("CREATE NEW THREAD\n");
	std::mutex mtx;
	const u_char *packet;
	u_char *ts[1600];
	while(true) {
		mtx.lock();
		packet = getpkt();
		
		if (*(uint16_t *)(packet + 12) != 0x0008) {
			thq.push(mtx);
			continue;
		}

		uint8_t ihl = (packet[14] & 0xf) << 2;
		if (packet[23] != 0x06) {
			thq.push(mtx);
			continue;
		}

		printf("TCP packet detected\n");
	}
}

int main(int argc, char *argv[]) {
   if (argc < 2) {
       error("Not enough arguments");
   } 

   char *dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

   if (handle == NULL) {	   
      error("Could not open device");
   }
   uint8_t ihl;
   uint8_t thl;

   while(true) {
	if (!load(handle)) break;
	pkmtx.lock();
	thmtx.lock();
	if (pkq.empty()) {
		std::thread nt(thread);
	}
	pkq.push(packet);
	std::mutex m = thq.front();
	thq.pop();
	m.unlock();
	pkmtx.unlock();
	thmtx.unlock();
   }

   pcap_close(handle);

   return 0;
}



