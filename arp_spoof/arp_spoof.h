#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <pcap.h>
#include <pthread.h>
#include <thread>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

struct ARPPacket {
	uint8_t MAC_destin[6];
	uint8_t MAC_source[6];
	uint16_t etherType = 0x0608;
	uint16_t hardwareType = 0x0100;
	uint16_t protocolType = 0x0008;
	uint8_t hwAddrLen = 6;
	uint8_t ptAddrLen = 4;
	uint16_t operation;
	uint8_t hwAddr_source[6];
	uint8_t ptAddr_source[4];
	uint8_t hwAddr_destin[6];
	uint8_t ptAddr_destin[4];
};

struct Address {
	uint8_t MAC[6];
	uint8_t IP[4];
};

struct spoofTarget {
	struct Address sender;
	struct Address target;
};

void error(const char *);
void assert(int, const char *);
void getMacAddr(struct Address *, const char *);
void getIpAddr(struct Address *, const char *);
void printMac(struct Address *);
void printIp(struct Address *);
void getHWaddr(pcap_t *, struct Address *, struct Address *);
void sendARP(pcap_t *, struct spoofTarget *, struct Address *);
int isARP(const u_char *p);
int load(pcap_t *, struct pcap_pkthdr **, const u_char **);
