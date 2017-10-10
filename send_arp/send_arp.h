#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

struct packet_ARP {
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

void error(const char *);
void assert(int, const char *);
void getMacAddr(uint8_t *, const char *);
void getIpAddr(uint8_t *, const char *);
void printMac(uint8_t *);
void printIp(uint8_t *);
