#include "arp_spoof.h"

void error(const char *message) {
	fprintf(stderr, "\x1b[31mError\x1b[0m : %s\n", message);
	exit(-1);
}

void assert(int cond, const char *message) {
	if(!cond) error(message);
}
