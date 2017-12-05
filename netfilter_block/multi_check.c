#include "multi_block.h"

struct Link {
	struct Node *link;
	struct Node *next;
};


struct Node {
	int outlink;
	int len;
	char *str;
	struct Link link;
};

void init(struct Node **h) {
	*h = (struct Node *)malloc(sizeof(struct Node));
	h->outlink = 0;
	h->len = 0;
	h->str = NULL;
	h->link = NULL;
}

void update(struct Node **h, char *target) {
	int len = strlen(target);
	struct Node *c = *h;
	int idx = 0;
	while() {
		while(h->
	}
}

void load(struct Node **h, char *list[], int cnt) {
	for (int i = 0 ; i < cnt ; i++) {

	}
}
