#include <stdio.h>
#include <stdlib.h>

int main(void) {
	char *str = "123f\r\n";

	int r = strtol(str, NULL, 16);

	printf("%d\n", r);
}
