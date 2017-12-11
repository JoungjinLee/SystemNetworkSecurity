#include "ssl_web_proxy.h"


char reply[] = "HTTP/1.1 200 Connection estabilshed\r\n\r\n";

std::mutex cntmtx;

int concnt = 0;
void updateCNT(int v) {
	cntmtx.lock();
	concnt += v;
	cntmtx.unlock();
}



void *sock_client(void *data) {
	updateCNT(1);	

	printf("ESTABLISHED :: %d connections\n", concnt);
	int client = *(int *)data;
	char buffer[2017];
	char host[200];
	int idx = 0;
	while(1) {
		int readed = recv(client, buffer + idx, 1990 - idx, 0);
		if (readed <= 0) {
			close(client);
			return NULL;
		}
		idx += readed;
		if (*(unsigned int *)(buffer + idx - 4) == htonl(0x0d0a0d0a)) break;
	}

	printf("CONNECTION MESSAGE : \n");
	print(buffer, idx);
	
	if (memcmp(buffer, "CONNECT ", 8)) {
		close(client);
		return NULL;
	}

	idx = 7;

	while(buffer[idx] == ' ' || buffer[idx] == '\t') idx++;

	for (int i = 0 ; i < 200 ; i++) {
		if (i > 195) {
			close(client);
			return NULL;
		}
		if (buffer[idx] == ' ' || buffer[idx] == '\t' || buffer[idx] == ':' || buffer[idx] == '\x0d') {
			host[i] = '\0';
			break;
		} else {
			host[i] = buffer[idx];
		}
		idx++;
	}

	send(client, reply, strlen(reply), 0);

	SSL_CTX *cctx = load_server_context(host);
	SSL *cssl = SSL_new(cctx);
	SSL_set_fd(cssl, client);

	int con = create_client(host, 443);
	SSL_CTX *sctx = load_client_context();
	SSL *sssl = SSL_new(sctx);
	SSL_set_fd(sssl, con);

	if (SSL_accept(cssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}

	if (SSL_connect(sssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	
	while(1) {
		printf("\n\nCLIENT SENT\n");
		int cl;
		while(1) {
			int read = SSL_read(cssl, buffer, 2000);
			if (read <= 0) {cl = 1; break;}
			SSL_write(sssl, buffer, read);
			print(buffer, read);
			if (*(unsigned int *)(buffer + read - 4) == htonl(0x0d0a0d0a)) break;
		}
		if (cl) break;
		printf("\n\nSERVER SENT\n");

		int totlen = 0;

		while(1) {
			int i;
			int isbing = 0;
			if (memcmp(host, "api.bing.com", 12) == 0) {
				printf("[[[BING DETECTED]]]\n");
				isbing = 1;
			}
			if (isbing) {
				for (i = 0 ; i < 200 ; i++) {
					readssl(sssl, buffer, 1);
					printf("%02X(", buffer[0]);
					print(buffer, 1);
					printf(")|");
				}
			}

			for (i = 0 ; *(uint16_t*)(buffer + i - 2) != htons(0x0d0a) && i < 1900 ; i++) {
				if (readssl(sssl, buffer + i, 1) < 0) {
					cl = 1;
					break;
				}
			}

			if (cl) break;

			SSL_write(cssl, buffer, i);
			print(buffer, i);

			if (memcmp(buffer, "\r\n", 2) == 0) {
				break;
			}
			if (memcmp(buffer, "Content-Length: ", 16) == 0) {
				totlen = atoi(buffer + 16);
			}

			if (memcmp(buffer, "Transfer-Encoding: chunked", 26) == 0) {
				totlen = -1;
			}
		}

		if (totlen < 0) {
			while(1) {
				int i;
				for (i = 0 ; *(uint16_t *)(buffer + i - 2) != htons(0x0d0a) ; i++) {
					if (readssl(sssl, buffer + i, 1) < 0) {
						cl = 1;
						break;
					}
				}


				if (cl) break;

				SSL_write(cssl, buffer, i);
				print(buffer, i);

				int len = strtol(buffer, NULL, 16);
				if (len <= 0) {
					if (readssl(sssl, buffer, 2) < 0) {cl = 1;}
					if (cl) break;
					SSL_write(sssl, buffer, 2);
					print(buffer, 2);
					break;
				}

				while(len > 0) {
					int read = SSL_read(sssl, buffer, std::min(len, 2000));
					if (read <= 0) {cl = 1; break;}
					SSL_write(cssl, buffer, read);
					print(buffer, read);
					len -= read;
				}

				if (readssl(sssl, buffer, 2) < 0) {cl = 1; break;}
				if (cl) break;
				SSL_write(sssl, buffer, 2);
				print(buffer, 2);

			}
		} else {
			while(totlen > 0) {
				int read = SSL_read(sssl, buffer, std::min(totlen, 2000));
				if (read <= 0) {cl = 1; break;}
				SSL_write(cssl, buffer, read);
				print(buffer, read);
				totlen -= read;
			}
		}
		if (cl) break;
	}

	SSL_free(cssl);
	SSL_free(sssl);
	close(client);
	close(con);
	updateCNT(-1);
	printf("CLOSED :: %d connections\n", concnt);
}

int main(int argc, char *argv[]) {
	init_openssl();
	
	int sock = create_server(4433);

	while(1) {
		struct sockaddr_in addr;
		uint len = sizeof(addr);

		int client = accept(sock, (struct sockaddr *)&addr, &len);
		pthread_t t;
		pthread_create(&t, NULL, sock_client, (void *)&client);
	}
	
	cleanup_openssl();
	return 0;
}
























	
