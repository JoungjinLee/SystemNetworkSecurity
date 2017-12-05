#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <map>
#include <mutex>
#include <thread>

using namespace std;

int create_socket(int port) {
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	return s;
}

int create_client(const char *hostname, int port) {
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;
	struct hostent *host;

	if ( (host = gethostbyname(hostname)) == NULL) {
		perror(hostname);
		exit(EXIT_FAILURE);
	}

	addr.sin_addr.s_addr = *(long *)(host->h_addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Unable to connect");
		exit(EXIT_FAILURE);
	}

	return s;
}

void init_openssl() {
	system("cd cert && sudo ./_init_site.sh > dummy");
	system("mkdir certs > dummy");
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
}

SSL_CTX *create_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();
	
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL_context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

SSL_CTX *client_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_client_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL_context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

SSL_CTX *generate_context(const char *s) {
	char buffer[1000];
	char pem[300];
	char key[300];

	SSL_CTX *ctx = create_context();
	
	SSL_CTX_set_ecdh_auto(ctx, 1);
	
	sprintf(pem, "certs/%s.pem", s);
	sprintf(key, "certs/%s.key", s);
	if (access(buffer, 0) < 0) {
		sprintf(buffer, "cd cert && ./_make_site.sh %s > dummy && cp %s.pem ../certs/ && cp %s.key ../certs/%s.key", s, s, s, s);
		system(buffer);
	}
	
	if (SSL_CTX_use_certificate_file(ctx, pem, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("GEN DONE\n");

	return ctx;
}

map<string, SSL_CTX *> keymap;

mutex mtx;

SSL_CTX *load_context(const char *s) {
	string str = s;

	mtx.lock();

	if (keymap.count(str)) {
		mtx.unlock();

		SSL_CTX *tr = keymap[str];
		
		while(tr == NULL) {
			sleep(1);
			tr = keymap[str];
		}
		return tr;
	}

	keymap[str] = NULL;
	mtx.unlock();

	return (keymap[str] = generate_context(s));
}

int readn(int s, char *buf, int len) {
	int pos = 0;
	int t = len;
	while(len) {
		int readed = recv(s, buf + pos, min(len, 100), 0);
		if (readed > 0) {
			len -= readed;
			pos += readed;
		} else if (readed == 0) {
			return -1;
		}
	}
	return 0;
}

char reply[] = "HTTP/1.1 200 Connection estabilshed\r\n\r\n";

void print(char *, int);

void *sock_client(void *data) {
	printf("ESTABLISHED\n");
	int client = *(int *)data;
	char buffer[2000];
	char host[200];
	int idx = 0;
	while(1) {
		int readed = recv(client, buffer + idx, 1990 - idx, 0);
		if (readed <= 0) {
			close(client);
			return NULL;
		}
		idx += readed;
		//printf("%X\n", *(unsigned int *)(buffer + idx - 4));
		if (*(unsigned int *)(buffer + idx - 4) == htonl(0x0d0a0d0a)) break;
	}
	
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

	SSL_CTX *cctx = load_context(host);
	SSL *cssl = SSL_new(cctx);
	SSL_set_fd(cssl, client);

	int con = create_client(host, 443);
	SSL_CTX *sctx = client_context();
	SSL *sssl = SSL_new(sctx);
	SSL_set_fd(sssl, con);

	if (SSL_accept(cssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}

	if (SSL_connect(sssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}

	//	SSL_write(ssl, "HELLO!\n", 7);
	//	SSL_read(ssl, buffer, len);
	
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

		int st = 0;
		int datlen = SSL_read(sssl, buffer, 2000);
		if (datlen <= 0) break;
		SSL_write(cssl, buffer, datlen);
		int totlen = -1;
		while(1) {
			if (*(uint16_t *)(buffer + st) == htons(0x0d0a)) break;
			if (memcmp(buffer + st, "Content-Length: ", 16) == 0) {
				totlen = atoi(buffer + st + 16);	
			}
			while(*(uint16_t *)(buffer + st) != htons(0x0d0a)) st++;
			st += 2;
		}

		int remain = totlen - (datlen - st - 2);
		while(remain > 0) {
			int read = SSL_read(sssl, buffer, min(remain, 2000));
			if (read <= 0) {cl = 1; break;}
			SSL_write(cssl, buffer, read);
			print(buffer, read);
			remain -= read;
		}
		if (cl) break;
	}

	SSL_free(cssl);
	SSL_free(sssl);
	close(client);
	close(con);
	printf("CLOSED\n");
}

void print(char *buf, int len) {
	for (int i = 0 ; i < len ; i++) {
		char t = buf[i];
		if (' ' <= t && t <= '~') printf("%c", t);
		else if (t == '\n') printf("\n");
		else if (t == '\r'); 
		else printf(".");
	}
}


int main(int argc, char *argv[]) {
	init_openssl();
	
	int sock = create_socket(4433);

	while(1) {
		struct sockaddr_in addr;
		uint len = sizeof(addr);

		int client = accept(sock, (struct sockaddr *)&addr, &len);
		pthread_t t;
		pthread_create(&t, NULL, sock_client, (void *)&client);
	}
}
























	
