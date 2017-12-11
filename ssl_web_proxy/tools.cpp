#include "ssl_web_proxy.h"

int create_server(int port) {
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

	if (listen(s, 10) < 0) {
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

SSL_CTX *load_client_context() {
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
	if (access(pem, 0) < 0) {
		sprintf(buffer, "cd cert && ./_make_site.sh %s && cp %s.pem ../certs/ && cp %s.key ../certs/%s.key", s, s, s, s);
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

	return ctx;
}


std::map<std::string, SSL_CTX *> keymap;
std::mutex mtx;

SSL_CTX *load_server_context(const char *s) {
	std::string str = s;

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
		int readed = recv(s, buf + pos, std::min(len, 100), 0);
		if (readed > 0) {
			len -= readed;
			pos += readed;
		} else if (readed == 0) {
			return -1;
		}
	}
	return 0;
}

int readssl(SSL *ssl, char *buf, int len) {
	int pos = 0;
	int t = len;
	while(len) {
		int readed = SSL_read(ssl, buf + pos, std::min(len, 100));
		if (readed > 0) {
			len -= readed;
			pos += readed;
		} else if (readed == 0) {
			return -1;
		}
	}
	return 0;
}

void print(const char *buf, int len) {
	for (int i = 0 ; i < len ; i++) {
		char t = buf[i];
		if (' ' <= t && t <= '~') printf("%c", t);
		else if (t == '\n') printf("\n");
		else if (t == '\r'); 
		else printf(".");
	}
}















	
