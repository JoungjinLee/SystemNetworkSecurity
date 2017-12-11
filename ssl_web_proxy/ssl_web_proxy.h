#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <map>
#include <mutex>
#include <thread>

int create_server(int);
int create_client(const char *, int);

void init_openssl();
void cleanup_openssl();
SSL_CTX *load_server_context(const char *);
SSL_CTX *load_client_context();

int readn(int, const char *, int);
int readssl(SSL *, char *, int);
void print(const char *, int);


