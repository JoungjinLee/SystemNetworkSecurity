all: bin

bin : ssl_web_proxy.o tools.o
	g++ -o bin ssl_web_proxy.o tools.o -lssl -lcrypto -pthread

ssl_web_proxy.o : ssl_web_proxy.h ssl_web_proxy.cpp
	g++ -c -o ssl_web_proxy.o -std=c++11 ssl_web_proxy.cpp

tools.o : ssl_web_proxy.h tools.cpp
	g++ -c -o tools.o -std=c++11 tools.cpp

#	g++ -o bin ssl_web_proxy.cpp -std=c++11 -lssl -lcrypto -pthread
