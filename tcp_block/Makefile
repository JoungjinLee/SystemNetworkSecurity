all: bin

bin : tcp_block.o
	g++ -g -o bin tcp_block.o -lpcap -pthread

tcp_block.cpp:
	g++ -g -c -o tcp_block.o -std=c++11 tcp_block.cpp

clean:
	rm -f bin
	rm -f *.o
