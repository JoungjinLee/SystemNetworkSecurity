all: bin

bin : arp_spoof.o main.o tools.o
	g++ -g -o bin arp_spoof.o main.o tools.o -lpcap -pthread

arp_spoof.cpp:
	g++ -g -c -o arp_spoof.o arp_spoof.cpp

main.cpp:
	g++ -g -c -o main.o main.cpp

tools.cpp:
	g++ -g -c -o tools.o tools.cpp

clean:
	rm -f bin
	rm -f *.o
