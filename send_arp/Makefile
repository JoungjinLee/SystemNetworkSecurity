all: bin

bin : send_arp.o main.o
	g++ -g -o bin send_arp.o main.o -lpcap

send_arp.cpp:
	g++ -g -c -o send_arp.o send_arp.cpp

main.cpp:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f bin
	rm -f *.o
