all: bin

bin : pcap_test.o
	g++ -g -o bin pcap_test.o -lpcap

pcap_test.cpp:
	g++ -g -c -o pcap_test.o pcap_test.cpp

clean:
	rm -f bin
	rm -f *.o
