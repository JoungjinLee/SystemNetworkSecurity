all: bin

bin: nfqnl_test.o
	g++ -g -o bin nfqnl_test.o

nfqnl_test.c:
	g++ -g -c -o nfqnl_test.o nfqnl_test.c

clean:
	rm -f bin
	rm -f *.o
