all : bin
clear :
	rm *.o
	rm sum_test

bin : sum.o main.o
	g++ -o bin main.o sum.o

sum.o : sum.h sum.cpp
	g++ -c -o sum.o sum.cpp

main.o : sum.h main.cpp
	g++ -c -o main.o main.cpp
