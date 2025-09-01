CXX=g++
CXXFLAGS=-g -Wall -Werror -O2 -lcrypto

all: crypto.elf 

#rsa.o: rsa/rsa.h rsa/rsa.cpp rsa/rsa_PRVMAN.cpp rsa/rsa_PUBMAN.cpp rsa/rsa_crypto.cpp
#	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp

rsa.o: rsa/*
	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp

aes.o: aes/aes.h aes/aes.cpp
	$(CXX) $(CXXFLAGS) -c $^

dh.o: dh/dh.h dh/dh.cpp
	$(CXX) $(CXXFLAGS) -c $^

crypt.o: crypt.cpp
	$(CXX) $(CXXFLAGS) -c $^

crypto.elf: rsa.o aes.o dh.o crypt.o
	$(CXX) $(CXXFLAGS) -o $@ $^


mem.elf: rsa.o aes.o dh.o crypt.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -fsanitize=address -fsanitize=bounds



.PHONY: clean

clean:
	rm *.o
