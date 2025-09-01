CXX=g++
CXXFLAGS=-g -Wall -Werror -O2 -lcrypto -std=c++23

all: crypto

#rsa.o: rsa/rsa.h rsa/rsa.cpp rsa/rsa_PRVMAN.cpp rsa/rsa_PUBMAN.cpp rsa/rsa_crypto.cpp
#	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp

rsa.o: rsa/*
	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp

ed25519.o: ed25519/*
	$(CXX) $(CXXFLAGS) -c ed25519/ed25519.cpp

aes.o: aes/aes.h aes/aes.cpp
	$(CXX) $(CXXFLAGS) -c aes/aes.cpp

dh.o: dh/dh.h dh/dh.cpp
	$(CXX) $(CXXFLAGS) -c dh/dh.cpp

crypt.o: crypt.cpp
	$(CXX) $(CXXFLAGS) -c $^

crypto: rsa.o aes.o dh.o ed25519.o crypt.o
	$(CXX) $(CXXFLAGS) -o $@ $^


mem: rsa.o aes.o dh.o ed25519.o crypt.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -fsanitize=address -fsanitize=bounds



.PHONY: clean

clean:
	rm *.o
