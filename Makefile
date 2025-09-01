CXX=g++
CXXFLAGS=-Wall -Werror -O2 -lcrypto

all: crypto.elf 

rsa.o: rsa/rsa.h rsa/rsa.cpp
	$(CXX) $(CXXFLAGS) -c $^

aes.o: aes/aes.h aes/aes.cpp
	$(CXX) $(CXXFLAGS) -c $^

crypto.elf: rsa.o aes.o
	$(CXX) $(CXXFLAGS) crypt.cpp -o $@ $^

.PHONY: clean

clean:
	rm *.o
