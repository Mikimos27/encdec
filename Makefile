CXX=g++
CXXFLAGS=-g -Wall -Werror -O2 -lcrypto -std=c++23

all: crypto

#rsa.o: rsa/rsa.h rsa/rsa.cpp rsa/rsa_PRVMAN.cpp rsa/rsa_PUBMAN.cpp rsa/rsa_crypto.cpp
#	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp

%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $@ $^

crypt.o: crypt.cpp
	$(CXX) $(CXXFLAGS) -c $^

crypto: ./*.o
	$(CXX) $(CXXFLAGS) -o $@ $^


mem: ./*.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -fsanitize=address -fsanitize=bounds



.PHONY: clean

clean:
	rm *.o
