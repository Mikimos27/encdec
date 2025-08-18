CXX = g++
CXXFLAGS = -g -Wall -Werror -O2 -lcrypto -std=c++23

SRC = $(wildcard src/*.cpp) 
OBJ = $(SRC:.cpp=.o)
BIN = crypto

all: $(BIN)

#rsa.o: rsa/rsa.h rsa/rsa.cpp rsa/rsa_PRVMAN.cpp rsa/rsa_PUBMAN.cpp rsa/rsa_crypto.cpp
#	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp


%.o: src/%.cpp hdr/%.h
	$(CXX) $(CXXFLAGS) -c $@ $<

crypt.o: crypt.cpp
	$(CXX) $(CXXFLAGS) -c $^


$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^


mem: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ -fsanitize=address -fsanitize=bounds



.PHONY: clean

clean:
	rm -f $(BIN) $(OBJ)
