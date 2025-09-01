CXX = g++
CXXFLAGS = -g -Wall -Werror -O2 -lcrypto -std=c++23#6

SRC = $(wildcard src/*.cpp) 
OBJ = $(SRC:.cpp=.o)
BIN = crypto mem

all: $(BIN)


#rsa.o: rsa/rsa.h rsa/rsa.cpp rsa/rsa_PRVMAN.cpp rsa/rsa_PUBMAN.cpp rsa/rsa_crypto.cpp
#	$(CXX) $(CXXFLAGS) -c rsa/rsa.cpp


%.o: %.cpp ../hdr/%.h hdr/error.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^


mem: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ -fsanitize=address -fsanitize=bounds



.PHONY: clean remake

clean:
	rm -f $(BIN) $(OBJ)

remake: clean $(BIN)
