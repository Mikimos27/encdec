CXX = g++
CXXFLAGS = -g -Wall -Werror -O2 -lcrypto -std=c++23#6

SRC = $(wildcard src/*.cpp) 
OBJ = $(SRC:.cpp=.o)
BIN = test

all: $(OBJ)

test: $(BIN)



%.o: %.cpp ../hdr/%.h hdr/error.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BIN): $(OBJ) tests/test.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^




.PHONY: clean remake

clean:
	rm -f $(BIN) $(OBJ)

remake: clean $(OBJ)
