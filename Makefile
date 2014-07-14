CXX = g++

SRC = $(wildcard *.cc)

OBJ=$(wildcard src/*.o)

BIN=$(patsubst %.cc,%.out, $(SRC))

CFLAGS = -c -Wall -I include
LDFLAGS =

.SUFFIXES:

all: clean make_src $(BIN)

make_src:
	make -C src

%.o: %.cc
	$(CXX) $(CFLAGS) $< -o $@

%.out: %.o
	$(CXX) -o $@ $(LDFLAGS) $< $(OBJ)

clean:
	make -C src clean
	-rm -f $(patsubst %.cc, %.o, $(SRC)) $(BIN)
