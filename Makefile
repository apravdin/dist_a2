CXX = g++

SRC = $(wildcard *.cc)

OBJ=$(filter-out src/rpc.o, $(wildcard src/*.o))

BIN=$(patsubst %.cc,%.out, $(SRC))

CFLAGS = -c -Wall -I include -Wno-write-strings
LDFLAGS = -L.

.SUFFIXES:

all: clean make_src $(BIN)

make_src:
	make -C src

%.o: %.cc
	$(CXX) $(CFLAGS) $< -o $@

%.out: %.o
	$(CXX) -o $@ $< $(LDFLAGS) -lrpc -lpthread $(OBJ)

clean:
	make -C src clean
	-rm -f $(patsubst %.cc, %.o, $(SRC)) $(BIN)
