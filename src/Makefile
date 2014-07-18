COMPILER = g++
ARCHIVER = ar
CFLAGS = -c -Wall -I ../include -Wno-write-strings

SRC=$(wildcard *.cc)
OBJ=$(patsubst %.cc,%.o, $(SRC))

.SUFFIXES:

all: $(OBJ) librpc

%.o: %.cc
	$(COMPILER) $(CFLAGS) -Wall $< -o $@

librpc: rpc.o
	$(ARCHIVER) rcs ../librpc.a rpc.o

clean:
	-rm -f *.o *.a
