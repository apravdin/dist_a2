COMPILER = g++
CFLAGS = -c -Wall -I ../include -Wno-write-strings

SRC=$(wildcard *.cc)
OBJ=$(patsubst %.cc,%.o, $(SRC))

.SUFFIXES:

all: $(OBJ)

%.o: %.cc
	$(COMPILER) $(CFLAGS) -Wall $< -o $@

clean:
	-rm -f *.o
