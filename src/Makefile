COMPILER = g++
CFLAGS = -c -Wall -I ../include

SRC=$(wildcard *.cc)
OBJ=$(patsubst %.cc,%.o, $(SRC))

.SUFFIXES:

all: $(OBJ)

%.o: %.cc
	$(COMPILER) $(CFLAGS) -Wall $< -o $@

clean:
	-rm -f *.o
