CXX = g++
CFLAGS = -c -Wall -I ../include

SRC=$(wildcard *.cc)

OBJ=$(patsubst %.cc,%.o, $(SRC))

all: $(OBJ)

%.o: %.cc
	$(CXX) $(CFLAGS) $< -o $@

clean:
	-rm -f $(OBJ)
