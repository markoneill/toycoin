CC = gcc

CFLAGS=-g -w -Wall
 
EXEC = node
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = 
LIBS = -lcrypto

all: $(EXEC)

$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
%.o: %.c
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $@
 
clean:
	rm -f $(EXEC) $(OBJECTS)
