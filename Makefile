CC = gcc

CFLAGS=-g -w -Wall
LDFLAGS= 
 
EXEC:= node
SRCS:= $(filter-out $(wildcard *.t.c),$(wildcard *.c))
HDRS:= $(wildcard *.h)
OBJS:= $(SRCS:.c=.o)

TEXEC:= test
TSRCS:= $(wildcard *.t.c)
TOBJS:= $(TSRCS:.t.c=.t.o)
TOBJS+= $(filter-out main.o, $(OBJS))

LIBS:= -lcrypto
TLIBS:= -lpthread -lcheck

all: $(EXEC) $(TEXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(TEXEC): $(TOBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS) $(TLIBS)

%.t.o: %.t.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ -x c $<

%.o: %.c $(HDRS) Makefile
	$(CC) -c $(CFLAGS) -o $@ $<
 
clean:
	rm -f $(EXEC) $(TEXEC) $(OBJS) $($TOBJS)
