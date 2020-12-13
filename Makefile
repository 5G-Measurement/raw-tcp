CC=gcc
CFLAGS=-I.
DEPS = packet.h
OBJS = packet.o

all: new-sender new-receiver

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

new-sender: new-sender.o $(OBJS) 
	$(CC) -o new-sender new-sender.o $(OBJS)

new-receiver: new-receiver.o $(OBJS) 
	$(CC) -o new-receiver new-receiver.o $(OBJS)

.PHONY: clean

clean:
	rm -f new-sender new-receiver *.o
