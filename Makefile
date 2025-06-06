CC=gcc
CFLAG_INCLUDE=-I. -Iinclude -Iscripts
CFLAGS=-Wall $(CFLAG_INCLUDE) -Wextra -std=gnu99 -ggdb
LDLIBS=-lcrypto
SRC=src

all: bt

bt: bt.o bencode.o hash.o tracker_functions.o p2p_communication.o
	$(CC) $(CFLAGS) -o bt bt.o bencode.o hash.o tracker_functions.o p2p_communication.o $(LDLIBS)

bt.o: bt.c scripts/headers.h scripts/p2p_communication.o
	$(CC) $(CFLAGS) -c bt.c -o bt.o

bencode.o: bencodeLib/bencode.c bencodeLib/bencode.h bencodeLib/list.h
	$(CC) $(CFLAGS) -c bencodeLib/bencode.c -o bencode.o

hash.o: hashLib/hash.c hashLib/hash.h
	$(CC) $(CFLAGS) -c hashLib/hash.c -o hash.o

tracker_functions.o: scripts/tracker_functions.c scripts/headers.h 
	$(CC) $(CFLAGS) -c scripts/tracker_functions.c -o tracker_functions.o

p2p_communication.o: scripts/p2p_communication.c scripts/headers.h
	$(CC) $(CFLAGS) -c scripts/p2p_communication.c -o p2p_communication.o

clean:
	rm -f *.o bt *~

