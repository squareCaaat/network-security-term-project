CC= gcc
CFLAGS= -Wall -I/usr/include/x86_64-linux-gnu
LDDIR= /usr/lib/x86_64-linux-gnu
LIBS= -lssl -lcrypto

all: test

test: test.o
	$(CC) $(CFLAGS) -o test $^ -L$(LDDIR) $(LIBS)

test.o: test.c
	$(CC) $(CFLAGS) -c test.c
