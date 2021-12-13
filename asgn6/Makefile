CC = clang
CFLAGS = -Wall -Wpedantic -Werror -Wextra -g $(shell pkg-config --cflags gmp)
LFLAGS= $(shell pkg-config --libs gmp)

all: keygen encrypt decrypt

keygen: keygen.o randstate.o numtheory.o rsa.o
	$(CC) -o keygen keygen.o randstate.o numtheory.o rsa.o $(LFLAGS)

encrypt: encrypt.o randstate.o numtheory.o rsa.o
	$(CC) -o encrypt encrypt.o randstate.o numtheory.o rsa.o $(LFLAGS)

decrypt: decrypt.o randstate.o numtheory.o rsa.o
	$(CC) -o decrypt decrypt.o randstate.o numtheory.o rsa.o $(LFLAGS)

keygen.o: keygen.c randstate.c randstate.h numtheory.c numtheory.h rsa.c rsa.h
	$(CC) $(CFLAGS) -c keygen.c randstate.c numtheory.c rsa.c

encrypt.o: encrypt.c randstate.c randstate.h numtheory.c numtheory.h rsa.c rsa.h
	$(CC) $(CFLAGS) -c encrypt.c randstate.c numtheory.c rsa.c

decrypt.o: decrypt.c randstate.c randstate.h numtheory.c numtheory.h rsa.c rsa.h
	$(CC) $(CFLAGS) -c decrypt.c randstate.c numtheory.c rsa.c

clean:
	rm -f keygen encrypt decrypt *.o

format:
	clang-format -i -style=file *.[ch]
