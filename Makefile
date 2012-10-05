CC=gcc
CFLAGS=-Wall -std=c99 -g -O2

runasuser: runasuser.c
	$(CC) $(CFLAGS) -o runasuser runasuser.c

clean:
	rm -f runasuser
