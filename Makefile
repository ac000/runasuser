CC=gcc
CFLAGS=-Wall -std=c99 -O2

runasuser: runasuser.c
	$(CC) $(CFLAGS) -o runasuser runasuser.c

clean:
	rm runasuser
