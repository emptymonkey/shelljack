CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3
LDIR = -L../ctty -L../ptrace_do
IDIR = -I../ctty -I../ptrace_do

all: fsh

fsh: fsh.o
	$(CC) $(LDIR) fsh.o -o fsh -lctty -lptrace_do
	strip -s fsh

fsh.o: fsh.c
	$(CC) $(IDIR) $(CFLAGS) -c fsh.c

clean: 
	rm fsh.o fsh
