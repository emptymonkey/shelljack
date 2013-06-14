CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -pedantic -O3
LDIR = -L../ctty -L../ptrace_do
IDIR = -I../ctty -I../ptrace_do

all: shelljack

shelljack: shelljack.o
	$(CC) $(LDIR) shelljack.o -o shelljack -lctty -lptrace_do
	strip -s shelljack

shelljack.o: shelljack.c
	$(CC) $(IDIR) $(CFLAGS) -c shelljack.c

clean: 
	rm shelljack.o shelljack
