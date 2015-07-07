#Makefile

CC=gcc
LDLIBS=-lcrypto
CPPFLAGS=-g -Wall

all: chat

chat: chat.o dhread.o

chat.o: dhread.h

clean:
	rm -f *.o
