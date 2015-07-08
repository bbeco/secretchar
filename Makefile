#Makefile

CC=gcc
LDLIBS=-lcrypto
CPPFLAGS=-g -Wall

all: chat

chat: chat.o dhread.o secretchat_support_lib.o secretchat_lib.o comm.o verify.o

chat.o: secretchat_lib.h secretchat_support_lib.h

secretchat_lib.o: secretchat_support_lib.h verify.h

secretchat_support_lib.o: comm.h dhread.h

clean:
	rm -f *.o
