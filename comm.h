#ifndef _COMM_LIB_SECRETCHAT_H_
#define _COMM_LIB_SECRETCHAT_H_

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>

int send_msg(int sk, unsigned char* buf, int num_bytes,char format);
int recv_msg(int sk, unsigned char** buf,char* format);

#endif
