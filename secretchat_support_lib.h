#ifndef _SECRETCHAT_SUPPORT_LIB_H_
#define _SECRETCHAT_SUPPORT_LIB_H_

#include <stdio.h>
#include <openssl/dh.h>

#define FIELD_SEPARATOR 32
#define HELO_MSG1 1
#define HELO_MSG2 2
#define CHAT_MSG 3

int prepare_and_sign_hello(
	char* mail1,
	unsigned int length1,
	char *mail2,
	unsigned int length2,
	int nonce,
	unsigned char* pubkey,
	unsigned int publen,
	unsigned char** hello_buf,
	unsigned int* hello_len,
	unsigned char** sign_buf,
	unsigned int* sign_len);
	
unsigned char* prepare_cert(FILE* fp,unsigned int* cert_len);

int encrypt_msg(int sk,
	char format,
	unsigned char* plain,
	unsigned int plain_len,
	unsigned char* shared_secret);
	
int decrypt_msg(int sk,
	char format,
	unsigned char** plain,
	unsigned char* shared_secret);
	
int send_hello(
	int sk,
	unsigned char* hello,
	unsigned int hello_len,
        unsigned char* sign,
        unsigned int sign_len,
        unsigned char* cert,
        unsigned int cert_len);
        
int recv_hello(
	int sk,
	unsigned char** hello,
	unsigned int* hello_len,
	unsigned char** sign,
	unsigned int *sign_len,
	unsigned char** cert, unsigned int* cert_len);
	
DH* dh_genkey();
#endif
