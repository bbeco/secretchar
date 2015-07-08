#ifndef _VERIFY_LIB_SECRETCHAT_H_
#define _VERIFY_LIB_SECRETCHAT_H_

#include <openssl/x509.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/pem.h>

#define DIM_MAIL 255

int get_common_name(char* dest, const char* src);
char* read_common_name(FILE* fp);
int verify_name(
	FILE* fp,
	unsigned char *hello_buf,
	unsigned int hello_len,
	unsigned char *sign_buf,
	unsigned int sign_len,
	unsigned char** pub_buf,
	unsigned int *pubbuf_len,
	X509_STORE* str,
	int* nonce,
	int init);

#endif
