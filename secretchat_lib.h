#ifndef _SECRETCHAT_H_
#define _SECRETCHAT_H_

#include <openssl/x509.h>
#include <arpa/inet.h>

#define SA struct sockaddr
#define CRL_PEM "crl.pem"

int create_socket(struct sockaddr_in* sa,int port,char *ip);
int accept_connection(unsigned char* hello_buf, unsigned int hello_len, unsigned char* sign_buf, unsigned int sign_len, unsigned char* cert_buf, unsigned int cert_len, int* nonce,int sk,X509_STORE* str, unsigned char** shared_secret, unsigned int* shared_len);
int init_connection(char* buf,int *peer_sk,int mynonce,X509_STORE* str, unsigned char** shared_secret, unsigned int* shared_len);
int decode_incoming_message(int sk,char* in_chat,int *mynonce, X509_STORE* str, unsigned char** shared_secret, unsigned int* shared_len);

#endif
