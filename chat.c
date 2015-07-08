#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
//#include <openssl/bn.h>
//#include <openssl/dh.h>
#include "dhread.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include "secretchat_support_lib.h"
#include "secretchat_lib.h"
#define BACKLOG_SIZE 1

#define DIM_BUF 512

#define AUTO_CERT "cacert.pem"


int main(int argc, char*argv[]) {

	socklen_t len;					/* Length of the client address */
	int sk, peer_sk = 0;						/* Passive socket */
	int optval,nonce = 0;						/* Socket options */
	int my_port;					/* my port */
	fd_set rfds, rfds_copy;					/* array of fd for the select*/
	int nfds;
	int i, ret;
	FILE* fp;
	X509* cert;
	X509_STORE* str;
	X509_CRL* crl;
	short int num_byte;
	char buf[DIM_BUF];
	char in_chat = 0;
	struct sockaddr_in my_addr, peer_addr;		/* mine and peer's addresses */
	unsigned char *shared_secret = NULL;	/* The session key */
	unsigned int shared_len;	/* The session key length */
	if((fp=fopen(AUTO_CERT,"r"))==NULL){
		printf("Cannot open the TTP certificate\n");
		return 1;
	}
	if (argc!=2) {
	printf ("Error inserting parameters. Usage: \n\t %s (port) \n\n", argv[0]);
	return 1;
	}
	if((str=X509_STORE_new())==NULL){
		printf("error on creating store for certificate\n");
		return 1;
	}
	if((cert=PEM_read_X509(fp,NULL,NULL,NULL))==NULL){
		printf("Cannot read TTP certificate\n");
		return 1;
	}
	if(fclose(fp)!=0){
		perror("error on close fp\n");
		return 1;
	}
	if((fp=fopen(CRL_PEM,"r"))==NULL){
		perror("error on open crl\n");
		return 1;
	}
	if((crl=PEM_read_X509_CRL(fp,NULL,NULL,NULL))==NULL){
		fprintf(stderr,"error on read crl\n");
		return 1;
	}
	if(X509_STORE_add_cert(str,cert)!=1){
		printf("Error on adding TTP certificate on the store\n");
		return 1;
	}
	if(X509_STORE_add_crl(str,crl)!=1){
		fprintf(stderr,"Error on adding crl to the certificate store\n");
		return 1;
	}
	X509_STORE_set_flags(str,X509_V_FLAG_CRL_CHECK);
	if(fclose(fp)!=0){
		perror("error on close fp\n");
		return 1;
	}
	FD_ZERO(&rfds);				/* initialize fd_set */
	FD_SET(0,&rfds);			/* wait for stadndard input */
	nfds = 1;
	my_port = atoi(argv[1]);
	if((sk=create_socket(&my_addr,my_port,NULL)) == -1){
		perror("Error on creating socket\n");
		return 1; 
	}else if(sk == -2){
		perror("Bad port or ip\n");
		return 1;
	}
	optval = 1;
	ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if(ret == -1) {
		printf("\nError setting SO_REUSEADDR\n");
		return 1;
	}
	ret = bind(sk, (SA *) &my_addr, sizeof(my_addr));
	if(ret == -1) {
		printf("\nError binding the socket\n");
		return 1;
	}
	/* Creation of backlog queue */
	ret = listen(sk, BACKLOG_SIZE);
	if(ret == -1) {
		printf("\nError creating the backlog queue, size %d\n", BACKLOG_SIZE);
		return 1;
	}
	
	printf("Waiting for connections ...\n");
	FD_SET(sk,&rfds);
	nfds = sk+1;
	for(;;){
		printf("%c ", in_chat==0? '#':'>');
		fflush(NULL);
		rfds_copy = rfds;
		if( select(nfds,&rfds_copy,NULL,NULL,NULL) == -1 ){
			perror("select error\n");
			return -1;
		}
		for (i=0; i < nfds;i++){
			if(FD_ISSET(i,&rfds_copy)){
				if(i == sk){
					printf("tentativo di connessione\n");
					len = sizeof(SA);
					if((peer_sk = accept(sk, (SA*)&peer_addr,&len))==-1){
						perror ("error on accept\n");
						return -1;
					}
					FD_SET(peer_sk,&rfds);
					if (peer_sk >= nfds){
						nfds = peer_sk+1;
					}
					//in_chat = 1;
				}	
				else if (i == 0){
					num_byte = read(0,buf,DIM_BUF);
					if (in_chat == 0){
						if(buf[0] == '!'){
							switch (buf[1]){
							case 'c':
								ret = init_connection(&buf[2],&peer_sk,nonce,str, &shared_secret, &shared_len);
								if(ret == 0){
									fprintf(stderr,"Client disconnected\nAborting connection!\n");
									goto close;
								}
								if(ret == -1){
									fprintf(stderr, "Generic error\nAborting connection!\n");
									goto close;
								}
								if (ret == -2) {
									fprintf(stderr, "Unexpected message format.\nConnection aborted\n");
									goto close;
								}
								if( ret == -3) {
									fprintf(stderr, "Mismatching in data.\nConnection aborted\n");
									goto close;
								}
								FD_SET(peer_sk,&rfds);
								if (peer_sk >= nfds){
									nfds = peer_sk+1;
								}
								in_chat = 1;
								break;
							case 'q':
								goto close_all;	
							}
						}
					}else {
						if (buf[0] == '!'){
							if(buf[1] == 'q'){
								goto close;
							} else{
								printf("Comando non valido\n");
							}
						} else{
							if(encrypt_msg(peer_sk, (char)CHAT_MSG,(unsigned char*)buf,num_byte, shared_secret) < 0){
								fprintf(stderr, "Send error\n");
								continue;
							}
						}	
					}
				} else{
				
						ret = decode_incoming_message(peer_sk,&in_chat,&nonce,str, &shared_secret, &shared_len);
						if( ret == -3){
							fprintf(stderr, "Mismatching in data. Connection aborted\n");
							goto close;
						}
						if (ret == -2) {
							fprintf(stderr, "Unexpected message format. Connection aborted\n");
							goto close;
						}
						if (ret == -1) {
							fprintf(stderr, "Generic error");
							if (in_chat == 1) {
								continue;
							} else {
								fprintf(stderr, "Connection aborted!\n");
								goto close;
							}
						}
						if (ret == 0) {
							fprintf(stderr, "Client has disconnected\n");
							goto close;
						}
						
				}
			}
		}
		continue;
close:
		if (shared_secret == NULL) {
			free(shared_secret);
		}
		close(peer_sk);
		FD_CLR(peer_sk,&rfds);
		peer_sk = 0;
		in_chat = 0;
	}
close_all:
	if (shared_secret == NULL) {
		free(shared_secret);
	}
	if(peer_sk != 0){	
		close(peer_sk);
	}
	close(sk);
	return 0;
}	
