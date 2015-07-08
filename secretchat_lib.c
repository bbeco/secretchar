#include "secretchat_lib.h"
#include "verify.h"
#include "secretchat_support_lib.h"

#include <openssl/dh.h>
#include <sys/socket.h>
#include <unistd.h>

#define TMP_CERT "/tmp/tmp_cert.pem"
#define DIM_IP 16
#define DIM_ENV 646
#define CERT_NAME "05.pem"
#define SAI struct sockaddr_in

int create_socket(SAI* sa,int port,char *ip){
	if ((port <= 0) || (port > 65535)) {
		errno = EINVAL;
		return -2; // bad port or ip
	}
			/* New socket creation */
	int sk, ret;		
	sk = socket(AF_INET, SOCK_STREAM, 0);
	if(sk == -1){
		errno = EINVAL;
		return -1;
	}
	/* The socket is binded with the IP address and the port number */
	memset(sa, 0, sizeof(SAI)); 
	sa->sin_family = AF_INET;
	if(ip == NULL){
		sa->sin_addr.s_addr = htonl(INADDR_ANY);
	}else{
		if ((ret = inet_pton(AF_INET, ip, &(sa->sin_addr))) == 0) {
			errno = EINVAL;
			close(sk);
			return -2; //-2 bad ip or port
		}
		if (ret == -1) {
			close(sk);
			return -1;
		}
	} 
	sa->sin_port = htons(port);
	return sk;
}

/* 
 * This returns 1 on success, 0 in case of client disconnected, -1 in 
 * case of a generic error, -2 if we received and invalid message 
 * format during the connection or -3 in case of some data mismatching
 * (nonce, certificate common name, etc.).
 */
int accept_connection(unsigned char* hello_buf, unsigned int hello_len, unsigned char* sign_buf, unsigned int sign_len, unsigned char* cert_buf, unsigned int cert_len, int* nonce,int sk,X509_STORE* str, unsigned char** shared_secret, unsigned int* shared_len){
	FILE* fp = NULL;
	char peer_mail[DIM_MAIL],*my_mail;
	unsigned char *peer_pub_buf = NULL, *my_pub_buf = NULL;
	unsigned char* my_hello_buf = NULL, *my_sign_buf = NULL;
	unsigned char* my_cert_buf = NULL;
	unsigned int my_hello_len, my_sign_len, my_cert_len;
	unsigned int peer_pub_len, my_pub_len;
	int ret, peer_nonce, pos;
	DH* dh = NULL;
	BIGNUM* peer_pub_par = NULL;
	uint32_t tmp;
	char c;
	
	*shared_secret = NULL;
	
	
	if(hello_buf == NULL || cert_buf == NULL || sign_buf == NULL || sk < 0 || str == NULL) {
		errno = EINVAL;
		ret = -1;
		goto fail;
	}
	
	if ((fp = fopen(TMP_CERT, "w+")) == NULL) { //the 2 cert overlaps
		ret = -1;
		goto fail;
	}
	
	if (fwrite(cert_buf, 1, cert_len, fp) < cert_len) {
		ret = -1;
		goto fail;
	}
	
	ret = verify_name(fp, hello_buf, hello_len, sign_buf, sign_len, &peer_pub_buf, &peer_pub_len, str, &peer_nonce,0);
	fp =  NULL;
	if ( ret < 0) {
		goto fail;
	}
	
	if ((fp = fopen(CERT_NAME, "r")) == NULL) {
		fprintf(stderr, "Error opening certificate\n");
		ret = -1;
		goto fail;
	}
	
	if ((my_mail = read_common_name(fp)) == NULL) {
		ret = -1;
		goto fail;
	}
	
	sscanf((char *)hello_buf, "%s", peer_mail);
	
	if ((dh = dh_genkey()) == NULL) {
		ret = -1;
		goto fail;
	}
	
	my_pub_buf = (unsigned char*)calloc(1, BN_num_bytes(dh->pub_key));
	my_pub_len = BN_bn2bin(dh->pub_key, my_pub_buf);
	
	if ((ret = prepare_and_sign_hello(peer_mail, strlen(peer_mail), my_mail, strlen(my_mail), *nonce, my_pub_buf, my_pub_len, &my_hello_buf, &my_hello_len, &my_sign_buf, &my_sign_len)) != 1) {
		ret = -1;
		goto fail;
	}
	
	rewind(fp);
	if ((my_cert_buf = prepare_cert(fp, &my_cert_len)) == NULL) {
		ret = -1;
		fp = NULL;
		goto fail;
	}
	fp = NULL;
	if (send_hello(sk, my_hello_buf, my_hello_len, my_sign_buf, my_sign_len, my_cert_buf, my_cert_len) < my_hello_len + my_sign_len + my_cert_len) {
		ret = -1;
		goto fail;
	}
	free(my_hello_buf);
	free(my_sign_buf);
	free(my_cert_buf);
	
	//generating shared secret
	peer_pub_par = BN_new();
	if (BN_bin2bn(peer_pub_buf, (int)peer_pub_len, peer_pub_par) == NULL) {
		ret = -1;
		goto fail;
	}
	*shared_secret = (unsigned char*)calloc(1, DH_size(dh));
	if ((*shared_len = DH_compute_key(*shared_secret, peer_pub_par, dh)) <= 0) {
		ret = -1;
		goto fail;
	}
	
	//receiving encrypted helo msg 2
	if ((my_hello_len = (unsigned int)decrypt_msg(sk, (char)HELO_MSG2, &my_hello_buf, *shared_secret)) <= 0) {
		ret = my_hello_len;
		goto fail;
	}
	
	//copying nonce
	memcpy(&tmp, my_hello_buf + my_hello_len - sizeof(tmp), sizeof(tmp));
	if (*nonce != ntohl(tmp)) {
		ret = -3;
		goto fail;
	}
	
	free(my_hello_buf);
	
	//sending encrypted helo msg 2
	//creating second hello
	my_hello_len = strlen(my_mail) + strlen(peer_mail) + 2 + sizeof(tmp);
	my_hello_buf = (unsigned char*)calloc(1, my_hello_len);
	
	memcpy(my_hello_buf, peer_mail, strlen(peer_mail));
	pos = strlen(peer_mail);
	c = (char)FIELD_SEPARATOR;
	memcpy(my_hello_buf + pos, &c, 1);
	pos++;
	memcpy(my_hello_buf + pos, my_mail, strlen(my_mail));
	pos += strlen(my_mail);
	memcpy(my_hello_buf + pos, &c, 1);
	pos++;
	tmp = htonl(peer_nonce);
	memcpy(my_hello_buf + pos, &tmp, sizeof(tmp));
	pos += sizeof(tmp);
	//sending
	if (encrypt_msg(sk, (char)HELO_MSG2, my_hello_buf, (unsigned int)pos, *shared_secret) < pos) {
		ret = -1;
		goto fail;
	}
	
	free(my_hello_buf);
	
	return 1;

fail:	if (fp != NULL) {
		fclose(fp);
	}
	if (my_pub_buf != NULL) {
		free(my_pub_buf);
	}
	
	if (my_hello_buf != NULL) {
		free(my_hello_buf);
	}
	
	if (my_sign_buf != NULL) {
		free(my_sign_buf);
	}
	
	if (my_pub_buf != NULL) {
		free(my_pub_buf);
	}
	if (peer_pub_par != NULL) {
		BN_free(peer_pub_par);
	}
	return ret;
}

/* This function starts a connection with the given peer.
 * It performs various checks and returns -1 if the connection can not be established
 * but the program must not terminate, -2 if the program fails completely.
 * It returns 1 on success.
 */
int init_connection (char* buf,int *peer_sk,int mynonce,X509_STORE* str, unsigned char** shared_secret, unsigned int* shared_len){
	char ipbuf[DIM_IP], peer_mail[DIM_MAIL],*my_mail;
	DH* dh;
	unsigned int mypub_len,peerpub_len,hello_len,sign_len,cert_len;
	unsigned char *mypub_buf = NULL,*peerpub_buf = NULL,*hello_buf = NULL,*sign_buf=NULL,*cert_buf=NULL;
	int peernonce,peer_port,ret;
	FILE* fp = NULL;
	SAI peer_addr;
	BIGNUM* peer_pub_par = NULL;
	*shared_secret = NULL;
	uint32_t tmp;
	char c;
	int pos;
	if((fp = fopen(CERT_NAME, "r"))==NULL){
		ret = -1;
		goto fail;
	}
	
	sscanf(buf,"%s%d%s",ipbuf,&peer_port,peer_mail);
	if((*peer_sk=create_socket(&peer_addr,peer_port,ipbuf)) < 0){
		ret = -1;
		goto fail;
	}	
 	if(connect(*peer_sk,(SA*)&peer_addr,sizeof(peer_addr)) < 0){
 		ret = -1;
		goto fail;
 	}
 	if((my_mail=read_common_name(fp))==NULL){
		ret = -1;
		goto fail;
	}
	if((dh=dh_genkey())==NULL){
		errno = EINVAL;
		ret = -1;
		goto fail;	
	}
	mypub_buf = (unsigned char*)calloc(1,BN_num_bytes(dh->pub_key));
	mypub_len = BN_bn2bin(dh->pub_key,mypub_buf);
	//input:my_mail,length1,peer_mail,length2,mynonce,mypub_buf,mypub_len
	//output:hello_buf,hello_len,sign_buf,sign_len
	if(prepare_and_sign_hello(my_mail,strlen(my_mail),peer_mail,\
		strlen(peer_mail),mynonce,mypub_buf,mypub_len,&hello_buf,\
		&hello_len,&sign_buf,&sign_len)<0){
		ret = -1;
		goto fail;
	}
 	cert_buf = prepare_cert(fp,&cert_len); //this closes fp
 	fp = NULL;
 	if(cert_buf == NULL){
 		ret = -1;
		goto fail;
 	}
  	if(send_hello(*peer_sk,hello_buf, hello_len, sign_buf, sign_len, cert_buf, cert_len)<=0){
		ret = -1;
		goto fail;
 	}
	free(hello_buf);
	free (sign_buf);
	free(cert_buf);
	/*
	 * the next call set the correct hello_buf, hello_len, sign_buf,sign_len, 
	 * cert and cert_len
	 */
	if((ret=recv_hello(*peer_sk,&hello_buf, &hello_len, &sign_buf, &sign_len, &cert_buf, &cert_len))<=0){
		goto fail;
	}	
	if((fp=fopen(TMP_CERT,"w+"))==NULL){
		ret = -1;
		goto fail;
	}
	if(fwrite(cert_buf,1,cert_len,fp)<cert_len){
		ret = -1;
		goto fail;
	}
	//this closes fp
	if ((ret=verify_name(fp,hello_buf,hello_len,sign_buf,sign_len,&peerpub_buf, &peerpub_len,str, &peernonce,1)) <= 0) {
			fp = NULL;
			goto fail;
	}
	fp = NULL;
	free(hello_buf);
	free(sign_buf);
	free(cert_buf);
	
	/*We have just verified the received hello msg. Time to send 
	 * the last part of hello phase
	 */
	
	/*computing shared secret*/
	peer_pub_par = BN_new();
	if (BN_bin2bn(peerpub_buf, (int)peerpub_len, peer_pub_par) == NULL) {
		ret = -1;
		goto fail;
	}
	*shared_secret = (unsigned char*)calloc(1, DH_size(dh));
	if ((*shared_len = DH_compute_key(*shared_secret, peer_pub_par, dh)) <= 0) {
		ret = -1;
		goto fail;
	}
	
	//creating second hello
	hello_len = strlen(my_mail) + strlen(peer_mail) + 2 + sizeof(tmp);
	hello_buf = (unsigned char*)calloc(1, hello_len);
	
	memcpy(hello_buf, my_mail, strlen(my_mail));
	pos = strlen(my_mail);
	c = (char)FIELD_SEPARATOR;
	memcpy(hello_buf + pos, &c, 1);
	pos++;
	memcpy(hello_buf + pos, peer_mail, strlen(peer_mail));
	pos += strlen(peer_mail);
	memcpy(hello_buf + pos, &c, 1);
	pos++;
	tmp = htonl(peernonce);
	memcpy(hello_buf + pos, &tmp, sizeof(tmp));
	pos += sizeof(tmp);
	//sending
	if (encrypt_msg(*peer_sk, (char)HELO_MSG2, hello_buf, (unsigned int)pos, *shared_secret) < pos) {
		ret = -1;
		goto fail;
	}
	
	free(hello_buf);
	//receiving encrypted helo msg 2
	if ((hello_len = (unsigned int)decrypt_msg(*peer_sk, (char)HELO_MSG2, &hello_buf, *shared_secret)) <= 0) {
		ret = hello_len;
		goto fail;
	}
	
	//copying nonce
	memcpy(&tmp, hello_buf + hello_len - sizeof(tmp), sizeof(tmp));
	if (mynonce != ntohl(tmp)) {
		ret = -3;
		goto fail;
	}
	
	free(hello_buf);
	free(mypub_buf);
	free(peerpub_buf);
	return 1;
	
fail: 	if (fp != NULL) {
		fclose(fp);
	}
	if (hello_buf != NULL) {
		free(hello_buf);
	}
	if (sign_buf != NULL) {
		free(sign_buf);
	}
	if (cert_buf != NULL) {
		free(cert_buf);
	}
	if (mypub_buf != NULL) {
		free(mypub_buf);
	}
	if (peerpub_buf != NULL) {
		free(peerpub_buf);
	}
	if (peer_pub_par != NULL) {
		BN_free(peer_pub_par);
	}
	if (*shared_secret != NULL) {
		free(*shared_secret);
	}
	return ret;
}

/*
 * It returns the same error code convention used before
 */
int decode_incoming_message(int sk,char* in_chat,int *mynonce, X509_STORE* str, unsigned char** shared_secret, unsigned int* shared_len) {
	int ret;
	unsigned char* recv_buf = NULL;
	unsigned char *hello = NULL, *sign = NULL, *cert = NULL;
	unsigned int hello_len,sign_len,cert_len;
	
	if(*in_chat == 0){
		if( (ret=recv_hello(sk,&hello,&hello_len,&sign,&sign_len,&cert,&cert_len)) <= 0){
			goto fail;
		}
		ret = accept_connection(hello, hello_len, sign, sign_len, cert, cert_len,mynonce,sk,str, shared_secret, shared_len);
		if (ret <= 0) {
			goto fail;
		}
		*in_chat = 1;
		return 1;	
	}
	
	//here we are in chat
	if((ret=decrypt_msg(sk, (char)CHAT_MSG,&recv_buf, *shared_secret)) <= 0){
		goto fail;
	}
	
	//if we reached this point, we can print the incoming message
	printf("\n");
	write(1,recv_buf,ret);
	free(recv_buf);
			
	return 1;
	
fail:	if (hello != NULL) {
		free(hello);
	}
	if (sign != NULL) {
		free(sign);
	}
	if (cert != NULL) {
		free(cert);
	}
	if (recv_buf != NULL) {
		free(recv_buf);
	}
	
	return ret;
}
