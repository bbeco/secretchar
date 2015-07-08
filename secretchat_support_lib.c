#include "secretchat_support_lib.h"
#include "comm.h"
#include "dhread.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PRIV_KEY "privkey.pem"

/* This function signs the buffer passed as argument, returns the length of the signature
 * else -1 on error
 * It leaves the sign in **sign_buf (which is allocated)
 */
int sign_hello(unsigned char* hello_buf,unsigned int hello_len,unsigned char** sign_buf){
	EVP_MD_CTX* ctx = NULL;
	unsigned int sign_len;
	EVP_PKEY* evp = EVP_PKEY_new();
	FILE* fp;
	*sign_buf = NULL;
	ctx = (EVP_MD_CTX*)calloc(1,sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init(ctx);
	OpenSSL_add_all_algorithms();
	if((fp=fopen(PRIV_KEY,"r"))==NULL){
		goto fail;
	}
	if((evp=PEM_read_PrivateKey(fp,NULL,NULL,NULL))==NULL){
		goto fail;
	}
	*sign_buf = (unsigned char*)calloc(1,EVP_PKEY_size(evp));
   	if(EVP_SignInit(ctx,EVP_sha512())==0){
		goto fail;
	}
	if(EVP_SignUpdate(ctx,hello_buf,hello_len)==0){
		goto fail;
	}
	if(EVP_SignFinal(ctx,*sign_buf,&sign_len,evp)==0){
		goto fail;
	}
	
	EVP_MD_CTX_cleanup(ctx);
	free(ctx);
	EVP_PKEY_free(evp);
	return sign_len;
    
fail:
	EVP_MD_CTX_cleanup(ctx); 
	free(ctx);
	if (*sign_buf != NULL) {
		free(*sign_buf);
	}
	return -1;
}

/*
 * This function prepares an hello message (mail1' 'mail2' 'nonce pubkey) and leaves it in **hello_buf
 * (which is allocated) and then It signs hello_buf using the sign function.
 * It returns 1 on success or -1 in case of error
 */
int prepare_and_sign_hello(char* mail1,unsigned int length1,char *mail2,unsigned int length2,int nonce,unsigned char* pubkey, unsigned int publen,unsigned char** hello_buf, unsigned int* hello_len,unsigned char** sign_buf,unsigned int* sign_len){
	/*create the hello*/
	uint32_t tmp;
	*hello_len = length1+length2+2+sizeof(tmp)+publen;
	*hello_buf = (unsigned char*)calloc(1,*hello_len);
	unsigned int pos;
	memcpy(*hello_buf,mail1,length1);
	*(*hello_buf+length1) = (unsigned char)FIELD_SEPARATOR;
	pos = length1 + 1;
	memcpy(*hello_buf + pos, mail2, length2);
	pos += length2;
	*(*hello_buf + pos) = (unsigned char)FIELD_SEPARATOR;
	pos++;
	tmp = htonl(nonce);
	memcpy(*hello_buf + pos, &tmp, sizeof(tmp));
	pos += sizeof(tmp);
	memcpy(*hello_buf + pos, pubkey, publen);
	pos+=publen;
	/*sign the hello*/
	if((*sign_len=sign_hello(*hello_buf,*hello_len,sign_buf))<=0){
		return -1;
	}
	return 1;
}

/* This function takes an open file pointer fp and it closes it before 
 * returning.
 *  It takes the fp of a certificate and write it in a buffer.
 * It returns the pointer to the buffer or NULL in case of error.
 * This function allocates cert
 */
unsigned char* prepare_cert(FILE* fp,unsigned int* cert_len){
	struct stat file_info;
	int fd;
	unsigned char* cert;
	if(fp == NULL){
		return NULL;
	}
	//to come back to the start
	rewind(fp);
	fd = fileno(fp);
	if(fstat(fd,&file_info) < 0){
		return NULL;
	}
	cert = (unsigned char*)calloc(1,file_info.st_size);
	if(fread(cert,1,file_info.st_size,fp)<file_info.st_size){
		return NULL;
	}
	*cert_len = file_info.st_size;
	fclose(fp);
	return cert;
}

/* 
 * Creates the hello + certificate message and sends it.
 * It returns the number of bytes sent or -1 if an error occured. This function
 * set the value of errno in case of error.
 */
int send_hello(int sk, unsigned char* hello, unsigned int hello_len, \
                    unsigned char* sign, unsigned int sign_len, \
                    unsigned char* cert, unsigned int cert_len)
{
	uint32_t tmp;
	int num_bytes, ret;
	unsigned char* msg;

	if (sk < 0 || hello == NULL || sign == NULL || cert == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* this message contains the hello string length, the hello string, the
	* hello string signature length, the hello string signature, the 
	* certificate length and the certificate
	*/
	msg = (unsigned char*)calloc(1, hello_len + sign_len + cert_len + \
			3*sizeof(tmp));

	/* appending hello */
	tmp = htonl(hello_len);
	memcpy(msg, &tmp, sizeof(tmp));
	num_bytes = sizeof(tmp);
	memcpy(msg + num_bytes, hello, hello_len);
	num_bytes += hello_len;

	/*appending signature*/
	tmp = htonl(sign_len);
	memcpy(msg + num_bytes, &tmp, sizeof(tmp));
	num_bytes += sizeof(tmp);
	memcpy(msg + num_bytes, sign, sign_len);
	num_bytes += sign_len;

	/*appending certificate*/
	tmp = htonl(cert_len);
	memcpy(msg + num_bytes, &tmp, sizeof(tmp));
	num_bytes += sizeof(tmp);
	memcpy(msg + num_bytes, cert, cert_len);
	num_bytes += cert_len;

	/* sending */
	if ((ret = send_msg(sk, msg, num_bytes,(char)HELO_MSG1)) <= 0) {
		free(msg);
		return -1;
	}
	free(msg);
	return ret;
}

/*
 * This function decrypts a string after it has been received on a socket.
 * It performs previous checking on the format and may discard the 
 * message and return an error if the format mismatch. We can avoid a 
 * decryption if the format mismatches.
 * 
 * @return It returns the plaintext length or -1 if a generic error occured,
 * -2 if the format is not the one expected and 0 in case of disconnection.
 * It leaves the decrypted message in **plain ( which is allocated).
 */
int decrypt_msg(int sk, char format, unsigned char** plain, unsigned char* shared_secret)
{
	EVP_CIPHER_CTX* ctx;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned int iv_len = EVP_MAX_IV_LENGTH;
	unsigned char* msg = NULL;//msg has to set free in this function
	unsigned int msg_len;
	char recv_format;
	int outlen, outtot = 0, ret;
	*plain = NULL;
	ctx = (EVP_CIPHER_CTX*)calloc(1, sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	
	if ((msg_len = recv_msg(sk, &msg, &recv_format)) <= 0) {
		ret = msg_len;
		goto fail;
	}
	
	if (recv_format != format) {
		ret = -2;
		goto fail;
	}
	
	*plain = (unsigned char*)calloc(1, msg_len - iv_len);
	memcpy(iv, msg, iv_len);
	if (EVP_DecryptInit(ctx, EVP_aes_256_cbc(), shared_secret, iv) == 0) {
		ret = -1;
		goto fail;
	}
	if (EVP_DecryptUpdate(ctx, *plain, &outlen, msg + iv_len, msg_len - iv_len) == 0) {
		ret = -1;
		goto fail;
	}
	outtot = outlen;
	if (EVP_DecryptFinal(ctx, *plain + outtot, &outlen) == 0) {
		ret = -1;
		goto fail;
	}
	outtot += outlen;
	
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	free(msg);
	return outtot;
	
fail:	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	if (*plain != NULL) {
		free(*plain);
	}
	if (msg != NULL) {
		free(msg);
	}
	return ret;
	
}

/*
 * This function encrypts a string before calling send_msg.
 * It also append the given IV for the ecnryption mode.
 * It returns the length of the cipher text (iv is not considered), -1 on error.
 * Errno is set appropriately
 */
int encrypt_msg(int sk, char format, unsigned char* plain, unsigned int plain_len, unsigned char* shared_secret)
{
	EVP_CIPHER_CTX* ctx;
	unsigned char* iv;
	unsigned int iv_len = EVP_MAX_IV_LENGTH;
	unsigned char* outbuf = NULL;
	int outlen, outtot = 0;
	ctx = (EVP_CIPHER_CTX*)calloc(1, sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	
	iv = (unsigned char*)calloc(1, iv_len);
	RAND_bytes(iv, iv_len);
	if (EVP_EncryptInit(ctx, EVP_aes_256_cbc(), shared_secret, iv) == 0) {
		goto fail;
	}
	outbuf = (unsigned char*)calloc(1, plain_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()) + iv_len);
	if (EVP_EncryptUpdate(ctx, outbuf + iv_len, &outlen, plain, plain_len) == 0) {
		goto fail;
	}
	outtot += outlen;
	if (EVP_EncryptFinal(ctx, outbuf + iv_len + outtot, &outlen) == 0) {
		goto fail;
	}
	outtot += outlen;
	
	//We concatenate iv and cipher text together
	memcpy(outbuf, iv, iv_len);
	if (send_msg(sk, outbuf, outtot + iv_len, format) < outtot + iv_len) {
		goto fail;
	}
	
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	free(iv);
	free(outbuf);
	return outtot;
	
	
fail:	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	free(iv);
	if (outbuf != NULL) {
		free(outbuf);
	}
	return -1;
	
}

/*
 * This function generates my Diffie Hellmann parameter
 */
DH* dh_genkey(){
	DH *dh = get_dh1024();
	if(DH_generate_key(dh)!=1){
		DH_free(dh);
		return NULL;
	}
	return dh;
}

/*
 * This function receives an hello + certificate message
 * If something goes wrong, it returns -1 in case of generic error, -2 
 * for format mismatching or 0 in case of disconnection.
 * In case of success it returns the length of the received hello string.
 * The given pointers (hello, sign, cert) are allocated using calloc and 
 * must be freed. They are intitially set to NULL becasue if something
 * goes wrong the calling function has no need to set them free
 */
int recv_hello(int sk, unsigned char** hello, unsigned int* hello_len, \
					unsigned char** sign, unsigned int *sign_len, \
                    unsigned char** cert, unsigned int* cert_len)
{
	uint32_t tmp;
	int msg_len, pos, ret;
	unsigned char* msg = NULL;//msg has to set free later in this function
	char format;
	*hello = NULL;
	*sign = NULL;
	*cert = NULL;
	if (sk < 0) {
		errno = EINVAL;
		return -1;
	}

	if ((msg_len = recv_msg(sk, &msg,&format)) <= 0) {
		ret = msg_len;
		goto fail;
	}
	if(format != HELO_MSG1){
		errno = EINVAL;
		ret = -2;
		goto fail;
	}
	/* reading hello */
	memcpy(&tmp, msg, sizeof(tmp));
	*hello_len = (unsigned int)ntohl(tmp);
	pos = sizeof(tmp);

	*hello = (unsigned char*)calloc(1, *hello_len);
	memcpy(*hello, msg + pos, *hello_len);
	pos += *hello_len;

	/* reading hello signature */
	memcpy(&tmp, msg + pos, sizeof(tmp));
	*sign_len = (unsigned int)ntohl(tmp);
	pos += sizeof(tmp);

	*sign = (unsigned char*)calloc(1, *sign_len);
	memcpy(*sign, msg + pos, *sign_len);
	pos += *sign_len;

	/* reading certificate */
	memcpy(&tmp, msg + pos, sizeof(tmp));
	pos += sizeof(tmp);
	*cert_len = (int)ntohl(tmp);

	*cert = (unsigned char*)calloc(1, *cert_len);
	memcpy(*cert, msg + pos, *cert_len);
	pos += *cert_len;

	free(msg);
	
	return pos;
    
fail:	if (msg != NULL) {
		free(msg);
	}
	return ret;
}
