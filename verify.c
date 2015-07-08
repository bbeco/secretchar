#include "verify.h"

/*
 * gets the common name field value from an identifier string.
 * The output string is null terminated.
 * It returns -1 and set errno if an error occured. Otherwise, if everything is
 * ok, it returns the number of byte written into dest.
 */
int get_common_name(char* dest, const char* src)
{
	char* field_start = "/CN=";
	int i, j, byte_count = 0;

	if (!src || !dest) {
		goto fail;
	}
	
	i = 0;
	while (src[i] != '\0') {
		/* starting comparison */
		j = 0;
		while (field_start[j] == src[i + j] && field_start[j] != '\0') {
			/* continue until the end of the field name is over */
			j++;
		}
		/* if field_start[j] == '\0' we have found the common name */
		if (field_start[j] == '\0') {
			i = i + j;
			j = 0;
			/* copying common name until a new field is found */
			while (src[i] != '/') {
				dest[j] = src[i];
				i++;
				j++;
				byte_count++;
			}
			/* if the copy is over */
			if (src[i] == '/') {
				dest[byte_count] = '\0';
				return byte_count;
			}
		}
		
		i++;
	}
	/* this point is reached only if we were unable to find the 
	 * common name
	 */
fail:	errno = EINVAL;
	return -1;
}

/*
 * This function reads a common name from a certificate using get_common_name.
 * It returns ther name or NULL in case of error. Errno is set appropriately.
 * The file pointer must be opened before calling the function.
 * The function does not close it. 
 * It allocates my_mail.
 */ 
char* read_common_name(FILE* fp){
	X509* cert;
	if(fp==NULL){
		return NULL;
	}
	if((cert=PEM_read_X509(fp, NULL, NULL, NULL))==NULL){
		return NULL;
	}
	X509_NAME* name;
	int ret;
	char* identifier;
	char* my_mail = (char*)calloc(1,DIM_MAIL);
	name = X509_get_subject_name(cert);
	identifier = X509_NAME_oneline(name, NULL, 0);
	if((ret=get_common_name(my_mail,identifier)) < 0){
		return NULL;
	}
	return my_mail;
}

/*
 * This function verifies the validity of the certificate and the matching of the
 * other part's name with the certificate.
 * It also checks the sign validity of a message.
 * It returns -1 on generic error, -3 on mismatching on certificate, 1 on success.
 * It closes the passed file pointer fp (which should have already been opened).
 * The last argument is used to distinguish if we are initializing or accepting
 * a connection and so which is the correct name to verify.
 * After verifying, It leaves the public parameter of DH and the nonce of the
 * other part respectively in **pub_buf (which is allocated) and *nonce.
 */
int verify_name(FILE* fp,unsigned char *hello_buf,unsigned int hello_len,unsigned char *sign_buf,unsigned int sign_len,unsigned char** pub_buf,unsigned int *pubbuf_len,X509_STORE* str,int* nonce,int init){	
	int sheet_len,ret;
	uint32_t tmp;
	char read_mail[DIM_MAIL],temp_mail[DIM_MAIL],*cert_mail = NULL;
	X509_STORE_CTX* cert_ctx = NULL;
	EVP_PKEY* evp = EVP_PKEY_new();
	EVP_MD_CTX* ctx = NULL;
	*pub_buf = NULL;
	if (!fp) {
		ret = -1;
		goto fail;
	}
	//We must come back to the start of fp
	rewind(fp);
	X509* cert = PEM_read_X509(fp,NULL,NULL,NULL);
	*pub_buf = NULL;
	//the following function is needed to correctly verify the certificate
	OpenSSL_add_all_algorithms();
	if((cert_ctx=X509_STORE_CTX_new())==NULL){
		ret = -1;
		goto fail;
	}
	if(X509_STORE_CTX_init(cert_ctx,str,cert,NULL)<=0){
		ret = -1;
		goto fail;
	}
	if(X509_verify_cert(cert_ctx)==0){
		//fprintf(stderr, "Error verifying certificate: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(cert_ctx)));
		ret = -3;
		goto fail;	
	}
	X509_STORE_CTX_cleanup(cert_ctx);
	X509_STORE_CTX_free(cert_ctx);
	cert_ctx = NULL;
	ctx  = (EVP_MD_CTX*)calloc(1,sizeof(EVP_MD_CTX));
	EVP_MD_CTX_init(ctx);
	evp = X509_get_pubkey(cert);
	if(EVP_VerifyInit(ctx,EVP_sha512())==0){
		ret = -1;
		goto fail;
	}
	if(EVP_VerifyUpdate(ctx,hello_buf,hello_len)==0){
		ret = -1;
		goto fail;
	}
	ret=EVP_VerifyFinal(ctx,sign_buf,sign_len,evp);
	if(ret == 0){
		ret = -3;
		goto fail;
	}
	if (ret == -1) {
		goto fail;
	}
	rewind(fp);
	cert_mail = read_common_name(fp);//set it free later
	if(init == 1){
		sscanf((char *)hello_buf,"%s%s",temp_mail,read_mail);
	} else{
		sscanf((char *)hello_buf,"%s%s",read_mail,temp_mail);
	}
	sheet_len = strlen(temp_mail)+strlen(read_mail)+2;
	*pubbuf_len = hello_len - sheet_len;
	tmp = *((uint32_t *)(hello_buf+sheet_len));
	*nonce = ntohl(tmp);
	sheet_len+=sizeof(tmp);
	*pub_buf = (unsigned char*)calloc(1,*pubbuf_len);
	memcpy(*pub_buf,hello_buf+sheet_len,*pubbuf_len);
	if(strlen(cert_mail)!=strlen(read_mail)){
		ret = -3;
		goto fail;
	}
	if(strncmp(cert_mail,read_mail,strlen(cert_mail))!=0){
		ret = -3;
		goto fail;
	}
	free(ctx);
	fclose(fp);
	EVP_PKEY_free(evp);
	free(cert_mail);
	return 1;
	fail:
		fclose(fp);
		if(cert_mail!=NULL){
			free(cert_mail);
		}
		if(cert_ctx!=NULL){
			X509_STORE_CTX_cleanup(cert_ctx);
			X509_STORE_CTX_free(cert_ctx);
		}
		if(ctx!=NULL){
			free(ctx);
		}	
		if(*pub_buf!=NULL){
			free(*pub_buf);
		}
		EVP_PKEY_free(evp);
		return ret;
}
