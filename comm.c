#include "comm.h"

/*
 * This function sends a msg (which is allocated and then set free)
 * to a socket sk. It appends the length and the format of the 
 * original message(contained in buf) before sending msg
 * Errno is set appropriately.
 * It returns the number of bytes sent or -1 in case of error
 */
int send_msg(int sk, unsigned char* buf, int num_bytes,char format) {
	uint32_t tmp;
    unsigned char* msg;
	int ret, msg_len;
    if (sk < 0 || buf == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    msg = (unsigned char*)calloc(1, sizeof(tmp) + num_bytes+1);
	tmp = htonl((uint32_t)num_bytes + 1);
	memcpy(msg, &tmp, sizeof(tmp));
	msg[4] = format;
    memcpy(msg + sizeof(tmp)+1, buf, num_bytes);
    msg_len = num_bytes + sizeof(tmp) + 1;
	if ((ret = send(sk,msg,msg_len,0)) < msg_len) {
        free(msg);
        return -1;
    }
    free(msg);
	return ret;
}

/*
 * This function receives a message from a socket
 * It returns the length of the payload in bytes or -1 if an error occurred.
 * This function set errno appropriately.
 * @return the number of bytes of the payload or -1 in case of error or 
 * 0 if a disconnection occurs
 * It leaves the message in **buf (which is allocated) and its
 * format in *format.
 */
int recv_msg(int sk, unsigned char** buf,char* format) {
    int ret, buflen;
    uint32_t tmp;
    
    if (sk < 0) {
        errno = EINVAL;
        return -1;
    }
    
    if ((ret = recv(sk, &tmp, sizeof(tmp), MSG_WAITALL)) < sizeof(tmp)) {
	ret = (ret == 0) ? ret : -1;
        return ret;
    }
    buflen = ntohl(tmp);
    *buf = (unsigned char*)calloc(1, buflen);
    
    if ((ret = recv(sk, *buf, buflen, MSG_WAITALL)) < buflen) {
	ret = (ret == 0) ? ret : -1;
        free(*buf);
        return ret;
    }
    *format = (*buf)[0];
    memmove(*buf,(*buf)+1,buflen-1);//we remove the format from buf
    return ret-1;//It returns the effective buflen
}
