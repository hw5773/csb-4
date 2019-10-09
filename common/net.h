#ifndef __NET_H__
#define __NET_H__

#include <time.h>

int send_message(int fd, unsigned char *msg, int mlen);
int receive_message(int fd, unsigned char *buf, int max);

#endif /* __NET_H__ */
