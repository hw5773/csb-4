#ifndef __CONN_H__
#define __CONN_H__

int open_connection(const char *domain, int port);
int open_listener(int port);

#endif /* __CONN_H__ */
