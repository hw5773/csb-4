#include "conn.h"
#include "debug.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>

int open_connection(const char *domain, int port)
{   
  fstart("domain: %s, port: %d", domain, port);
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
    
  if ( (host = gethostbyname(domain)) == NULL )
  {
    ferr();
    perror(domain);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0); 
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) 
  {
    close(sd);
    ferr();
    perror(domain);
    abort();
  }
  
  ffinish("sd: %d", sd);
  return sd; 
}

int open_listener(int port)
{   
  fstart("port: %d", port);
  int sd, ret, enable;
  struct sockaddr_in addr;

  sd = socket(PF_INET, SOCK_STREAM, 0); 
  enable = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    abort();
  }

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) 
  {
    ferr();
    perror("can't bind port");
    abort();
  }

  if (listen(sd, 10) != 0) 
  {
    ferr();
    perror("Can't configure listening port");
    abort();
  }

  ffinish("sd: %d", sd);
  return sd; 
}
