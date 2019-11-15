#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "cert.h"
#include "../include/debug.h"


struct cert_list_st *load_cert_list(const char *dname);

int main(int argc, char *argv[])
{
  struct cert_list_st *list = load_cert_list("certs");

  return 0;
}

struct cert_list_st *load_cert_list(const char *dname)
{
  fstart("dname: %s", dname);
  unsigned char cname[MAX_PATH_LEN] = {0, };
  struct cert_list_st *ret;
  struct cert_entry_st *entry;
  int i;

  ret = init_cert_list();
  for (i=0; i<MAX_NUM_OF_CERTS; i++)
  {
    memset(cname, 0x0, MAX_PATH_LEN);
    snprintf(cname, MAX_PATH_LEN, "%s/%d.crt", dname, i);
    dmsg("Certificate file: %s", cname);

    if (access(cname, F_OK) != -1)
    {
      entry = init_cert_entry(load_certificate(cname));
      add_cert_entry_to_list(entry, ret);
    }
    else
      break;
  }

  ffinish("ret: %p", ret);
  return ret;
}
