#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "cert.h"
#include "../include/debug.h"
#include "../include/defines.h"


struct cert_list_st *load_cert_list(const char *dname);

int main(int argc, char *argv[])
{
  // load the certificate chain from the directory 'certs'
  struct cert_list_st *list = load_cert_list("certs");

  // print the certificate chain
  print_cert_list(list);

  // check the number of certificates in the certificate chain
  int num = get_num_of_entry_in_list(list);
  imsg(">>> The number of certificates in the list: %d", num);

  // fetch the first certificate (the leaf certificate) from the certificate
  // chain (the index is started from 0; that is, the index of the leaf
  // certificate is 0.
  struct cert_entry_st *leaf = get_cert_entry_from_list(0, list);

  // print the subject name of the leaf certificate
  unsigned char *subject = get_subject_from_certificate(leaf);
  imsg(">>> The subject of the leaf certificate: %s", subject);

  // print the issuer of the leaf certificate
  unsigned char *issuer = get_issuer_from_certificate(leaf);
  imsg(">>> The issuer of the leaf certificate: %s", issuer);

  // compare the two names
  int result = is_name_same(subject, issuer);

  if (result == SUCCESS)
  {
    imsg(">>> The two names are same");
  }
  else
  {
    imsg(">>> The two names are different");
  }

  // get the signature from the leaf certificate
  int slen;
  unsigned char *signature = get_signature_from_certificate(leaf, &slen);
  iprint("Signature of the leaf certificate", signature, 0, slen, ONE_LINE);

  // get the (signed) message from the leaf certificate
  int mlen;
  unsigned char *message = get_message_from_certificate(leaf, &mlen);
  iprint("Signed message of the leaf certificate", message, 0, mlen, ONE_LINE);

  // check whether the certificate is self-signed
  int self_signed = is_self_signed_certificate(leaf);
  if (self_signed == SUCCESS)
  {
    imsg(">>> The certificate is self-signed");
  }
  else
  {
    imsg(">>> The certificate is not self-signed");
  }

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
