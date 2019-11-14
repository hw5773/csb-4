#ifndef __RSA_H__
#define __RSA_H__

#define RSA_ENCRYPT 1
#define RSA_DECRYPT 2
#define RSA_SIGN    3
#define RSA_VERIFY  4

#include <stdio.h>
#include <time.h>
#include <openssl/rsa.h>

struct keypair
{
  RSA *pub;
  RSA *priv;
};

struct keypair *init_rsa_keypair(const char *skname, const char *pkname);
void free_rsa_keypair(struct keypair *kst);

int make_rsa_pubkey_to_bytes(struct keypair *kst, unsigned char *pk, int *len);
int make_bytes_to_rsa_pubkey(struct keypair *kst, unsigned char *buf, int len);
int rsa_operation(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen, int op);

#endif /* __OTP_H__ */
