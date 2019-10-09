#include "rsa.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/net.h"
#include "../include/err.h"
#include <assert.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

int rsa_encrypt_message(struct keypair *kst, unsigned char *input, int ilen,
    unsigned char *output, int *olen);

int rsa_decrypt_message(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen);

int rsa_sign_message(struct keypair *kst, unsigned char *msg, int mlen,
    unsigned char *sign, int *slen);

int rsa_verify_message(struct keypair *kst, unsigned char *sign, int slen,
    unsigned char *msg, int mlen);

int rsa_operation(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen, int op)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p, op: %d", 
      kst, input, ilen, output, olen, op);

  assert(kst != NULL);
  assert(input != NULL);
  assert(output != NULL);
  assert(ilen > 0);

  if (op == RSA_ENCRYPT)
    return rsa_encrypt_message(kst, input, ilen, output, olen);
  else if (op == RSA_DECRYPT)
    return rsa_decrypt_message(kst, input, ilen, output, olen);
  else if (op == RSA_SIGN)
    return rsa_sign_message(kst, input, ilen, output, olen);
  else if (op == RSA_VERIFY)
    return rsa_verify_message(kst, input, ilen, output, *olen);
  else
    return FAILURE;
}

struct keypair *init_rsa_keypair(const char *skname, const char *pkname)
{
  fstart("skname: %p, pkname: %p", skname, pkname);

  struct keypair *ret;
  int klen;
  BIO *b;

  b = BIO_new_fp(stdout, BIO_NOCLOSE);
  ret = (struct keypair *)malloc(sizeof(struct keypair));
  if (!ret)
  {
    emsg("Out of memory during a keypair malloc");
    goto err;
  }
  memset(ret, 0x0, sizeof(struct keypair));


  if (skname)
  {
    FILE *sk = fopen(skname, "rb");
    ret->priv = RSA_new();
    ret->priv = PEM_read_RSAPrivateKey(sk, NULL, NULL, NULL);
    if (!(ret->priv))
      emsg("Error to load the RSA private key");
    else
    {
      imsg("Succeed to load the RSA private key");
    }
    fclose(sk);
  }

  if (pkname)
  {
    FILE *pk = fopen(pkname, "rb");
    ret->pub = RSA_new();
    ret->pub = PEM_read_RSA_PUBKEY(pk, NULL, NULL, NULL);
    if (!(ret->pub))
      emsg("Error to load the RSA public key");
    else
    {
      imsg("Succeed to load the RSA public key");
    }
    fclose(pk);
  }

  ffinish("ret: %p", ret);
  return ret;
err:
  if (ret)
  {
    free_rsa_keypair(ret);
  }
  ffinish("ret: %p", ret);
  return NULL;
}

void free_rsa_keypair(struct keypair *kst)
{
  fstart("kst: %p", kst);

  if (kst)
  {
    if (kst->pub)
      RSA_free(kst->pub);

    if (kst->priv)
      RSA_free(kst->priv);

    free(kst);
    kst = NULL;
  }

  ffinish("kst: %p", kst);
}

int make_rsa_pubkey_to_bytes(struct keypair *kst, unsigned char *pk, int *len)
{
  fstart("kst: %p, pk: %p, len: %p", kst, pk, len);

  int ret;
  unsigned char *buf;
  BIO *b;
  BUF_MEM *pk_mem;

  assert(kst != NULL);
  assert(kst->pub != NULL);
  assert(pk != NULL);
  assert(len != NULL);
  
  b = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(b, kst->pub);
  BIO_get_mem_ptr(b, &pk_mem);

  dmsg("Length of the RSA public key: %d", pk_mem->length);

  if (pk_mem > 0)
  {
    memcpy(pk, pk_mem->data, pk_mem->length);
    *len = pk_mem->length;
    dprint("RSA public key", pk, 0, *len, ONE_LINE);
    ret = SUCCESS;
  }
  else
  {
    emsg("i2d_RSAPublicKey failed");
    ret = FAILURE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

int make_bytes_to_rsa_pubkey(struct keypair *kst, unsigned char *buf, int len)
{
  fstart("kst: %p, buf: %p, len: %d", kst, buf, len);

  int ret;
  BIO *b;

  assert(kst != NULL);
  assert(buf != NULL);
  assert(len > 0);

  dprint("RSA bytes", buf, 0, len, ONE_LINE);

  b = BIO_new(BIO_s_mem());
  BIO_write(b, buf, len);

  kst->pub = PEM_read_bio_RSA_PUBKEY(b, NULL, NULL, NULL);
  if (kst->pub)
  {
    ret = SUCCESS;
  }
  else
  {
    ret = FAILURE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

int rsa_encrypt_message(struct keypair *kst, unsigned char *input, int ilen,
    unsigned char *output, int *olen)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p",
      kst, input, ilen, output, olen);

  int ret;
  assert(kst != NULL);
  assert(input != NULL);
  assert(ilen > 0);
  assert(output != NULL);
  assert(olen != NULL);
  
  *olen = RSA_public_encrypt(ilen, input, output, kst->pub, RSA_PKCS1_OAEP_PADDING);

  if (*olen > 0)
  {
    dprint("Input", input, 0, ilen, ONE_LINE);
    dprint("Output", output, 0, *olen, ONE_LINE);
    ret = SUCCESS;
  }
  else
  {
    emsg("RSA Encryption error");
    ret = FAILURE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

int rsa_decrypt_message(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p",
      kst, input, ilen, output, olen);

  int ret;

  assert(kst != NULL);
  assert(input != NULL);
  assert(ilen > 0);
  assert(output != NULL);
  assert(olen != NULL);

  *olen = RSA_private_decrypt(ilen, input, output, kst->priv, RSA_PKCS1_OAEP_PADDING);

  if (*olen > 0)
  {
    dprint("Input", input, 0, ilen, ONE_LINE);
    dprint("Output", output, 0, *olen, ONE_LINE);
    ret = SUCCESS;
  }
  else
  {
    emsg("RSA Decryption error");
    ret = FAILURE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

int rsa_sign_message(struct keypair *kst, unsigned char *msg, int mlen,
    unsigned char *sign, int *slen)
{
  fstart("kst: %p, sign: %p, slen: %p, msg: %p, mlen: %d", 
      kst, sign, slen, msg, mlen);

  int ret;
  unsigned char digest[SHA256_DIGEST_LENGTH] = {0, };
  SHA256_CTX ctx;

  assert(kst != NULL);
  assert(kst->priv != NULL);
  assert(msg != NULL);
  assert(mlen > 0);
  assert(sign != NULL);
  assert(slen != NULL);

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, msg, mlen);
  SHA256_Final(digest, &ctx);

  ret = RSA_sign(HASH_ALGO, digest, SHA256_DIGEST_LENGTH, sign, slen, kst->priv);
  if (!ret)
    ret = FAILURE;

  if (ret > 0)
  {
    dmsg("Message (%d byts): %s", mlen, msg);
    dprint("Signature", sign, 0, *slen, ONE_LINE);
  }
  else
  {
    emsg("%s", ERR_error_string(ERR_get_error(), NULL));
  }
  ffinish("ret: %d", ret);
  return ret;
}

// TODO: Implement the RSA signature verification operation
int rsa_verify_message(struct keypair *kst, unsigned char *sign, int slen,
    unsigned char *msg, int mlen)
{
  fstart("kst: %p, sign: %p, slen: %d, msg: %p, mlen: %d", 
      kst, sign, slen, msg, mlen);

  int ret;

  assert(kst != NULL);
  assert(kst->pub != NULL);
  assert(sign != NULL);
  assert(slen > 0);
  assert(msg != NULL);

  ret = FAILURE;

  dmsg("Message (%d bytes): %s", mlen, msg);
  dprint("Signature", sign, 0, slen, ONE_LINE);
  dmsg("Verification: %d", ret);
  ffinish("ret: %d", ret);
  return ret;
}
