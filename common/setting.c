#include "setting.h"
#include "defines.h"
#include "debug.h"
#include <openssl/err.h>

void load_certificates(SSL_CTX* ctx, char *cacert) 
{
  fstart("ctx: %p, cacert: %p", ctx, cacert);
  /* Load certificates for verification purpose*/
  if (cacert)
  {
    if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != SUCCESS) 
    {
      ERR_print_errors_fp(stderr);
      ferr();
      abort();
    }
  }
  else
  {
    if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != SUCCESS) 
    {
      ERR_print_errors_fp(stderr);
      ferr();
      abort();
    }
  }

  /* Set default paths for certificate verifications */
  if (SSL_CTX_set_default_verify_paths(ctx) != SUCCESS) 
  {
    ERR_print_errors_fp(stderr);
    ferr();
    abort();
  }

  ffinish();
}

void load_dh_params(SSL_CTX *ctx, char *file) {
  fstart("ctx: %p, file: %s", ctx, file);
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL) {
    perror("Couldn't open DH file");
  }

  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) < 0) {
    perror("Couldn't set DH parameters");
  }
  ffinish();
}

void load_ecdh_params(SSL_CTX *ctx) {
  fstart("ctx: %p", ctx);
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
  {
    ferr();
    perror("Couldn't load the ec key");
  }

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
  {
    ferr();
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
  }

  ffinish();
}
