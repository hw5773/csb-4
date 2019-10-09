#ifndef __SETTING_H__
#define __SETTING_H__

#include <openssl/ssl.h>

void load_certificates(SSL_CTX *ctx, char *cacert);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);

#endif /* __SETTING_H__ */
