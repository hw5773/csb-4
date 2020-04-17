#ifndef __CERT_H__
#define __CERT_H__

#include "../include/defines.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>

struct cert_list_st;
struct cert_entry_st;

struct cert_problems_st {
  int num;
  struct cert_list_st *problems[MAX_PROBLEMS];
};

struct cert_list_st {
  int num;
  struct cert_entry_st *head;
};

struct cert_entry_st {
  X509 *x;
  struct cert_entry_st *next;
  struct cert_list_st *list;
};


struct cert_problems_st *init_cert_protblems(void);
void free_cert_problems(struct cert_problems_st *problems);
int add_cert_list_to_problems(struct cert_list_st *list, struct cert_problems_st *prob);
struct cert_list_st *get_cert_list_from_problems(int num, struct cert_problems_st *prob);
void print_cert_problems(struct cert_problems_st *prob);

struct cert_list_st *init_cert_list(void);
void free_cert_list(struct cert_list_st *list);
int add_buffer_to_list(unsigned char *buf, int len, struct cert_list_st *list);
int add_cert_entry_to_list(struct cert_entry_st *entry, struct cert_list_st *list);
unsigned char get_num_of_entry_in_list(struct cert_list_st *list);
struct cert_entry_st *get_cert_entry_from_list(int num, struct cert_list_st *list);
struct cert_entry_st *get_issuer_cert_entry_from_list(struct cert_entry_st *cert, 
    struct cert_list_st *list);
void print_cert_list(struct cert_list_st *list);

struct cert_entry_st *init_cert_entry(X509 *x);
void free_cert_entry(struct cert_entry_st *entry);

X509 *load_certificate(const char *file);
unsigned char *get_buffer_from_certificate(struct cert_entry_st *entry, int *len);
struct keypair *get_pubkey_from_certificate(struct cert_entry_st *entry);
unsigned char *get_subject_from_certificate(struct cert_entry_st *entry);
unsigned char *get_issuer_from_certificate(struct cert_entry_st *entry);
unsigned char *get_signature_from_certificate(struct cert_entry_st *entry, int *len);
unsigned char *get_message_from_certificate(struct cert_entry_st *entry, int *len);

int is_name_same(char *a, char *b);
int is_self_signed_certificate(struct cert_entry_st *entry);

#endif /* __CERT_H__ */
