#include "rsa.h"
#include "cert.h"
#include "../include/debug.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>

struct cert_problems_st *init_cert_problems(void)
{
  fstart();
  struct cert_problems_st *problems;
  problems = (struct cert_problems_st *)malloc(sizeof(struct cert_problems_st));
  memset(problems, 0x0, sizeof(struct cert_problems_st));

  ffinish("problems: %p", problems);
  return problems;
}

void free_cert_problems(struct cert_problems_st *prob)
{
  fstart("prob: %p", prob);
  int i, num;
  if (prob)
  {
    num = prob->num;

    for (i=0; i<num; i++)
    {
      free_cert_list(prob->problems[i]);
    }
  }
  ffinish();
}

int add_cert_list_to_problems(struct cert_list_st *list, struct cert_problems_st *prob)
{
  fstart("list: %p, prob: %p", list, prob);
  int idx;

  assert(list);
  assert(prob);
  idx = prob->num;

  if (idx >= MAX_PROBLEMS)
  {
    ffinish();
    return FAILURE;
  }

  prob->problems[idx] = list;
  prob->num++;

  ffinish();
  return SUCCESS;
}

struct cert_list_st *get_cert_list_from_problems(int num, struct cert_problems_st *prob)
{
  fstart("num: %d, prob: %p", num, prob);
  assert(prob);
  assert(num >= 0);

  if (num >= prob->num)
  {
    emsg("Out of index");
    return NULL;
  }

  ffinish("list: %p", prob->problems[num]);
  return prob->problems[num];
}

struct cert_list_st *init_cert_list(void)
{
  fstart();
  struct cert_list_st *list;
  list = (struct cert_list_st *)malloc(sizeof(struct cert_list_st));
  memset(list, 0x0, sizeof(struct cert_list_st));

  ffinish("list: %p", list);
  return list;
}

void free_cert_list(struct cert_list_st *list)
{
  fstart("list: %p", list);
  struct cert_entry_st *curr, *next;

  if (list)
  {
    curr = list->head;

    while (curr->next)
    {
      next = curr->next;
      free_cert_entry(curr);
      curr = next;
    }
    free_cert_entry(curr);
  }

  ffinish();
}

int add_buffer_to_list(unsigned char *buf, int len, struct cert_list_st *list)
{
  fstart("buf: %p, len: %d, list: %p", buf, len, list);
  int ret;
  struct cert_entry_st *entry;
  unsigned char *p;
  X509 *x;

  assert(buf);
  assert(len > 0);
  assert(list);

  p = buf;
  x = d2i_X509(NULL, &p, len);
  entry = init_cert_entry(x);
  if (!entry) goto err;
  ret = add_cert_entry_to_list(entry, list);
  if (ret == FAILURE) goto err;

  ffinish("ret: %d", ret);
  return ret;
err:
  if (x)
    X509_free(x);
  if (entry)
    free_cert_entry(entry);
  ffinish("ret: %d", ret);
  return ret;
}

int add_cert_entry_to_list(struct cert_entry_st *entry, struct cert_list_st *list)
{
  fstart("entry: %p, list: %p", entry, list);
  struct cert_entry_st *ptr;

  assert(entry);
  assert(list);
  ptr = list->head;

  if (ptr)
  {
    while (ptr->next)
      ptr = ptr->next;
    ptr->next = entry;
  }
  else
    list->head = entry;

  entry->list = list;
  list->num++;

  ffinish();
  return SUCCESS;
}

unsigned char get_num_of_entry_in_list(struct cert_list_st *list)
{
  fstart("list: %p", list);
  char ret;
  ret = (char) (list->num);
  ffinish("ret: %d", ret);
  return ret;
}

struct cert_entry_st *get_cert_entry_from_list(int num, struct cert_list_st *list)
{
  fstart("num: %d, list: %p", num, list);
  int i;
  struct cert_entry_st *ret;

  assert(num >= 0);
  assert(list);

  if (num >= list->num)
  {
    emsg("Out of index");
    return NULL;
  }

  ret = list->head;
  for (i=0; i<num; i++)
  {
    ret = ret->next;
  }

  ffinish("ret: %p", ret);
  return ret;
}

struct cert_entry_st *init_cert_entry(X509 *x)
{
  fstart("x : %p", x);
  struct cert_entry_st *entry;
  assert(x);
  entry = (struct cert_entry_st *)malloc(sizeof(struct cert_entry_st));
  if (!entry) goto out;
  memset(entry, 0x0, sizeof(struct cert_entry_st));
  entry->x = x;

  ffinish("entry: %p", entry);
out:
  return entry;
}

void free_cert_entry(struct cert_entry_st *entry)
{
  fstart("entry: %p", entry);
  if (entry)
  {
    if (entry->x)
      X509_free(entry->x);
    entry->next = NULL;
    entry->list = NULL;
    free(entry);
    entry = NULL;
  }
  ffinish();
}

X509 *load_certificate(const char *file)
{
  fstart("file: %s", file);
  BIO *in;
  X509 *x = NULL;

  assert(file);
  in = BIO_new(BIO_s_file());
  if (!in) goto out;
  if (BIO_read_filename(in, file) <= 0) goto out;

  x = PEM_read_bio_X509(in, NULL, NULL, NULL);
  ffinish("x: %p", x);
out:
  if (in)
    BIO_free(in);
  return x;
}

struct keypair *get_pubkey_from_certificate(struct cert_entry_st *entry)
{
  fstart("entry: %p", entry);
  X509 *x;
  struct keypair *kst;
  EVP_PKEY *pkey;

  assert(entry);
  x = entry->x;
  kst = (struct keypair *)malloc(sizeof(struct keypair));
  if (!kst) goto err;
  memset(kst, 0x0, sizeof(struct keypair));
  pkey = X509_get_pubkey(x);
  if (!pkey) goto err;

  kst->pub = EVP_PKEY_get1_RSA(pkey);

  return kst;

err:
  if (kst)
    free(kst);
  return NULL;
}

unsigned char *get_buffer_from_certificate(struct cert_entry_st *entry, int *len)
{
  fstart("entry: %p, len: %p", entry, len);
  unsigned char *ret;
  X509 *x;

  ret = NULL;
  x = entry->x;
  *len = i2d_X509(x, &ret);
  if (*len <= 0)
  {
    ffinish("ret: 0");
    return NULL;
  }

  ffinish("ret: %p, *len: %d", ret, *len);
  return ret;
}

unsigned char *get_subject_from_certificate(struct cert_entry_st *entry)
{
  fstart("entry: %p", entry);
  X509 *x;
  assert(entry);
  x = entry->x;
  ffinish();
  return X509_NAME_oneline(x->cert_info->subject, NULL, 0);
}

unsigned char *get_issuer_from_certificate(struct cert_entry_st *entry)
{
  fstart("entry: %p", entry);
  X509 *x;
  assert(entry);
  x = entry->x;
  ffinish();
  return X509_NAME_oneline(x->cert_info->issuer, NULL, 0);
}

unsigned char *get_signature_from_certificate(struct cert_entry_st *entry, int *len)
{
  fstart("entry: %p, len: %p", entry, len);
  X509 *x;
  assert(entry);
  assert(len);

  x = entry->x;
  *len = x->signature->length;
  ffinish();
  return x->signature->data;
}

unsigned char *get_message_from_certificate(struct cert_entry_st *entry, int *len)
{
  fstart("entry: %p, len: %p", entry, len);
  const ASN1_ITEM *it;
  unsigned char *ret;
  void *asn;
  X509 *x;
  assert(entry);
  assert(len);
  ret = NULL;
  x = entry->x;
  asn = x->cert_info;
  it = ASN1_ITEM_rptr(X509_CINF);
  *len = ASN1_item_i2d(asn, &ret, it);
  ffinish("ret: %p, *len: %d", ret, *len);
  return ret;
}

int is_name_same(char *a, char *b)
{
  fstart("a: %s, b: %s", a, b);
  int ret;
  size_t alen, blen;

  assert(a);
  assert(b);
  alen = strlen(a);
  blen = strlen(b);

  if (alen != blen)
  {
    ret = FAILURE;
    goto out;
  }

  if (strncmp(a, b, alen))
    ret = FAILURE;
  else
    ret = SUCCESS;

out:
  ffinish("ret: %d", ret);
  return ret;
}

int is_self_signed_certificate(struct cert_entry_st *entry)
{
  fstart("entry: %p", entry);
  assert(entry);
  ffinish();
  return is_name_same(get_subject_from_certificate(entry), get_issuer_from_certificate(entry));
}

void print_cert_problems(struct cert_problems_st *prob)
{
  fstart("prob: %p", prob);

  int i, j;
  struct cert_list_st *list;
  struct cert_entry_st *entry;

  printf("Number of Problems: %d\n", prob->num);
  for (i=0; i<prob->num; i++)
  {
    list = get_cert_list_from_problems(i, prob);
    printf("===== Problem %d =====\n", i);
    print_cert_list(list);
  }
  printf("======================\n");

  ffinish();
}

void print_cert_list(struct cert_list_st *list)
{
  fstart("list: %p", list);
  int i, num;
  struct cert_entry_st *entry;
  num = get_num_of_entry_in_list(list);
  printf(">>  Number of Certificates: %d\n", num);
  
  for (i=0; i<num; i++)
  {
    entry = get_cert_entry_from_list(i, list);
    printf(">>  Subject %d:\t %s\n", i, get_subject_from_certificate(entry));
    printf(">>  Issuer %d:\t %s\n", i, get_issuer_from_certificate(entry));
  }

  ffinish();
}
