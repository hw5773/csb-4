#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <pthread.h>
#include <getopt.h>
#include <dirent.h>

#include "rsa.h"
#include "cert.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/setting.h"
#include "../include/conn.h"
#include "../include/http.h"
#include "../include/net.h"
#include "../include/err.h"

struct cert_list_st *trusted;
unsigned char verify_cert_list(struct cert_list_st *list);
struct cert_list_st *load_trusted_root_cert_list(const char *trustdir);
int is_trusted_root_certificate(struct cert_entry_st *entry, struct cert_list_st *trusted);

int usage(const char *pname)
{
  emsg(">> usage: %s [-h <domain>] [--host <domain>] [-p <portnum>] [--port <portnum>] [-t <trusted directory>] [--trusted <trusted directory>]", pname);
  emsg(">> example: %s -h www.alice.com -p 5555 -t trusted", pname);
  exit(0);
}
// Client Prototype Implementation
int main(int argc, char *argv[])
{   
  const char *domain, *trustdir, *pname;
	int i, j, port, server;
  unsigned char buf[BUF_SIZE] = {0, };
  unsigned char answer, validation;
  const char *start = "Start";
  int ret, len, rlen, clen, c, err;
  struct cert_list_st *list;
  struct cert_entry_st *entry;
  DIR *tmp;

  pname = argv[0];
  domain = NULL;
  port = -1;
  err = 0;
  i = 0;
  answer = -1;

  SSL_library_init();
  OpenSSL_add_all_algorithms();

  /* Get command line arguments */
  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"host", required_argument, 0, 'h'},
      {"port", required_argument, 0, 'p'},
      {"trusted", required_argument, 0, 't'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "h:p:t:0", long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'h':
        domain = optarg;
        imsg("Domain: %s", domain);
        break;
      case 'p':
        port = atoi(optarg);
        imsg("Port: %d", port);
        break;
      case 't':
        tmp = opendir(optarg);
        if (tmp)
        {
          trustdir = optarg;
          imsg("Trusted Root Certificates Directory: %s", trustdir);
          closedir(tmp);
        }
        else if (errno == ENOENT)
        {
          emsg("Directory \"%s\" does not exist", optarg);
          trustdir = NULL;
        }
        else
        {
          trustdir = NULL;
          emsg("Other error happened");
        }
        break;
      default:
        usage(pname);
    }
  }

  /* Handle errors */
  if (!domain)
  {
    err |= ERR_DOMAIN_NAME;
  }
  
  if (port < 0)
  {
    err |= ERR_PORT_NUMBER;
  }
  
  if (!trustdir)
  {
    err |= ERR_CERT_DIR;
  }

  if (err)
  {
    emsg("Error in arguments");
    if (err & ERR_DOMAIN_NAME)
      emsg("Please insert the domain name (or IP address) of the server with the '-h' or '--host' flag.");

    if (err & ERR_PORT_NUMBER)
      emsg("Please insert the port number of the server with the '-p' or '--port' flag.");

    if (err & ERR_CERT_DIR)
      emsg("Please insert the directory where the trusted root certificates are located with the '-t' or '--trusted' flag.");

    usage(pname);
  }

  /* Load trusted root certificates */
  trusted = load_trusted_root_cert_list(trustdir);

  /* Set the TCP connection with the server */
	server = open_connection(domain, port);
  if (server <= 2)
  {
    emsg("Open TCP connection failed");
    abort();
  }

  /* Send the Start message to Server */
  ret = send_message(server, start, strlen(start));
  if (ret == FAILURE)
  {
    emsg("Send the Start message failed");
    abort();
  }

  for (i=0; i<NUM_OF_PROBLEMS; i++)
  {
    imsg("===== Problem %d =====", i);
    /* Initialize the certificate list */
    list = init_cert_list();

    /* Receive the number of certificates from Server */
    ret = receive_message(server, buf, 1);
    if (ret == FAILURE)
    {
      emsg("Receive the number of certificates failed");
      abort();
    }
    clen = buf[0];
    imsg("Number of Certificates: %d", clen);
  
    for (j=0; j<clen; j++)
    {
      /* Receive the challenge message from Server */
      ret = receive_message(server, buf, BUF_SIZE);
      if (ret == FAILURE)
      {
        emsg("Receive the challenge message failed");
        abort();
      }
      rlen = ret;
    
      ret = add_buffer_to_list(buf, rlen, list);
      if (ret == FAILURE)
      {
        emsg("Error happened in adding the certificate to the list");
        abort();
      }
    }

    // Print the received certificate list
    print_cert_list(list);

    // TODO: Verify the certificate chain
    validation = verify_cert_list(list);
    print_validation_result(validation);

    ret = send_message(server, &validation, 1);
    if (ret == FAILURE)
    {
      emsg("Send the validation result failed");
      abort();
    }

    ret = receive_message(server, &answer, 1);
    if (ret == FAILURE)
    {
      emsg("Receive the answer failed");
      abort();
    }

    if (validation == answer)
    {
      imsg("Problem %d: Success (Validation Result: %d / Answer: %d)", i, validation, answer);
    }
    else
    {
      imsg("Problem %d: Failed (Validation Result: %d / Answer: %d)", i, validation, answer);
    }
  }
  imsg("======================");
  imsg("End of the Execution");

	return 0;
}

void print_validation_result(int validation)
{
  switch (validation)
  {
    case RESULT_NOT_SET:
      imsg("Result is not set");
      break;
    case CHAIN_VALIDATED:
      imsg("Chain is validated");
      break;
    case NO_ISSUER_FOUND:
      imsg("Issuer is not found");
      break;
    case WRONG_SIGNATURE:
      imsg("Signature is wrong");
      break;
    case NO_TRUSTED_ROOT:
      imsg("Root certificate is not trusted");
      break;
    default:
      emsg("Error happend");
  }
}

struct cert_list_st *load_trusted_root_cert_list(const char *trustdir)
{
  unsigned char cname[MAX_PATH_LEN] = {0, };
  struct cert_list_st *ret;
  struct cert_entry_st *entry;
  int i;

  ret = init_cert_list();
  for (i=0; i<MAX_NUM_OF_CERTS; i++)
  {
    memset(cname, 0x0, MAX_PATH_LEN);
    snprintf(cname, MAX_PATH_LEN, "%s/%d.crt", trustdir, i);
    dmsg("Trusted Root Certificate File: %s", cname);

    if (access(cname, F_OK) != -1)
    {
      entry = init_cert_entry(load_certificate(cname));
      add_cert_entry_to_list(entry, ret);
    }
    else
      break;
  }

  return ret;
}

// TODO: Implement the following function.
// Return Value: CHAIN_VALIDATED (1), NO_ISSUER_FOUND (2), WRONG_SIGNATURE (3),
// NO_TRUSTED_ROOT (4)
unsigned char verify_cert_list(struct cert_list_st *list)
{
  int ret;

  assert(list);
  ret = RESULT_NOT_SET;

  return ret;
}

// TODO: Implement the following function.
// Let say two certificates are the same if the subject and the issuer are the
// same. (This is not true in practice!)
// Return Value: TRUE (1) / FALSE (0)
int is_trusted_root_certificate(struct cert_entry_st *entry, struct cert_list_st *trusted)
{
  int ret;

  assert(entry);
  assert(trusted);
  ret = RESULT_NOT_SET;

  return ret;
}

