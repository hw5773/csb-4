#include "http.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define DELIMITER 		"\r\n"
#define DELIMITER_LEN 2

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
    uint32_t clen, uint8_t *msg, uint32_t *mlen) {
  const uint8_t *get = "GET /";
  const uint8_t *http = " HTTP/1.1";
  const uint8_t *host = "Host: ";
  const uint8_t *header = "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n\r\n";
  uint32_t hlen;
  uint8_t *p; 

  hlen = strlen(header);

  p = msg;

  memcpy(p, get, 5); 
  p += 5;

  if (clen > 0) {
    memcpy(p, content, clen);
    p += clen;
  }
  memcpy(p, http, 9); 
  p += 9;

  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;
  memcpy(p, host, 6); 
  p += 6;
  memcpy(p, domain, dlen);
  p += dlen;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  memcpy(p, header, hlen);
  p += hlen;
  *(p++) = 0;

  *mlen = p - msg;

  return *mlen;
}

int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r) {
	(void) mlen;
	int l;
	uint8_t *cptr, *nptr, *p, *q;
	struct rinfo *info;

	info = r;
	cptr = msg;

	while ((nptr = strstr(cptr, DELIMITER))) {
		l = nptr - cptr;
		p = cptr;

		while (*p == ' ')
			p++;

		if ((l > 0) && (strncmp((const char *) p, "GET", 3) == 0)) {
			p += 3;

			while (*p != '/')
				p++;

			q = p;

			while (*q != ' ' && *q != '\r')
				q++;

			if (q - p == 1) {
				info->content = (uint8_t *) malloc(INDEX_FILE_LEN + 1);
				memset(info->content, 0x0, INDEX_FILE_LEN + 1);
				memcpy(info->content, INDEX_FILE, INDEX_FILE_LEN);
				info->clen = INDEX_FILE_LEN;
			} else {
				info->content = (uint8_t *) malloc(q - p + 1);
				memset(info->content, 0x0, q - p + 1);
				memcpy(info->content, p, q - p);
				info->clen = q - p;
			}
		}

		if ((l > 0) && (strncmp((const char *) p, "Host:", 5) == 0)) {
			p += 5;

			while (*p == ' ')
				p++;

			info->domain = (uint8_t *) malloc(nptr - p + 1);
			memset(info->domain, 0x0, nptr - p + 1);
			memcpy(info->domain, p, nptr - p);
			info->dlen = nptr - p;
		}

		cptr = nptr + DELIMITER_LEN;

	}

	return 1;
}

int http_parse_response(uint8_t *msg, uint32_t mlen)
{
  int ret, hlen;
  uint32_t i, j, l;
  uint8_t *cptr, *nptr, *p;
  cptr = msg;
  ret = INT_MAX;
  hlen = 0;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;
    hlen += (l + 2);
    if (l == 0)
      break;

    p = cptr;

    for (i=0; i<l; i++)
    {
      if (p[i] == ' ')
        break;
    }

    if ((l > 0) && (strncmp((const char *)p, "Content-Length:", i) == 0))
    {
      for (j=i+1; j<l; j++)
      {
        if (p[j] == ' ')
          break;
      }
      ret = char_to_int(p + i + 1, j - i);
    }

    cptr = nptr + DELIMITER_LEN;
  }

  return ret + hlen;
}
