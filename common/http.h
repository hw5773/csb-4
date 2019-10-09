#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdio.h>
#include <stdint.h>

#define INDEX_FILE "/index.html"
#define INDEX_FILE_LEN 12

struct rinfo
{
  FILE *fp;
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size; // total size including the header size
  uint32_t sent; // actual sent size
  uint32_t rlen; // header size
};

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen);
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
int http_parse_response(uint8_t *msg, uint32_t mlen);

static int char_to_int(uint8_t *str, uint32_t slen) 
{
	int i;
	int ret = 0;
	uint8_t ch;

	for (i = 0; i < slen; i++) {
		ch = str[i];
		if (ch == ' ')
			break;

		switch (ch) {
		case '0':
			ret *= 10;
			continue;
		case '1':
			ret = ret * 10 + 1;
			continue;
		case '2':
			ret = ret * 10 + 2;
			continue;
		case '3':
			ret = ret * 10 + 3;
			continue;
		case '4':
			ret = ret * 10 + 4;
			continue;
		case '5':
			ret = ret * 10 + 5;
			continue;
		case '6':
			ret = ret * 10 + 6;
			continue;
		case '7':
			ret = ret * 10 + 7;
			continue;
		case '8':
			ret = ret * 10 + 8;
			continue;
		case '9':
			ret = ret * 10 + 9;
			continue;
		}
	}

	return ret;
}
#endif /* __HTTP_H__ */
