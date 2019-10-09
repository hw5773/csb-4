#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <assert.h>

#define DEBUG_LEVEL 2
#define ONE_LINE 16

#define LFINFO 0
#define LDEBUG 1
#define LINFO 2
#define LERROR 3

static int count_idx;

#if DEBUG_LEVEL <= LFINFO
#define fstart(format, ...) printf("[CSB/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define ffinish(format, ...) printf("[CSB/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define ferr(format, ...) printf("[CSB/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#else
#define fstart(format, ...)
#define ffinish(format, ...)
#define ferr(format, ...)
#endif /* LFINFO */

#if DEBUG_LEVEL <= LDEBUG
#define dmsg(format, ...) printf("[CSB/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
#define dprint(msg, buf, start, end, interval) \
  printf("[CSB/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
  for (count_idx = start; count_idx < end; count_idx++) \
  { \
    printf("%02X ", buf[count_idx]); \
    if (count_idx % interval == (interval - 1)) \
    { \
      printf("\n"); \
    } \
  } \
  printf("\n");
#else
#define dmsg(format, ...)
#define dprint(msg, buf, start, end, interval)
#endif /* DEBUG */

#if DEBUG_LEVEL <= LINFO
#define imsg(format, ...) printf("[CSB/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define iprint(msg, buf, start, end, interval) \
  printf("[CSB/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
  for (count_idx = start; count_idx < end; count_idx++) \
  { \
    printf("%02X ", buf[count_idx]); \
    if (count_idx % interval == (interval - 1)) \
    { \
      printf("\n"); \
    } \
  } \
  printf("\n");
#else
#define imsg(format, ...)
#define iprint(msg, buf, start, end, interval)
#endif /* INFO */

#if DEBUG_LEVEL <= LERROR
#define emsg(format, ...) printf("[CSB/ERROR] " format "\n", ## __VA_ARGS__)
#else
#define emsg(format, ...)
#endif /* ERROR */

#endif /* __DEBUG_H__ */
