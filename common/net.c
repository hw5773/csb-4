#include "net.h"
#include "defines.h"
#include "debug.h"
#include <assert.h>
#include <unistd.h>

int tcp_send(int fd, char *buf, int len)
{
  fstart("fd: %d, buf: %p, len: %d", fd, buf, len);
  int sent, offset;
  struct timeval tv;
  time_t curr, limit;
  gettimeofday(&tv, NULL);
  curr = tv.tv_sec;
  limit = curr + 10;

  sent = 0; offset = 0;
  while (sent < len && curr < limit)
  {
    offset = write(fd, buf, len);
    if (offset > 0)
      sent += offset;
    else if (offset == 0) 
    {
      emsg("Connection error");
      goto err;
    }
    gettimeofday(&tv, NULL);
    curr = tv.tv_sec;
  }

  if (sent < len)
  {
    emsg("Time out");
    goto err;
  }

  ffinish("sent: %d", sent);
  return sent;
err:
  ferr("sent: %d", FAILURE);
  return FAILURE;
}

int tcp_recv(int fd, char *buf, int len)
{
  fstart("fd: %d, buf: %p, len: %d", fd, buf, len);
  int rcvd, offset;
  struct timeval tv;
  time_t curr, limit;
  gettimeofday(&tv, NULL);
  curr = tv.tv_sec;
  limit = curr + 10;

  rcvd = 0; offset = 0;
  while (rcvd < len && curr < limit)
  {
    offset = read(fd, buf, len);
    if (offset > 0)
      rcvd += offset;
    else if (offset == 0) 
    {
      emsg("Connection error");
      goto err;
    }
    gettimeofday(&tv, NULL);
    curr = tv.tv_sec;
  }

  if (rcvd < len)
  {
    emsg("Time out");
    goto err;
  }

  ffinish("rcvd: %d", rcvd);
  return rcvd;
err:
  ferr("rcvd: %d", FAILURE);
  return FAILURE;
}

/**
 * @brief This function sends the message prepended with the length information
 * (mlen (2 bytes) || message (mlen bytes))
 * @param fd The socket file descriptor
 * @param msg The message to be sent
 * @param mlen The length of the message
 * @return The length of the sent message 
 * (the length information is not included)
 *
 */
int send_message(int fd, unsigned char *msg, int mlen)
{
  fstart("fd: %d, msg: %p, mlen: %d", fd, msg, mlen);
  int ret;
  char len[LENGTH_INFO_LEN];
  char *p;
  struct timeval tv;
  time_t sec;
  size_t tlen;

  assert(fd > 2);
  assert(msg != NULL);
  assert(mlen <= BUF_SIZE);

  /* Serialize the length of the message into the buffer */
  p = len;
  VAR_TO_PTR_2BYTES(mlen, p);

  /* Send the length of the message */
  ret = tcp_send(fd, len, LENGTH_INFO_LEN);
  if (ret == FAILURE) goto err;

  /* Send the message */
  ret = tcp_send(fd, msg, mlen);
  if (ret == FAILURE) goto err;

  dprint("Sent message", msg, 0, ret, ONE_LINE);
  ffinish("sent: %d", ret);
  return ret;
err:
  ferr("sent: %d", ret);
  return FAILURE;
}

/**
 * @brief This function receives message in the form of 
 * tlen (2 bytes) || timestamp (tlen bytes) || mlen (2 bytes) || message (mlen bytes)
 * @param ssl The SSL context
 * @param buf The buffer to receive the message
 * @param rlen The length of the received message
 * @param ts The pointer to the received timestamp
 * @return The function returns the received len
 */
int receive_message(int fd, unsigned char *buf, int rlen)
{
  fstart("fd: %d, buf: %p, rlen: %d", fd, buf, rlen);
  int ret;
  char len[LENGTH_INFO_LEN];
  char seconds[TIMESTAMP_LEN];
  char *p;
  int tlen, mlen;

  assert(fd > 2);
  assert(buf != NULL);
  assert(rlen > 0);

  /* Receive the length of the message */
  ret = tcp_recv(fd, len, LENGTH_INFO_LEN);
  if (ret != LENGTH_INFO_LEN)
  {
    emsg("Received length mismatch: required: %d, received: %d", LENGTH_INFO_LEN, ret);
    goto err;
  }
  p = len;
  PTR_TO_VAR_2BYTES(p, mlen);

  if (mlen > rlen)
  {
    emsg("Insufficient buffer size: the server has sent %d bytes, but the size of the buffer is only %d bytes", mlen, rlen);
    goto err;
  }
  
  /* Receive the message */
  ret = tcp_recv(fd, buf, mlen);
  if (ret != mlen)
  {
    emsg("Received length mismatch: required: %d, received: %d", mlen, ret);
    goto err;
  }

  dprint("Received message", buf, 0, ret, ONE_LINE);
  ffinish("ret: rcvd: %d", ret);
  return ret;
err:
  ferr("ret: rcvd: %d", FAILURE);
  return FAILURE;
}
