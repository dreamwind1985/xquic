#ifndef __POC_COMMON_H__
#define __POC_COMMON_H__
#define _GNU_SOURCE
#include <stdio.h>
#include <event2/event.h>
#include <memory.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>
#include <./src/transport/xqc_engine.h>
#include <./src/transport/xqc_conn.h>
#include <getopt.h>
#include <src/common/xqc_hash.h>

void poc_hex_print(char *p, size_t n);
ssize_t poc_h3_request_send_headers_raw_data(xqc_h3_stream_t *h3s, xqc_var_buf_t *data, uint8_t fin);
ssize_t poc_h3_request_header_qpack_encoder(xqc_h3_stream_t *h3s, xqc_http_headers_t *headers, xqc_var_buf_t *data);
xqc_int_t poc_h3_request_format_headers(xqc_h3_request_t *h3_request,
                              xqc_http_headers_t *headers_in,
                              xqc_http_headers_t *headers,
                              uint8_t fin);

#endif /* __POC_COMMON_H__ */
