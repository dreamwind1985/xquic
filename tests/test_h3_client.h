#ifndef __TEST_H3_CLIENT_H__
#define __TEST_H3_CLIENT_H__
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

#define XQC_ALPN_TRANSPORT      "transport"
#define DEFAULT_CID_LEN 16

int client_test_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
int client_test_release_user_conn(user_conn_t *user_conn);
int client_test_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data);
int client_test_user_close_conn_proactive(user_conn_t *user_conn);
int client_test_handshake_finished(user_conn_t *user_conn);
void client_test_conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data);
void client_test_conn_ping_acked_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data, void *conn_proto_data);
int client_test_stream_write_notify(xqc_stream_t *stream, void *user_data);
int client_test_stream_read_notify(xqc_stream_t *stream, void *user_data);
int client_test_stream_close_notify(xqc_stream_t *stream, void *user_data);
int client_test_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
int client_test_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data);
void client_test_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data);
void client_test_h3_conn_ping_acked_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *user_data);
int client_test_request_close_notify(xqc_h3_request_t *h3_request, void *user_data);
int client_test_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream);
int client_test_request_write_notify(xqc_h3_request_t *h3_request, void *user_data);
int client_test_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data);
int client_test_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data);
void client_test_request_closing_notify(xqc_h3_request_t *h3_request, 
    xqc_int_t err, void *h3s_user_data);
void client_test_create_req_callback(int fd, short what, void *arg);
user_conn_t *client_test_user_conn_create(client_ctx_t *ctx, const char *server_addr, int server_port,
    int transport);
 
 

 
#endif /* __TEST_H3_CLIENT_H__ */
