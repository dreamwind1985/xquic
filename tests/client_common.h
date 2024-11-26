
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef __CLIENT_COMMON_H__
#define __CLIENT_COMMON_H__
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
#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_SERVER_ADDR "127.0.0.1"
#define TEST_SERVER_PORT 8443

#define MAX_PROCESS_NUM 32

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)
//#define XQC_MAX_TOKEN_LEN 32
#define MAX_HEADER_SIZE 128
#define XQC_ALPN_TRANSPORT      "transport"
#define XQC_ALPN_TRANSPORT_TEST "transport-test"
#define DEFAULT_CID_LEN 16

typedef struct user_conn_s user_conn_t;

typedef struct user_stats{
    uint64_t        total_conn_count;
    uint64_t        total_stream_count;
    uint64_t        conc_conn_count;
    uint64_t        conc_stream_count;

    uint64_t        send_bytes_count;
    uint64_t        recv_bytes_count;
    uint64_t        send_request_count;
    uint64_t        recv_response_count;
}user_stats_t;

typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    user_conn_t        *user_conn;
    xqc_http_headers_t http_header;
    char               *send_body;
    size_t              send_body_len;
    uint64_t            send_offset;

    int                 header_sent;

    int                 header_recvd;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    FILE               *recv_body_fp;
    int                 recv_fin;
    xqc_msec_t          start_time;
} user_stream_t;

typedef struct client_ctx_s {
    xqc_engine_t        *engine;
    struct event        *ev_engine;
    struct event_base   *eb;
    int                 log_fd;
    int                 keylog_fd;
    int                 no_crypto_flag;

    struct event        *ev_conc;
    int                 cur_conn_num;
} client_ctx_t;

typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;
    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;
    xqc_flag_t          get_local_addr;

    unsigned char      *token;
    unsigned            token_len;

    struct event       *ev_socket;
    struct event       *ev_timeout;

    int                 h3;
    client_ctx_t        *ctx;

    xqc_connection_t   *quic_conn;
    xqc_h3_conn_t      *h3_conn;
    int                 send_request_count;
    int                 recv_response_count;
    int                 cur_stream_num;
    int                 total_stream_num;
    struct event       *ev_req;
    void               *ext_data;
} user_conn_t;


extern int      g_debug_flag;
extern char     g_server_addr[64];
extern int      g_server_port;
extern int      g_use_1rtt;
extern int      g_no_crypto_flag;
extern int      g_conn_num;
extern int      g_max_conn_num;
extern int      g_stream_num_per_conn;
extern int      g_qpack_header_num;
extern int      g_req_body_len;
extern int      g_test_mode;
extern int      g_process_num;
extern int      g_session_len;
extern int      g_tp_len;
extern int      g_req_per_time;
extern FILE     *g_stats_fp;
extern user_stats_t g_user_stats;
extern char     g_session_ticket_data[8192];
extern char     g_tp_data[8192];
extern unsigned char g_token[XQC_MAX_TOKEN_LEN];
extern int      g_token_len;
extern uint64_t g_process_count_array[MAX_PROCESS_NUM];
extern int      g_req_intval; /* 单位毫秒 */
extern xqc_http_header_t g_headers[MAX_HEADER_SIZE];
extern int      g_header_cnt;
extern char     g_header_file[256];

extern char     g_host[256];
extern char     g_path[256];
extern char     g_scheme[8];


typedef xqc_int_t (*client_arg_parse_callback)(int ch, char *p_arg); 

static inline uint64_t
now()
{
    /*获取微秒单位时间*/
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ul = tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
    return  ul;
}
void client_set_event_timer(xqc_msec_t wake_after, void *user_data);
void client_save_session_cb(const char * data, size_t data_len, void *user_data);
void client_save_tp_cb(const char * data, size_t data_len, void * user_data);
void client_save_token(const unsigned char *token, unsigned token_len, void *user_data);

int client_read_token(unsigned char *token, unsigned token_len);
int client_read_file_data( char * data, size_t data_len, char *filename);
void client_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data);
int client_cert_verify(const unsigned char *certs[], 
    const size_t cert_len[], size_t certs_len, void *conn_user_data);
ssize_t client_write_log_file(void *engine_user_data, const void *buf, size_t count);
int client_open_keylog_file(client_ctx_t *ctx);
int client_open_log_file(void *engine_user_data);
void client_keylog_cb(const xqc_cid_t *scid, const char *line, void *user_data);

int client_print_stats(void);
void client_print_stat_thread(void);
int client_parse_args(int argc, char *argv[], client_arg_parse_callback c_cb, char *c_args);
void xqc_convert_addr_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len);
ssize_t client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user);
user_stream_t *client_create_user_stream(xqc_engine_t * engine,
    user_conn_t *user_conn, xqc_cid_t * cid);
int client_fill_default_headers(xqc_http_header_t *header_array,
    int max_header_num, int *header_cnt);
int client_read_http_headers_from_file(xqc_http_header_t *header_array, int max_header_num,
    char * file_path, char *header_buffer, int header_buf_size);
void client_engine_callback(int fd, short what, void *arg);
int client_check_close_user_conn(user_conn_t * user_conn);
 
void client_timeout_callback(int fd, short what, void *arg);
void client_socket_event_callback(int fd, short what, void *arg);
int client_create_socket(int type, 
    const struct sockaddr *saddr, socklen_t saddr_len, char *interface);
void client_init_addr(user_conn_t *user_conn,
    const char *server_addr, int server_port);
void client_socket_write_handler(user_conn_t *user_conn);
void client_socket_read_handler(user_conn_t *user_conn, int fd);
int client_close_conn_proactive(user_conn_t *user_conn);
user_conn_t *client_create_user_conn_and_event(client_ctx_t *ctx, const char *server_addr,
    int server_port, int transport);
client_ctx_t *client_create_and_initial_ctx();
int client_initial_global_var();
int client_fork_multi_process();
/* notify 函数 */
void client_conn_update_cid_notify(xqc_connection_t *conn,
    const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data);
xqc_int_t client_conn_closing_notify(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data);
int client_stream_read_notify_null(xqc_stream_t *stream, void *user_data);
int client_stream_close_notify_null(xqc_stream_t *stream, void *user_data);
void client_conn_ping_acked_notify_null(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data,
    void *user_data, void *conn_proto_data);
int client_conn_create_notify_default(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data);
void client_conn_handshake_finished_notify_default(xqc_connection_t *conn, void *user_data,
    void *conn_proto_data);
int client_conn_close_notify_default(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *conn_proto_data);
#endif  /* __CLIENT_COMMON_H__ */
