#include "client_common.h"

#define MAX_CONN_NUM 1000

#define TOKEN_FILE      "./xqc_token"
#define SESSION_FILE    "./test_session"
#define TP_FILE         "./tp_localhost"
#define CLIENT_LOG_FILE "./clog"
#define XQC_MAX_LOG_LEN 2048

#define CLIENT_KEY_LOG  "./ckeys.log"

#define MAX_QPACK_KEY_LEN 128
#define MAX_QPACK_VALUE_LEN 4096
#define HTTP_BODY_MAX_SIZE 1024*1024


int     g_debug_flag = 0;
char    g_server_addr[64];
int     g_server_port;
int     g_use_1rtt = 0;
int     g_no_crypto_flag = 0;
int     g_conn_num = 1;
int     g_max_conn_num = MAX_CONN_NUM;
int     g_stream_num_per_conn = 10;
int     g_qpack_header_num = 10;
int     g_req_body_len = (1024 * 1);
int     g_test_mode = 0;
int     g_process_num = 1;
int     g_session_len = 0;
int     g_tp_len = 0;
FILE    * g_stats_fp;
int     g_req_per_time = 1;
int     g_req_intval = 1000; /* 单位毫秒 */
int     g_transport = 0;
user_stats_t g_user_stats;
char g_session_ticket_data[8192]={0};
char g_tp_data[8192] = {0};
unsigned char g_token[XQC_MAX_TOKEN_LEN];
int g_token_len = XQC_MAX_TOKEN_LEN;
uint64_t g_process_count_array[MAX_PROCESS_NUM];

xqc_http_header_t g_headers[MAX_HEADER_SIZE];
int     g_header_cnt;
char    g_header_file[256] = {0};

char    g_host[256] = "localhost";
char    g_path[256] = "/index.html";
char    g_scheme[8] = "https";

void
client_set_event_timer(xqc_msec_t wake_after, void *user_data)
{
    client_ctx_t *ctx = (client_ctx_t *) user_data;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

void
client_save_session_cb(const char * data, size_t data_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;

    FILE * fp  = fopen(SESSION_FILE, "wb");
    if (fp == NULL) {
        printf("open session file error\n");
        return;
    }
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

void
client_save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;

    FILE * fp = fopen(TP_FILE, "wb");
    int write_size = fwrite(data, 1, data_len, fp);
    if(data_len != write_size){
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}

void
client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t*)user_data;
    printf("xqc_client_save_token use client ip as the key. h3[%d]\n", user_conn->h3);

    int fd = open(TOKEN_FILE, O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
    if (fd < 0) {
        printf("save token error %s\n", strerror(errno));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(errno));
        close(fd);
        return;
    }
    close(fd);
}

int
client_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open(TOKEN_FILE, O_RDONLY);
    if (fd < 0) {
        printf("read token error %s\n", strerror(errno));
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    close(fd);
    return n;
}

int
client_read_file_data( char * data, size_t data_len, char *filename)
{
    FILE * fp = fopen(filename, "rb");

    if(fp == NULL){
        printf("read file error:%s\n", filename);
        return -1;
    }
    fseek(fp, 0 , SEEK_END);
    size_t total_len  = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if(total_len > data_len) {
        printf("read file error:%s\n", filename);
        return -1;
    }

    size_t read_len = fread(data, 1, total_len, fp);
    if (read_len != total_len) {
        printf("read file error:%s, read_len:%lu, total_len:%lu\n",
                filename, read_len, total_len);
        return -1;
    }

    fclose(fp);
    return read_len;
}

void 
client_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN + 1];

    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("xqc_client_write_log fd err\n");
        return;
    }

    int log_len = snprintf(log_buf, XQC_MAX_LOG_LEN + 1, "%s\n", (char *)buf);
    if (log_len < 0) {
        printf("xqc_client_write_log err\n");
        return;
    }

    int write_len = write(ctx->log_fd, log_buf, log_len);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", errno);
    }
}


int 
client_cert_verify(const unsigned char *certs[], 
    const size_t cert_len[], size_t certs_len, void *conn_user_data)
{
    /* self-signed cert used in test cases, return >= 0 means success */
    return 0;
}

ssize_t
client_write_log_file(void *engine_user_data, const void *buf, size_t count)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        printf("client write long file error\n");
        return -1;
    }
    return write(ctx->log_fd, buf, count);
}

/*
 * key log functions
 */


int
client_open_keylog_file(client_ctx_t *ctx)
{
    ctx->keylog_fd = open(CLIENT_KEY_LOG, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->keylog_fd <= 0) {
        return -1;
    }

    return 0;
}


int
client_open_log_file(void *engine_user_data)
{
    client_ctx_t *ctx = (client_ctx_t*)engine_user_data;
    ctx->log_fd = open(CLIENT_LOG_FILE, (O_WRONLY | O_APPEND | O_CREAT), 0644);
    if (ctx->log_fd <= 0) {
        return -1;
    }
    return 0;
}

void 
client_keylog_cb(const xqc_cid_t *scid, const char *line, void *user_data)
{
    return;
}



void 
convert_addr_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len)
{
    if (type == AF_INET6) {
        *saddr = calloc(1, sizeof(struct sockaddr_in6));
        memset(*saddr, 0, sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)(*saddr);
        inet_pton(type, addr_text, &(addr_v6->sin6_addr.s6_addr));
        addr_v6->sin6_family = type;
        addr_v6->sin6_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in6);

    } else {
        *saddr = calloc(1, sizeof(struct sockaddr_in));
        memset(*saddr, 0, sizeof(struct sockaddr_in));
        struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
        inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
        addr_v4->sin_family = type;
        addr_v4->sin_port = htons(port);
        *saddr_len = sizeof(struct sockaddr_in);
    }
}


ssize_t
client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    user_conn_t *user_conn = (user_conn_t *) user;
    ssize_t res;
    int fd = user_conn->fd;
    do {
        errno = 0;
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("xquic client_write_socket err %zd %s\n", res, strerror(errno));
            if (errno == EAGAIN) {
                res = XQC_SOCKET_EAGAIN; 
            }
        }
        if(res > 0){
            g_user_stats.send_bytes_count += res;
        }
    } while ((res < 0) && (errno == EINTR));
    return res;
}

int 
client_conn_closing_notify(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data)
{
    //printf("conn closing: %d\n", err_code);
    return XQC_OK;
}

void 
client_fill_stream_http_header(xqc_http_headers_t *http_header)
{
    http_header->headers = g_headers;
    http_header->count = g_header_cnt;
}


user_stream_t *
client_create_user_stream(xqc_engine_t * engine, user_conn_t *user_conn, xqc_cid_t * cid)
{
    user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
    if(user_stream == NULL){
        return NULL;
    }
    if (user_conn->h3 == 0) {
        user_stream->h3_request = xqc_h3_request_create(engine, cid, user_stream);
        if (user_stream->h3_request == NULL) {
            return NULL;
        }
    } else {
        user_stream->stream = xqc_stream_create(engine, cid, user_stream);
        if (user_stream->stream == NULL) {
            return NULL;
        }
    }
    user_stream->user_conn = user_conn;
    g_user_stats.conc_stream_count++;
    g_user_stats.total_stream_count++;

    client_fill_stream_http_header(&user_stream->http_header);
    return user_stream;
}



/* 注意不要有多余的空格，多余的空格会作为字符串放进header；最后一行需要有\n，否则不读 */
int
client_read_http_headers_from_file(xqc_http_header_t *header_array, int max_header_num,
    char * file_path, char *header_buffer, int header_buf_size)
{
    int read_len = client_read_file_data(header_buffer, header_buf_size - 1, file_path);
    if(read_len < 0) {
        return 0;
    }

    header_buffer[read_len] = '\0';

    int header_count = 0;
    char * p = header_buffer;

    while (*p != '\0') {
        char *end_p = strchr(p, '\n');

        if(end_p == NULL) {
            break;
        }
        *end_p = '\0';
        
        if ((end_p - 1 > p) && (*(end_p - 1) == '\r')) {
            *(end_p - 1) = '\0'; //如果是\r\n则都设置为0
        }

        char *split_p = strchr(p, ':');
        if (split_p != NULL) {
            header_array[header_count].name.iov_base = p;
            header_array[header_count].name.iov_len = split_p - p;
            header_array[header_count].value.iov_base = split_p + 1;
            header_array[header_count].value.iov_len = strlen(split_p + 1);
            header_array[header_count].flags = 0;
            if (header_array[header_count].name.iov_len == 0
                    || header_array[header_count].value.iov_len == 0) {
                printf("error http header file line:%s\n", p);
            } else {
                header_count++;
                if(header_count >= max_header_num){
                    break;
                }
            }
        } 

        *end_p = '\n';
        p = end_p;
        p++;
    }
    return header_count;
}

int
client_fill_default_headers(xqc_http_header_t *header_array,
    int max_header_num, int *header_cnt)
{
    if (*header_cnt + 4 > max_header_num) {
        return -1;
    }
    header_array[(*header_cnt)].name.iov_base = ":method";
    header_array[(*header_cnt)].name.iov_len = 7;
    header_array[(*header_cnt)].value.iov_base = "GET";
    header_array[(*header_cnt)].value.iov_len = 3;
    header_array[(*header_cnt)].flags = 0;
    (*header_cnt)++;

    header_array[(*header_cnt)].name.iov_base = ":scheme";
    header_array[(*header_cnt)].name.iov_len = 7;
    header_array[(*header_cnt)].value.iov_base = g_scheme;
    header_array[(*header_cnt)].value.iov_len = strlen(g_scheme);
    header_array[(*header_cnt)].flags = 0;
    (*header_cnt)++;

    header_array[(*header_cnt)].name.iov_base = "host";
    header_array[(*header_cnt)].name.iov_len = 4;
    header_array[(*header_cnt)].value.iov_base = g_host;
    header_array[(*header_cnt)].value.iov_len = strlen(g_host);
    header_array[(*header_cnt)].flags = 0;
    (*header_cnt)++;

    header_array[(*header_cnt)].name.iov_base = ":path";
    header_array[(*header_cnt)].name.iov_len = 5;
    header_array[(*header_cnt)].value.iov_base = g_path;
    header_array[(*header_cnt)].value.iov_len = strlen(g_path);
    header_array[(*header_cnt)].flags = 0;
    (*header_cnt)++;
    return 0;
}


/* 定时调用main_logic */
void
client_engine_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}


int
client_check_close_user_conn(user_conn_t * user_conn)
{
    if(user_conn->cur_stream_num > 0 || user_conn->total_stream_num <= g_stream_num_per_conn ){
        return 0;
    }

    if(user_conn->cur_stream_num < 0) {
        printf("error cur_stream_num little than 0\n");
        return -1;
    }

    client_ctx_t *ctx = user_conn->ctx;
    int rc = xqc_conn_close(ctx->engine, &user_conn->cid);
    if(rc){
        printf("xqc_conn_close error\n");
        return 0;
    }
    return 0;
}

void
client_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid, const xqc_cid_t *new_cid, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *) user_data;
    memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));
    //if (g_debug_flag) {
        client_ctx_t *ctx = user_conn->ctx;
        printf("====>SCID:%s\n", xqc_scid_str(new_cid));
        printf("====>DCID:%s\n", xqc_dcid_str_by_scid(ctx->engine, new_cid));
    //}
}


void
client_init_addr(user_conn_t *user_conn,
    const char *server_addr, int server_port)
{
    int ip_type = AF_INET; /* 暂时没有支持ipv6 */
    convert_addr_text_to_sockaddr(ip_type, 
                                      server_addr, server_port,
                                      &user_conn->peer_addr, 
                                      &user_conn->peer_addrlen);

    if (ip_type == AF_INET6) {
        user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in6));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in6));
        user_conn->local_addrlen = sizeof(struct sockaddr_in6);

    } else {
        user_conn->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
        memset(user_conn->local_addr, 0, sizeof(struct sockaddr_in));
        user_conn->local_addrlen = sizeof(struct sockaddr_in);
    }
}



int 
client_create_socket(int type, 
    const struct sockaddr *saddr, socklen_t saddr_len, char *interface)
{
    int size;
    int fd = -1;

    /* create fd & set socket option */
    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno: %d\n", errno);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno: %d\n", errno);
        goto err;
    }

    size = 1 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("setsockopt failed, errno: %d\n", errno);
        goto err;
    }

    /* connect to peer addr */
    if (connect(fd, (struct sockaddr *)saddr, saddr_len) < 0) {
        printf("connect socket failed, errno: %d\n", errno);
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}



void
client_socket_write_handler(user_conn_t *user_conn)
{
    client_ctx_t *p_ctx;
    p_ctx = user_conn->ctx;

    xqc_conn_continue_send(p_ctx->engine, &user_conn->cid);

    return;
}



void
client_socket_read_handler(user_conn_t *user_conn, int fd)
{
    xqc_int_t ret;
    ssize_t recv_size = 0;
    ssize_t recv_sum = 0;

    client_ctx_t *p_ctx;
    p_ctx = user_conn->ctx;
    unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

    static ssize_t last_rcv_sum = 0;
    static ssize_t rcv_sum = 0;

    do {
        recv_size = recvfrom(fd,
                             packet_buf, sizeof(packet_buf), 0, 
                             user_conn->peer_addr, &user_conn->peer_addrlen);
        if (recv_size < 0 && errno == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd(%s)\n", recv_size, strerror(errno));
            break;
        }

        /* if recv_size is 0, break while loop, */
        if (recv_size == 0) {
            break;
        }

        recv_sum += recv_size;
        rcv_sum += recv_size;

        if (user_conn->get_local_addr == 0) {
            user_conn->get_local_addr = 1;
            socklen_t tmp = sizeof(struct sockaddr_in6);
            int ret = getsockname(user_conn->fd, (struct sockaddr *) user_conn->local_addr, &tmp);
            if (ret < 0) {
                printf("getsockname error, errno: %d\n", errno);
                break;
            }
            user_conn->local_addrlen = tmp;
        }

        uint64_t recv_time = now();

        ret = xqc_engine_packet_process(p_ctx->engine, packet_buf, recv_size,
                                      user_conn->local_addr, user_conn->local_addrlen,
                                      user_conn->peer_addr, user_conn->peer_addrlen,
                                      (xqc_msec_t)recv_time, user_conn);
        if (ret != XQC_OK) {
            printf("xqc_client_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
	
	if (recv_size > 0) {
	    g_user_stats.recv_bytes_count += recv_size;
	}
    } while (recv_size > 0);

    xqc_engine_finish_recv(p_ctx->engine);
    return;
}

/* write and read 的实际action，linux系统就是调用read和write接口 */
void
client_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        client_socket_write_handler(user_conn);

    } else if (what & EV_READ) {
        client_socket_read_handler(user_conn, fd);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}



/* 用于限制单个连接的存活时间 */
void
client_timeout_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *) arg;
    int rc;
    client_ctx_t *ctx = user_conn->ctx;

    rc = xqc_conn_close(ctx->engine, &user_conn->cid);
    if (rc) {
        printf("xqc_conn_close error\n");
        return;
    }
    ctx->cur_conn_num--;

    printf("xqc_conn_close, %d connetion rest\n", ctx->cur_conn_num);
}

int
client_print_stats(void)
{

    static uint64_t last_record_time = 0;
    static user_stats_t last_user_stats;

    uint64_t cur_time = now();
    int pid = getpid();

    if (last_record_time == 0) {
        fprintf(g_stats_fp,"conn_per_second:%d, max connection:%d, \
                stream_per_second:%d, qpack header key_value num:%d, \
                http body len:%d, test mode:%d, process_num:%d\n",
                g_conn_num, g_max_conn_num, g_stream_num_per_conn,
                g_qpack_header_num, g_req_body_len, g_test_mode, 
                g_process_num);
    }

    if (last_record_time > 0) {

        struct timeval tv;
        gettimeofday(&tv, NULL);

        struct tm tm;
        localtime_r(&tv.tv_sec, &tm);
        tm.tm_mon++;
        tm.tm_year += 1900;
        fprintf(g_stats_fp, "%4d/%02d/%02d %02d:%02d:%02d %06ld\n",
                tm.tm_year, tm.tm_mon,
                tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec, tv.tv_usec);
        fprintf(g_stats_fp, "pid:%d, total_conn:%lu, total_stream:%lu, conc_conn:%lu, conc_stream:%lu, total_send:%lu, total_recv:%lu, total_req:%lu, total_res:%lu\n",
                pid, g_user_stats.total_conn_count, g_user_stats.total_stream_count, g_user_stats.conc_conn_count, g_user_stats.conc_stream_count,
                g_user_stats.send_bytes_count, g_user_stats.recv_bytes_count, g_user_stats.send_request_count, g_user_stats.recv_response_count);

        uint64_t past_time = cur_time - last_record_time;
        uint64_t new_conn = g_user_stats.total_conn_count - last_user_stats.total_conn_count;
        uint64_t new_stream = g_user_stats.total_stream_count - last_user_stats.total_stream_count;
        uint64_t send_b = g_user_stats.send_bytes_count - last_user_stats.send_bytes_count;
        uint64_t recv_b = g_user_stats.recv_bytes_count - last_user_stats.recv_bytes_count;
        uint64_t send_req = g_user_stats.send_request_count - last_user_stats.send_request_count;
        uint64_t recv_res = g_user_stats.recv_response_count - last_user_stats.recv_response_count;

        new_conn = (new_conn * 1000000)/past_time;
        new_stream = (new_stream * 1000000)/past_time;
        send_b = (send_b *1000000)/past_time;
        recv_b = (recv_b *1000000)/past_time;
        send_req = (send_req * 1000000)/past_time;
        recv_res = (recv_res * 1000000)/past_time;
        fprintf(g_stats_fp,"new_conn_rate:%lu, new_stream_rate:%lu, send_byte_rate:%luKB, recv_byte_rate:%luKB, send_req_rate:%lu, recv_req_rate:%lu\n\n",
                new_conn, new_stream, send_b/1000, recv_b/1000, send_req, recv_res);

        fflush(g_stats_fp);
    }
    memcpy(&last_user_stats, &g_user_stats, sizeof(user_stats_t));
    last_record_time = cur_time;

    return 0;
}


void
client_print_stat_thread(void)
{
    while(1) {
        client_print_stats();
        static int n_second = 0;

        
        if(n_second % 30 == 0){

            int i = 0;
            for(i = 0; i < MAX_PROCESS_NUM; i++){
                //printf("proc_n:%d\t hash_count:%lu\n",i,g_process_count_array[i]);
            }
            printf("\n");
        }

        n_second++;
        sleep(1);
    }
}

int
client_parse_args(int argc, char *argv[], client_arg_parse_callback c_cb, char *c_args)
{

    int ch = 0;
    printf("useage: \n"
            "-a server address, default 127.0.0.1\n"
            "-p server port, default 8443\n"
            "-r 0rtt 0, 1RTT 1,default 0\n"
            "-t text crypto: 0, no crypto 1, default 0\n"
            "-c create connection per second, default 1\n"
            "-C MAX connection num, default 1000 \n"
            "-s max stream num per conn, default 10 \n"
            "-q qpack header key_value num ,default 10\n"
            "-b http request body length , default 1024\n"
            "-m test mode: 0 test concurrent, 1 test new create mode, 2 one connection,multi stream\n"
            "-P process num: default 1\n"
            "-Q request num create per time: default 1\n"
            "-I request create interval, default 0\n"
            "-u host url, default 127.0.0.1\n"
            "-T Transport protocol: 0 H3 (default), 1 Transport layer, 2 H3-ext.\n"
            "-H header file path\n"
            "-D print debug info to std io\n"
            "-h print help\n");
    sleep(1);
    char args[2048] = {0};
    snprintf(args, sizeof(args), "a:p:r:t:c:C:s:q:b:m:P:Q:I:u:T:H:Dh%s", c_args);
    while ((ch = getopt(argc, argv, args)) != -1) {
        switch(ch)
        {
            case 'a':
                printf("option a:'%s'\n", optarg);
                snprintf(g_server_addr, sizeof(g_server_addr), optarg);
                break;
            case 'p':
                printf("option port :%s\n", optarg);
                g_server_port = atoi(optarg);
                break;

            case 'r':
                printf("use_1rtt flag:%s\n", optarg);
                g_use_1rtt = atoi(optarg);
                break;
            case 't':
                printf("no crypto flag:%s\n", optarg);
                g_no_crypto_flag = atoi(optarg);
                break;
            case 'c':
                printf("create connection per second :%s\n", optarg);
                g_conn_num = atoi(optarg);
                break;
            case 'C':
                printf("MAX connection num:%s\n", optarg);
                g_max_conn_num = atoi(optarg);
                break;
            case 's': /*  */
                printf("stream num per conn :%s\n", optarg);
                g_stream_num_per_conn = atoi(optarg);
                break;
            case 'q':
                printf("qpack header key_value num :%s\n", optarg);
                g_qpack_header_num = atoi(optarg);
                break;
            case 'b':
                g_req_body_len = atoi(optarg);
                printf("http request body len:%s\n", optarg);
                break;
            case 'Q': /* Number of Parallel requests to create everytime. Default 1. */
                g_req_per_time = atoi(optarg);
                printf("option req_paral :%s\n", optarg);
                break;
            case 'm':
                g_test_mode = atoi(optarg);
                switch (g_test_mode) {
                    case 0:
                        printf("test mode : 测试并发模式\n");
                        break;
                    case 1:
                        printf("test mode : 测试新建模式\n");
                        break;
                    case 2:
                        printf("test mode : 测试长连多stream模式\n");
                        break;
                    default:
                        printf("error mode:%s", optarg);
                        return -1;
                }
                break;
            case 'P':
                printf("process num:%s\n", optarg);
                g_process_num = atoi(optarg);
                break;
            case 'I':
                printf("stream create interval:%s\n", optarg);
                g_req_intval = atoi(optarg);
                break;
            case 'u': /* Url. default https://test.xquic.com/path/resource */
                printf("option url :%s\n", optarg);
                sscanf(optarg, "%[^://]://%[^/]%s", g_scheme, g_host, g_path);
                break;
            case 'T': /* Transport layer. No HTTP3. */
                printf("option transport :%s\n", "on");
                g_transport = atoi(optarg);
                break;
            case 'H':
                printf("header file path:%s\n", optarg);
                snprintf(g_header_file, sizeof(g_header_file), optarg);
                break;
            case 'D':
                printf("debug info print:%s\n", optarg);
                g_debug_flag = 1;
                break;
            case 'h':
                printf("help info already print\n");
                return -2; 
            default:
                if (c_cb) {
                    xqc_int_t ret = c_cb(ch, optarg);
                    if (ret == XQC_OK) {
                        break;
                    }
                }
                printf("other option :%c\n", ch);
                return -1;

        }
    }
    return 0;
}

