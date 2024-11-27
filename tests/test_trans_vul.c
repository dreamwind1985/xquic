/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "src/http3/xqc_h3_request.h"
#include "client_common.h" 
#include "poc_common.h"

extern int g_conn_timeout;

extern xqc_conn_settings_t *g_conn_settings;

extern int g_conn_count;
extern int g_transport;


/* 
 * 用于持续往crytpo_stream流中发送short header封装的crypto frame
 * 用于验证当frame的offset发生空洞时，收包缓存占用内存是否会持续增长
 */
int
test_trans_stream_send(xqc_stream_t *stream, void *user_data)
{
    user_stream_t *user_stream = (user_stream_t *) user_data;
    user_conn_t *user_conn = user_stream->user_conn;
    xqc_connection_t *conn = user_conn->quic_conn;

    //xqc_stream_t *crypto_stream = stream;
    xqc_stream_t *crypto_stream = conn->crypto_stream[XQC_ENC_LEV_HSK];
    int i = 0, j = 0, len = 1000;
    for (i = 0; i < 10000; i++) {
        xqc_hs_buffer_t *buf = xqc_malloc(sizeof(xqc_hs_buffer_t) + len);
        xqc_init_list_head(&buf->list_head);
        if (buf == NULL) {
            printf("malloc error\n");
            return -1;
        }
        buf->data_len = len;
        for (j = 0; i < len; i++) {
            buf->data[i] = 0xF;
        }
 
        poc_crypto_stream_send(crypto_stream, buf, XQC_PTYPE_SHORT_HEADER); 
        if (i % 1000 == 999) {
            printf("send crypto stream:%d\n", i);
        }
    }
    xqc_engine_main_logic(user_conn->ctx->engine);
    sleep(1);
    return 0;
}

void
test_trans_create_stream_callback(int fd, short what, void *arg)
{
    user_conn_t *user_conn = (user_conn_t *)arg;
    xqc_engine_t *engine = user_conn->ctx->engine;
    xqc_cid_t *cid = &user_conn->cid; 
    if (user_conn->total_stream_num < g_stream_num_per_conn) {
        int i = 0;
        for (i = 0; i < g_req_per_time; i++) {
            user_stream_t *user_stream = calloc(1, sizeof(user_stream_t));
            
            if(user_stream == NULL){
                return;
            }
            user_stream->stream = xqc_stream_create(engine, cid, user_stream);
            if (user_stream->stream == NULL) {
                return;
            }
            user_stream->user_conn = user_conn;
            g_user_stats.conc_stream_count++;
            g_user_stats.total_stream_count++;

            user_conn->cur_stream_num++;
            user_conn->total_stream_num++;
            if (user_conn->total_stream_num >= g_stream_num_per_conn) {
                break;
            }
            test_trans_stream_send(user_stream->stream, user_stream);
        } 
    }
    if (user_conn->total_stream_num < g_stream_num_per_conn) {
        struct timeval tv;
        tv.tv_sec = g_req_intval/1000;
        tv.tv_usec = (g_req_intval%1000)*1000;
        event_add(user_conn->ev_req, &tv);  
    }
}

int
test_trans_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    user_stream_t *user_stream = (user_stream_t *) user_data;
    user_conn_t *user_conn = user_stream->user_conn;
    xqc_connection_t *conn = user_conn->quic_conn;
    //xqc_stream_t *crypto_stream = conn->crypto_stream[XQC_ENC_LEV_HSK];
    xqc_stream_t *crypto_stream = stream;

    test_trans_stream_send(stream, user_data); 

    return 0;
}

static void
test_trans_create_conn_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *)arg;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = (1000000/(g_conn_num));
    event_add(ctx->ev_conc, &tv);

    /* register transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = client_conn_create_notify_default,
            .conn_close_notify = client_conn_close_notify_default,
            .conn_handshake_finished = client_conn_handshake_finished_notify_default,
            .conn_ping_acked = client_conn_ping_acked_notify_null,
        },
        .stream_cbs = {
            .stream_write_notify = test_trans_stream_write_notify,
            .stream_read_notify = client_stream_read_notify_null,
            .stream_close_notify = client_stream_close_notify_null,
        }
    };

    xqc_engine_register_alpn(ctx->engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs);

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    conn_ssl_config.session_ticket_data = NULL;
    conn_ssl_config.transport_parameter_data = NULL;

    g_conn_timeout = 3600; /* 连接超时时间设置为一个小时 */
    if (g_conn_count < g_max_conn_num) {
        event_add(ctx->ev_conc, &tv);
        user_conn_t *user_conn = client_create_user_conn_and_event(ctx, g_server_addr, g_server_port, g_transport);
        
        if (user_conn == NULL) {
            printf("test_trans_user_conn_create error\n");
            return;
        }

        const xqc_cid_t *cid;

        cid = xqc_connect(ctx->engine, g_conn_settings, user_conn->token, user_conn->token_len,
                          g_host, g_no_crypto_flag, &conn_ssl_config, user_conn->peer_addr, 
                          user_conn->peer_addrlen, XQC_ALPN_TRANSPORT, user_conn);

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
        user_conn->ev_req = event_new(ctx->eb, -1, 0, test_trans_create_stream_callback, user_conn); 
        
        struct timeval tv;
        tv.tv_sec = g_req_intval / 1000;
        tv.tv_usec = (g_req_intval % 1000) * 1000;
        event_add(user_conn->ev_req, &tv); 
    }
    return;
}


client_ctx_t *
test_trans_create_ctx(xqc_engine_ssl_config_t *engine_ssl_config,
    xqc_transport_callbacks_t *tcbs, xqc_config_t *config)
{
    client_ctx_t *ctx = client_create_and_initial_ctx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->eb = event_base_new();

    if(ctx->eb == NULL){
        return NULL;
    }

    ctx->ev_engine = event_new(ctx->eb, -1, 0, client_engine_callback, ctx);
    if(ctx->ev_engine == NULL){
        return NULL;
    }
    ctx->ev_conc = event_new(ctx->eb, -1, 0, test_trans_create_conn_callback, ctx);
    if(ctx->ev_conc == NULL){
        return NULL;
    }
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ctx->ev_conc, &tv);

    xqc_engine_callback_t callback = {
        .set_event_timer = client_set_event_timer, /* call xqc_engine_main_logic when the timer expires */
        .log_callbacks = {
            .xqc_log_write_err = client_write_log,
            .xqc_log_write_stat = client_write_log,
        },
        .keylog_cb = client_keylog_cb,
        .cid_generate_cb = NULL, /* 设置cid */
    };

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, config, engine_ssl_config, &callback, tcbs, ctx);

    if(ctx->engine == NULL){
        return NULL;
    }
    return ctx;
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

    if (g_transport != 1) {
        printf("error: only support transport layer test\n");
        return -1;
    }

    if (client_initial_global_var() != XQC_OK) {
        printf("initial error\n");
        return -1;
    }

    if (client_fork_multi_process() != XQC_OK) {
        printf("fork processes error\n");
        return -1;
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
    client_ctx_t * ctx = NULL;
    ctx = test_trans_create_ctx(&engine_ssl_config, &tcbs, &config);
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

