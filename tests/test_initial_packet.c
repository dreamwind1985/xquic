/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * 
 * 测试文件：用于发送指定次数的 initial 报文
 * 功能：
 * 1. 发送指定次数的 initial 报文，创建指定个数的连接，但只发送 initial 报文
 * 2. 支持两种模式：
 *    - 正常模式：发送正常的 initial 报文
 *    - 异常模式：发送异常的 initial 报文（报文头部可以正常解析，但 payload 部分解密失败）
 */

#include "src/http3/xqc_h3_request.h"
#include "client_common.h" 
#include "poc_common.h"
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

extern int g_conn_timeout;
extern xqc_conn_settings_t *g_conn_settings;
extern int g_conn_count;
extern int g_transport;

/* 全局变量：控制 initial 报文发送次数和模式 */
static int g_initial_packet_count = 10;        /* 要发送的 initial 报文次数 */
static int g_initial_packet_mode = 0;          /* 0: 正常模式, 1: 异常模式 */
static int g_sent_initial_count = 0;           /* 已发送的 initial 报文计数 */

/**
 * 构造正常的 initial 报文
 * 返回构造的报文长度，失败返回负数
 */
static ssize_t
build_normal_initial_packet(xqc_connection_t *conn, unsigned char *buf, size_t buf_size)
{
    xqc_packet_out_t *packet_out;
    xqc_int_t ret;
    size_t enc_pkt_len = 0;

    /* 创建 packet_out */
    packet_out = xqc_packet_out_create(XQC_PACKET_OUT_BUF_CAP);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create packet_out error|");
        return -XQC_EMALLOC;
    }

    packet_out->po_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_out->po_pkt.pkt_pns = XQC_PNS_INIT;
    
    /* 获取 packet number */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    packet_out->po_pkt.pkt_num = pn_ctl->ctl_packet_number[XQC_PNS_INIT]++;

    /* 生成 long packet header */
    ret = xqc_gen_long_packet_header(packet_out,
                                     conn->dcid_set.current_dcid.cid_buf, 
                                     conn->dcid_set.current_dcid.cid_len,
                                     conn->scid_set.user_scid.cid_buf, 
                                     conn->scid_set.user_scid.cid_len,
                                     conn->conn_token, 
                                     conn->conn_token_len,
                                     conn->version, 
                                     XQC_PKTNO_BITS);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|gen long packet header error|%d|", ret);
        xqc_packet_out_destroy(packet_out);
        return ret;
    }

    packet_out->po_used_size = ret;

    /* 添加 CRYPTO frame（包含 ClientHello） */
    xqc_stream_t *crypto_stream = conn->crypto_stream[XQC_ENC_LEV_INIT];
    if (crypto_stream && !xqc_list_empty(&crypto_stream->stream_write_buff_list.write_buff_list)) {
        xqc_stream_write_buff_t *buff = xqc_list_entry(crypto_stream->stream_write_buff_list.write_buff_list.next,
                                                       xqc_stream_write_buff_t, sw_list);
        if (buff && buff->data_length > 0) {
            size_t written = 0;
            ssize_t frame_len = xqc_gen_crypto_frame(packet_out, 
                                                     buff->data_offset,
                                                     buff->sw_data, 
                                                     buff->data_length, 
                                                     &written);
            if (frame_len > 0) {
                packet_out->po_used_size += frame_len;
                packet_out->po_frame_types |= XQC_FRAME_BIT_CRYPTO;
            }
        }
    }

    /* 添加 PADDING frame 以满足 initial 报文最小长度要求 (1200 字节) */
    while (packet_out->po_used_size < XQC_PACKET_INITIAL_MIN_LENGTH - XQC_TLS_AEAD_OVERHEAD_MAX_LEN) {
        if (packet_out->po_used_size >= packet_out->po_buf_size) {
            break;
        }
        packet_out->po_buf[packet_out->po_used_size++] = 0x00; /* PADDING frame */
        packet_out->po_frame_types |= XQC_FRAME_BIT_PADDING;
    }

    /* 加密报文 */
    ret = xqc_packet_encrypt_buf(conn, packet_out, buf, buf_size, &enc_pkt_len);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|packet encrypt error|%d|", ret);
        xqc_packet_out_destroy(packet_out);
        return ret;
    }

    xqc_packet_out_destroy(packet_out);
    return enc_pkt_len;
}

/**
 * 构造异常的 initial 报文
 * 报文头部正常，但 payload 部分故意使用错误的数据，导致解密失败
 */
static ssize_t
build_malformed_initial_packet(xqc_connection_t *conn, unsigned char *buf, size_t buf_size)
{
    xqc_packet_out_t *packet_out;
    xqc_int_t ret;
    size_t header_len;
    unsigned char *dst_buf;

    /* 创建 packet_out */
    packet_out = xqc_packet_out_create(XQC_PACKET_OUT_BUF_CAP);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create packet_out error|");
        return -XQC_EMALLOC;
    }

    packet_out->po_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_out->po_pkt.pkt_pns = XQC_PNS_INIT;
    
    /* 获取 packet number */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    packet_out->po_pkt.pkt_num = pn_ctl->ctl_packet_number[XQC_PNS_INIT]++;

    /* 生成 long packet header */
    ret = xqc_gen_long_packet_header(packet_out,
                                     conn->dcid_set.current_dcid.cid_buf, 
                                     conn->dcid_set.current_dcid.cid_len,
                                     conn->scid_set.user_scid.cid_buf, 
                                     conn->scid_set.user_scid.cid_len,
                                     conn->conn_token, 
                                     conn->conn_token_len,
                                     conn->version, 
                                     XQC_PKTNO_BITS);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|gen long packet header error|%d|", ret);
        xqc_packet_out_destroy(packet_out);
        return ret;
    }

    header_len = ret;
    packet_out->po_used_size = header_len;

    /* 添加一些随机数据作为 payload（这些数据无法正确解密） */
    dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t payload_len = XQC_PACKET_INITIAL_MIN_LENGTH - header_len - XQC_TLS_AEAD_OVERHEAD_MAX_LEN;
    
    if (payload_len > packet_out->po_buf_size - packet_out->po_used_size) {
        payload_len = packet_out->po_buf_size - packet_out->po_used_size;
    }

    /* 填充随机数据 */
    for (size_t i = 0; i < payload_len; i++) {
        dst_buf[i] = (unsigned char)(rand() % 256);
    }
    packet_out->po_used_size += payload_len;

    /* 复制 header 到输出缓冲区 */
    if (packet_out->po_used_size > buf_size) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|buffer too small|");
        xqc_packet_out_destroy(packet_out);
        return -XQC_ENOBUF;
    }

    memcpy(buf, packet_out->po_buf, header_len);
    
    /* 复制随机 payload 数据 */
    memcpy(buf + header_len, dst_buf, payload_len);
    
    /* 添加假的 AEAD tag */
    size_t total_len = header_len + payload_len;
    for (size_t i = 0; i < XQC_TLS_AEAD_OVERHEAD_MAX_LEN && total_len < buf_size; i++) {
        buf[total_len++] = (unsigned char)(rand() % 256);
    }

    /* 更新 length 字段 */
    unsigned char *plength = buf + (packet_out->po_ppktno - packet_out->po_buf) - XQC_LONG_HEADER_LENGTH_BYTE;
    uint32_t length = total_len - header_len;
    xqc_vint_write(plength, length, 0x01, 2);

    xqc_packet_out_destroy(packet_out);
    return total_len;
}

/**
 * 自定义的 write_socket 函数，用于发送 initial 报文
 */
static ssize_t
test_initial_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user)
{
    user_conn_t *user_conn = (user_conn_t *)user;
    
    /* 只在第一次发送时拦截，后续让正常流程处理 */
    if (g_sent_initial_count < g_initial_packet_count) {
        xqc_connection_t *conn = user_conn->quic_conn;
        unsigned char packet_buf[XQC_PACKET_OUT_BUF_CAP];
        ssize_t packet_len;

        /* 根据模式构造报文 */
        if (g_initial_packet_mode == 0) {
            /* 正常模式 */
            packet_len = build_normal_initial_packet(conn, packet_buf, sizeof(packet_buf));
        } else {
            /* 异常模式 */
            packet_len = build_malformed_initial_packet(conn, packet_buf, sizeof(packet_buf));
        }

        if (packet_len < 0) {
            printf("build initial packet error: %zd\n", packet_len);
            return packet_len;
        }

        /* 发送报文 */
        ssize_t sent = sendto(user_conn->fd, packet_buf, packet_len, 0, 
                             peer_addr, peer_addrlen);
        if (sent < 0) {
            printf("sendto error: %s\n", strerror(errno));
            return sent;
        }

        g_sent_initial_count++;
        printf("Sent initial packet %d/%d, mode: %s, size: %zd bytes\n",
               g_sent_initial_count, g_initial_packet_count,
               g_initial_packet_mode == 0 ? "normal" : "malformed",
               sent);

        /* 如果已经发送完所有报文，不再继续发送 */
        if (g_sent_initial_count >= g_initial_packet_count) {
            printf("All initial packets sent. Total: %d\n", g_sent_initial_count);
            return sent;
        }

        return sent;
    }

    /* 使用默认的 write_socket */
    return client_write_socket(buf, size, peer_addr, peer_addrlen, user);
}

/**
 * 连接创建回调
 */
static void
test_initial_create_conn_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *)arg;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; /* 100ms 间隔 */

    /* 注册 transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = client_conn_create_notify_default,
            .conn_close_notify = client_conn_close_notify_default,
            .conn_handshake_finished = client_conn_handshake_finished_notify_default,
            .conn_ping_acked = client_conn_ping_acked_notify_null,
        },
        .stream_cbs = {
            .stream_write_notify = client_stream_read_notify_null,
            .stream_read_notify = client_stream_read_notify_null,
            .stream_close_notify = client_stream_close_notify_null,
        }
    };

    xqc_engine_register_alpn(ctx->engine, XQC_ALPN_TRANSPORT, 9, &ap_cbs, NULL);

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    conn_ssl_config.session_ticket_data = NULL;
    conn_ssl_config.transport_parameter_data = NULL;

    g_conn_timeout = 3600; /* 连接超时时间设置为一个小时 */

    if (g_sent_initial_count < g_initial_packet_count) {
        event_add(ctx->ev_conc, &tv);
        
        user_conn_t *user_conn = client_create_user_conn_and_event(ctx, g_server_addr, 
                                                                    g_server_port, g_transport);
        if (user_conn == NULL) {
            printf("client_create_user_conn_and_event error\n");
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

        memcpy(&user_conn->cid, cid, sizeof(*cid));
        user_conn->ctx = ctx;

        printf("Created connection %d, waiting to send initial packet...\n", 
               g_sent_initial_count + 1);
    } else {
        printf("All connections created. Total initial packets to send: %d\n", 
               g_initial_packet_count);
    }
}

/**
 * 创建测试上下文
 */
static client_ctx_t *
test_initial_create_ctx(xqc_engine_ssl_config_t *engine_ssl_config,
    xqc_transport_callbacks_t *tcbs, xqc_config_t *config)
{
    client_ctx_t *ctx = client_create_and_initial_ctx();
    if (ctx == NULL) {
        return NULL;
    }
    
    ctx->eb = event_base_new();
    if (ctx->eb == NULL) {
        return NULL;
    }

    ctx->ev_engine = event_new(ctx->eb, -1, 0, client_engine_callback, ctx);
    if (ctx->ev_engine == NULL) {
        return NULL;
    }
    
    ctx->ev_conc = event_new(ctx->eb, -1, 0, test_initial_create_conn_callback, ctx);
    if (ctx->ev_conc == NULL) {
        return NULL;
    }
    
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ctx->ev_conc, &tv);

    xqc_engine_callback_t callback = {
        .set_event_timer = client_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = client_write_log,
            .xqc_log_write_stat = client_write_log,
        },
        .keylog_cb = client_keylog_cb,
        .cid_generate_cb = NULL,
    };

    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, config, engine_ssl_config, 
                                    &callback, tcbs, ctx);
    if (ctx->engine == NULL) {
        return NULL;
    }
    
    return ctx;
}

/**
 * 解析命令行参数
 */
static int
parse_test_args(int argc, char *argv[])
{
    int opt;
    /* 保存原始的 optind，因为 client_parse_args 也会使用 getopt */
    int saved_optind = optind;
    int saved_opterr = opterr;
    
    /* 临时禁用 getopt 的错误输出 */
    opterr = 0;
    optind = 1;
    
    while ((opt = getopt(argc, argv, "c:m:a:p:s:t:l:e:E:d:u:n:x:1:r:")) != -1) {
        switch (opt) {
        case 'c':
            g_initial_packet_count = atoi(optarg);
            if (g_initial_packet_count <= 0) {
                printf("Invalid packet count: %s\n", optarg);
                opterr = saved_opterr;
                return -1;
            }
            break;
        case 'm':
            g_initial_packet_mode = atoi(optarg);
            if (g_initial_packet_mode != 0 && g_initial_packet_mode != 1) {
                printf("Invalid mode: %s (must be 0 or 1)\n", optarg);
                opterr = saved_opterr;
                return -1;
            }
            break;
        default:
            /* 忽略其他参数，让 client_parse_args 处理 */
            break;
        }
    }
    
    /* 恢复 optind 和 opterr，让 client_parse_args 可以重新解析所有参数 */
    optind = saved_optind;
    opterr = saved_opterr;
    return 0;
}

int
main(int argc, char *argv[])
{
    memset(g_server_addr, 0, sizeof(g_server_addr));
    strncpy(g_server_addr, TEST_SERVER_ADDR, sizeof(g_server_addr) - 1);
    g_server_port = TEST_SERVER_PORT;

    /* 解析测试参数 */
    if (parse_test_args(argc, argv) < 0) {
        return -1;
    }

    printf("=== Initial Packet Test ===\n");
    printf("Packet count: %d\n", g_initial_packet_count);
    printf("Packet mode: %s\n", g_initial_packet_mode == 0 ? "normal" : "malformed");
    printf("Server: %s:%d\n", g_server_addr, g_server_port);
    printf("===========================\n\n");

    if (client_parse_args(argc, argv, NULL, "") < 0) {
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

    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    xqc_transport_callbacks_t tcbs = {
        .write_socket = test_initial_write_socket,  /* 使用自定义的 write_socket */
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
    config.cid_len = DEFAULT_CID_LEN;

    client_ctx_t *ctx = test_initial_create_ctx(&engine_ssl_config, &tcbs, &config);
    if (ctx == NULL) {
        printf("ctx create error\n");
        return -1;
    }

    pthread_t id;
    int ret = pthread_create(&id, NULL, (void *)client_print_stat_thread, NULL);
    if (ret != 0) {
        printf("Create pthread error!\n");
        return -1;
    }

    event_base_dispatch(ctx->eb);
    
    printf("\n=== Test Summary ===\n");
    printf("Total initial packets sent: %d\n", g_sent_initial_count);
    printf("Mode: %s\n", g_initial_packet_mode == 0 ? "normal" : "malformed");
    printf("====================\n");

    return 0;
}
