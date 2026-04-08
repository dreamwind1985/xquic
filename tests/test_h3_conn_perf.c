/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * 
 * HTTP/3 连接性能测试程序
 * 功能：测试 HTTP/3 新建连接的性能，握手成功后立即断开连接，不发起请求
 */

#include "client_common.h"
#include <sys/time.h>

extern int g_conn_timeout;
extern xqc_conn_settings_t *g_conn_settings;
extern int g_conn_count;
extern int g_transport;

/* 性能统计 */
typedef struct {
    uint64_t total_conn_count;          /* 总连接数 */
    uint64_t success_conn_count;        /* 成功握手的连接数 */
    uint64_t failed_conn_count;         /* 失败的连接数 */
    uint64_t total_handshake_time_us;   /* 总握手时间（微秒） */
    uint64_t min_handshake_time_us;     /* 最小握手时间 */
    uint64_t max_handshake_time_us;     /* 最大握手时间 */
    xqc_usec_t start_time;              /* 测试开始时间 */
    xqc_usec_t end_time;                /* 测试结束时间 */
} perf_stats_t;

static perf_stats_t g_perf_stats = {0};

/* 多进程相关 */
extern int g_process_num;
extern uint64_t g_process_count_array[MAX_PROCESS_NUM];

/* 获取当前时间（微秒） */
static inline xqc_usec_t
get_current_time_us()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * H3 连接创建通知
 */
int
test_h3_conn_perf_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *)user_data;
    user_conn->h3_conn = conn;
    
    /* 记录连接创建时间 */
    if (user_conn->ext_data == NULL) {
        xqc_usec_t *create_time = malloc(sizeof(xqc_usec_t));
        *create_time = get_current_time_us();
        user_conn->ext_data = create_time;
    }
    
    return 0;
}

/**
 * H3 连接关闭通知
 */
int
test_h3_conn_perf_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *)user_data;
    
    if (user_conn) {
        /* 释放扩展数据 */
        if (user_conn->ext_data) {
            free(user_conn->ext_data);
            user_conn->ext_data = NULL;
        }
        
        /* 释放连接资源 */
        if (user_conn->ev_socket) {
            event_del(user_conn->ev_socket);
            if (user_conn->fd != -1) {
                close(user_conn->fd);
                user_conn->fd = -1;
            }
        }
        
        if (user_conn->ev_timeout) {
            event_del(user_conn->ev_timeout);
        }
        
        g_user_stats.conc_conn_count--;
        
        client_ctx_t *ctx = user_conn->ctx;
        ctx->cur_conn_num--;
        
        /* 所有连接都完成后退出事件循环 */
        if (ctx->cur_conn_num == 0 && g_conn_count >= g_max_conn_num) {
            g_perf_stats.end_time = get_current_time_us();
            event_base_loopbreak(ctx->eb);
        }
    }
    
    return 0;
}

/**
 * H3 握手完成通知 - 握手成功后立即断开连接
 */
void
test_h3_conn_perf_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    user_conn_t *user_conn = (user_conn_t *)user_data;
    
    if (user_conn == NULL) {
        return;
    }
    
    /* 计算握手时间 */
    if (user_conn->ext_data) {
        xqc_usec_t *create_time = (xqc_usec_t *)user_conn->ext_data;
        xqc_usec_t handshake_time = get_current_time_us() - *create_time;
        
        /* 更新统计信息 */
        g_perf_stats.success_conn_count++;
        g_perf_stats.total_handshake_time_us += handshake_time;
        
        if (g_perf_stats.min_handshake_time_us == 0 || 
            handshake_time < g_perf_stats.min_handshake_time_us) {
            g_perf_stats.min_handshake_time_us = handshake_time;
        }
        
        if (handshake_time > g_perf_stats.max_handshake_time_us) {
            g_perf_stats.max_handshake_time_us = handshake_time;
        }
        
        /* 每 100 个连接打印一次进度 */
        if (g_perf_stats.success_conn_count % 100 == 0) {
            printf("Handshake finished: %lu connections, avg time: %.2f ms\n",
                   g_perf_stats.success_conn_count,
                   (double)g_perf_stats.total_handshake_time_us / 
                   g_perf_stats.success_conn_count / 1000.0);
        }
    }
    
    /* 握手成功后立即主动关闭连接 */
    client_ctx_t *ctx = user_conn->ctx;
    if (ctx && ctx->engine) {
        xqc_h3_conn_close(ctx->engine, &user_conn->cid);
    }
}

/**
 * 创建连接回调
 */
static void
test_h3_conn_perf_create_conn_callback(int fd, short what, void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *)arg;
    
    /* 注册 H3 回调 */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = test_h3_conn_perf_create_notify,
            .h3_conn_close_notify = test_h3_conn_perf_close_notify,
            .h3_conn_handshake_finished = test_h3_conn_perf_handshake_finished,
            .h3_conn_ping_acked = NULL,
        },
        .h3r_cbs = {
            .h3_request_close_notify = NULL,
            .h3_request_read_notify = NULL,
            .h3_request_write_notify = NULL,
            .h3_request_closing_notify = NULL,
        }
    };
    
    static int h3_ctx_inited = 0;
    if (!h3_ctx_inited) {
        int ret = xqc_h3_ctx_init(ctx->engine, &h3_cbs);
        if (ret != XQC_OK) {
            printf("init h3 context error, ret:%d\n", ret);
            exit(-1);
        }
        h3_ctx_inited = 1;
    }
    
    /* 控制连接创建速率 */
    if (g_conn_count < g_max_conn_num) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = (1000000 / g_conn_num);
        event_add(ctx->ev_conc, &tv);
        
        /* 创建用户连接 */
        user_conn_t *user_conn = client_create_user_conn_and_event(ctx, g_server_addr, 
                                                                    g_server_port, 0);
        if (user_conn == NULL) {
            printf("client_create_user_conn_and_event error\n");
            g_perf_stats.failed_conn_count++;
            return;
        }
        
        /* 配置 SSL */
        xqc_conn_ssl_config_t conn_ssl_config;
        memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
        conn_ssl_config.session_ticket_data = NULL;
        conn_ssl_config.transport_parameter_data = NULL;
        
        /* 创建 H3 连接 */
        const xqc_cid_t *cid = xqc_h3_connect(ctx->engine, g_conn_settings, 
                                             user_conn->token, user_conn->token_len,
                                             g_host, g_no_crypto_flag, &conn_ssl_config, 
                                             user_conn->peer_addr, user_conn->peer_addrlen, 
                                             user_conn);
        
        if (cid == NULL) {
            printf("xqc_h3_connect error\n");
            g_perf_stats.failed_conn_count++;
            return;
        }
        
        g_conn_count++;
        ctx->cur_conn_num++;
        g_user_stats.conc_conn_count++;
        g_user_stats.total_conn_count++;
        g_perf_stats.total_conn_count++;
        
        memcpy(&user_conn->cid, cid, sizeof(*cid));
        user_conn->ctx = ctx;
    }
}

/**
 * 打印性能统计结果
 */
static void
print_perf_stats()
{
    printf("\n");
    printf("========================================\n");
    printf("  HTTP/3 Connection Performance Test\n");
    printf("  Process ID: %d\n", getpid());
    printf("========================================\n");
    printf("Total connections:     %lu\n", g_perf_stats.total_conn_count);
    printf("Successful handshakes: %lu\n", g_perf_stats.success_conn_count);
    printf("Failed connections:    %lu\n", g_perf_stats.failed_conn_count);
    printf("Success rate:          %.2f%%\n", 
           g_perf_stats.total_conn_count > 0 ? 
           (double)g_perf_stats.success_conn_count * 100.0 / g_perf_stats.total_conn_count : 0);
    printf("\n");
    
    if (g_perf_stats.success_conn_count > 0) {
        double avg_handshake_time = (double)g_perf_stats.total_handshake_time_us / 
                                   g_perf_stats.success_conn_count;
        printf("Handshake Time Statistics:\n");
        printf("  Min:     %.2f ms\n", g_perf_stats.min_handshake_time_us / 1000.0);
        printf("  Max:     %.2f ms\n", g_perf_stats.max_handshake_time_us / 1000.0);
        printf("  Average: %.2f ms\n", avg_handshake_time / 1000.0);
        printf("\n");
    }
    
    if (g_perf_stats.end_time > g_perf_stats.start_time) {
        double total_time_sec = (double)(g_perf_stats.end_time - g_perf_stats.start_time) / 1000000.0;
        double conn_per_sec = g_perf_stats.success_conn_count / total_time_sec;
        printf("Overall Performance:\n");
        printf("  Total time:        %.2f seconds\n", total_time_sec);
        printf("  Connections/sec:   %.2f\n", conn_per_sec);
    }
    printf("========================================\n");
}

/**
 * 统计线程 - 定期打印统计信息
 */
static void
print_stat_thread(void)
{
    while (1) {
        sleep(5);
        
        printf("\n[Progress] PID: %d, Success: %lu, Failed: %lu, Total: %lu\n",
               getpid(),
               g_perf_stats.success_conn_count,
               g_perf_stats.failed_conn_count,
               g_perf_stats.total_conn_count);
        
        if (g_perf_stats.success_conn_count > 0) {
            double avg_time = (double)g_perf_stats.total_handshake_time_us / 
                             g_perf_stats.success_conn_count / 1000.0;
            printf("[Progress] Avg handshake time: %.2f ms\n", avg_time);
        }
    }
}

/**
 * 创建测试上下文
 */
static client_ctx_t *
test_h3_conn_perf_create_ctx(xqc_engine_ssl_config_t *engine_ssl_config,
                             xqc_transport_callbacks_t *tcbs, 
                             xqc_config_t *config)
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
    
    ctx->ev_conc = event_new(ctx->eb, -1, 0, test_h3_conn_perf_create_conn_callback, ctx);
    if (ctx->ev_conc == NULL) {
        return NULL;
    }
    
    /* 立即开始创建连接 */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
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

int
main(int argc, char *argv[])
{
    /* 初始化服务器地址 */
    memset(g_server_addr, 0, sizeof(g_server_addr));
    strncpy(g_server_addr, TEST_SERVER_ADDR, sizeof(g_server_addr) - 1);
    g_server_port = TEST_SERVER_PORT;
    
    /* 解析命令行参数 */
    if (client_parse_args(argc, argv, NULL, "") < 0) {
        printf("parse arg error\n");
        return -1;
    }
    
    /* 强制使用 HTTP/3 */
    g_transport = 0;
    
    /* 不创建流 */
    g_stream_num_per_conn = 0;
    
    printf("=== HTTP/3 Connection Performance Test ===\n");
    printf("Server:      %s:%d\n", g_server_addr, g_server_port);
    printf("Connections: %d\n", g_max_conn_num);
    printf("Rate:        %d conn/s\n", g_conn_num);
    printf("Processes:   %d\n", g_process_num);
    printf("===========================================\n\n");
    
    /* 初始化全局变量 */
    if (client_initial_global_var() != XQC_OK) {
        printf("initial error\n");
        return -1;
    }
    
    /* 创建多进程 */
    if (client_fork_multi_process() != XQC_OK) {
        printf("fork processes error\n");
        return -1;
    }
    
    /* 配置 SSL */
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    
    /* 配置传输层回调 */
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
    
    /* 配置引擎 */
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    config.cid_len = DEFAULT_CID_LEN;
    
    /* 创建测试上下文 */
    client_ctx_t *ctx = test_h3_conn_perf_create_ctx(&engine_ssl_config, &tcbs, &config);
    if (ctx == NULL) {
        printf("ctx create error\n");
        return -1;
    }
    
    /* 记录开始时间 */
    g_perf_stats.start_time = get_current_time_us();
    
    /* 启动统计线程 */
    pthread_t stat_thread_id;
    int ret = pthread_create(&stat_thread_id, NULL, (void *)print_stat_thread, NULL);
    if (ret != 0) {
        printf("Create stat thread error!\n");
    }
    
    /* 启动事件循环 */
    printf("Starting test... (PID: %d)\n\n", getpid());
    event_base_dispatch(ctx->eb);
    
    /* 打印性能统计 */
    print_perf_stats();
    
    return 0;
}
