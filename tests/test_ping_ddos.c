#define _GNU_SOURCE
#include <stdio.h>
#include <event2/event.h>
#include <memory.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>
#include "platform.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <getopt.h>

#include "client_common.h" 
#include "test_h3_client.h"
#include "poc_common.h"

struct event_base *eb;

struct sockaddr_in g_server_sock_addr;

uint64_t g_random_seed = 0;
int
send_udp_data(char *server_ip, int server_port, uint8_t *data, size_t data_len)
{
    int sockfd;
    struct sockaddr_in server_addr;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket creation failed");
        return XQC_ERROR;
    } 
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // 发送数据到服务器
    if (sendto(sockfd, data, data_len, 0, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        printf("sendto failed");
        return XQC_ERROR;
    }
    // 关闭套接字
    close(sockfd);
    return 0;

}

int
random_generate(uint8_t *buf, size_t buf_len)
{
    int i = 0;
    srandom(time(NULL) + g_random_seed++);
    for (i = 0; i < buf_len; i++) {
        buf[i] = random() & 0xFF;
    }
    //poc_hex_print(buf, buf_len);
    return XQC_OK;
}

int 
do_action()
{
    xqc_packet_out_t *packet_out =  poc_raw_create_packet_out(XQC_PTYPE_INIT);
    xqc_cid_t odcid, oscid;
    xqc_cid_t *dcid = &odcid, *scid= &oscid;
    char token[0]; 
    uint32_t token_len = 0;
    int ret = 0;

    memset(dcid, 0, sizeof(odcid));
    memset(scid, 0, sizeof(oscid));
   
    dcid->cid_len = DEFAULT_CID_LEN;
    scid->cid_len = DEFAULT_CID_LEN;

    random_generate(dcid->cid_buf, dcid->cid_len);
    random_generate(scid->cid_buf, scid->cid_len);


    ret = poc_raw_gen_long_packet_header(packet_out, dcid->cid_buf, dcid->cid_len,
            scid->cid_buf, scid->cid_len, token, token_len);

    if (ret != XQC_OK) {
        printf("raw gen long packet header error\n");
        return ret;
    }
    ret = xqc_gen_ping_frame(packet_out);
    if (ret < 0 ) {
        printf("gen ping frame error\n");
        return ret;
    }

    poc_gen_padding_frame(packet_out);
    
    xqc_log_t *log = xqc_log_init(0, 0, 0, 0, 0, NULL, NULL, NULL);

    xqc_crypto_t *crypto = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256, log);
   
    ret = poc_raw_client_derive_initial_keys(crypto, dcid);
    if (ret != XQC_OK) {
        printf("raw derive initial keys failed\n");
        return ret;
    }

    uint8_t enc_buf[XQC_PACKET_OUT_BUF_CAP];
    size_t buf_size = sizeof(enc_buf); 
    size_t enc_data_len = 0;
    ret = poc_initial_packet_encrypt(crypto, packet_out, enc_buf, buf_size, &enc_data_len);

    if (ret != XQC_OK) {
        printf("poc initial packet encrypt failed\n");
        return ret;
    }

    ret = send_udp_data(g_server_addr, g_server_port, enc_buf, enc_data_len);
    if (ret != XQC_OK) {
        printf("send udp data error, send len:%lu\n", enc_data_len);
        return ret;
    }
    return XQC_OK;
}

int generate_initial_ping_data(uint8_t *enc_buf, size_t buf_size, size_t *end_data_len)
{
    xqc_packet_out_t *packet_out =  poc_raw_create_packet_out(XQC_PTYPE_INIT);
    xqc_cid_t odcid, oscid;
    xqc_cid_t *dcid = &odcid, *scid= &oscid;
    char token[0]; 
    uint32_t token_len = 0;
    int ret = 0;

    memset(dcid, 0, sizeof(odcid));
    memset(scid, 0, sizeof(oscid));
   
    dcid->cid_len = DEFAULT_CID_LEN;
    scid->cid_len = DEFAULT_CID_LEN;

    random_generate(dcid->cid_buf, dcid->cid_len);
    random_generate(scid->cid_buf, scid->cid_len);


    ret = poc_raw_gen_long_packet_header(packet_out, dcid->cid_buf, dcid->cid_len,
            scid->cid_buf, scid->cid_len, token, token_len);

    if (ret != XQC_OK) {
        printf("raw gen long packet header error\n");
        return ret;
    }
    ret = xqc_gen_ping_frame(packet_out);
    if (ret < 0 ) {
        printf("gen ping frame error\n");
        return ret;
    }

    poc_gen_padding_frame(packet_out);
    
    xqc_log_t *log = xqc_log_init(0, 0, 0, 0, 0, NULL, NULL, NULL);

    xqc_crypto_t *crypto = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256, log);
   
    ret = poc_raw_client_derive_initial_keys(crypto, dcid);
    if (ret != XQC_OK) {
        printf("raw derive initial keys failed\n");
        return ret;
    }

    ret = poc_initial_packet_encrypt(crypto, packet_out, enc_buf, buf_size, end_data_len);

    if (ret != XQC_OK) {
        printf("poc initial packet encrypt failed\n");
        return ret;
    }

    return XQC_OK;
}

int
init_socket_fd(char *server_ip, int server_port, int *fd, struct sockaddr_in *server_addr)
{
    if ((*fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket creation failed");
        return XQC_ERROR;
    } 
    memset(server_addr, 0, sizeof(struct sockaddr_in));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(server_port);
    server_addr->sin_addr.s_addr = inet_addr(server_ip);

    return XQC_OK; 
}

static void create_conn_callback(int fd, short what, void *arg)
{
    struct event *ev_conc = * ((struct event **)arg);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = (1000000/g_conn_num );
    int i = 0;
    event_add(ev_conc, &tv);
    int sockfd;
    struct sockaddr_in server_addr;

    uint8_t enc_buf[XQC_PACKET_OUT_BUF_CAP];
    size_t buf_size = sizeof(enc_buf); 
    size_t enc_data_len = 0;
    
    for (i = 0; i < g_req_per_time; i++) { 
        if ((i + 1) % 10 == 0) {
        
            int ret = init_socket_fd(g_server_addr, g_server_port, &sockfd, &server_addr);
            if (ret != XQC_OK) {
                printf("create fd failed\n");
                return;
            }
            int j = 0;
            for (j = 0; j < 10; j++) {
                ret = generate_initial_ping_data(enc_buf, buf_size, &enc_data_len);
                if (ret != XQC_OK) {
                    printf("generate initial ping data failed, ret = %d\n", ret);
                }
                // 发送数据到服务器
                ret = sendto(sockfd, enc_buf, enc_data_len, 0, (const struct sockaddr *)&server_addr, sizeof(server_addr));
                if (ret < 0) 
                {
                    if (errno == EAGAIN) {
                        printf("sendto eagain\n");
                        continue;
                    } else {
                        printf("send failed, ret = %d, errno:%d\n", ret, errno);
                    }

                }
            }

            close(sockfd);
        }
    }

    for (i = 0; i < g_req_per_time % 10; i++) {
        int ret = init_socket_fd(g_server_addr, g_server_port, &sockfd, &server_addr);
        if (ret != XQC_OK) {
            printf("create fd failed\n");
            return;
        } 
        ret = generate_initial_ping_data(enc_buf, buf_size, &enc_data_len);
        // 发送数据到服务器
        if (sendto(sockfd, enc_buf, enc_data_len, 0, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
        {
            printf("sendto failed");
            continue;
        }
        close(sockfd);
    }
}


int
main(int argc, char *argv[])
{
    int i;
    memset(g_server_addr, 0, sizeof(g_server_addr));
    strncpy(g_server_addr, TEST_SERVER_ADDR , sizeof(g_server_addr) - 1);
    g_server_port = TEST_SERVER_PORT;

    if(client_parse_args(argc, argv, NULL, "") < 0){
        printf("parse arg error\n");
        return -1;
    }
 
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
    
    eb = event_base_new();
    struct event    *ev_conc;
    ev_conc = event_new(eb, -1, 0, create_conn_callback, &ev_conc); 

    if(ev_conc == NULL) {
        printf("ev_conc NULL");
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add(ev_conc, &tv);

    event_base_dispatch(eb);
}
