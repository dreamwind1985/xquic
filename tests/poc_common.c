#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_request.h"
#include "src/common/xqc_list.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

xqc_int_t xqc_h3_request_copy_header(xqc_http_header_t *dst, xqc_http_header_t *src, xqc_var_buf_t *buf);

/* 用于16进制输出数据 */
void
poc_hex_print(char *p, size_t n)
{
    char HEX[] = "0123456789ABCDEF";
    unsigned int i, j, count;
    j = 0;
    i = 0;
    count = 0;
    while (j < n) {
        count++;
        printf("0x%d\t", count);
        if (j + 16 < n) {
            for (i = 0; i < 16; i++) {
                printf("0x%c%c ", HEX[(p[j + i] & 0xF0) >> 4], HEX[p[j + i] & 0xF]);
            }
            printf("\t");
            for (i = 0; i < 16; i++) {
                printf("%c", isprint(p[j + i]) ? p[j + i] : '.');
            }
            printf("\n");
            j = j + 16;
        } else {
            for (i = 0; i < n - j; i++) {
                printf("0x%c%c ", HEX[(p[j + i] & 0xF0) >> 4],HEX[p[j + i] & 0xF]);
            }
            printf("\t");
            for (i = 0; i < n - j; i++) {
                printf("%c", isprint(p[j + i]) ? p[j + i]:'.');
            }
            printf("\n");
            break;
        }
    }
}


/* poc get packet out不限制 */
xqc_packet_out_t *
poc_send_queue_get_packet_out_for_stream(xqc_send_queue_t *send_queue, unsigned need, xqc_pkt_type_t pkt_type,
    xqc_stream_t *stream)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos;

    xqc_list_for_each_reverse(pos, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == pkt_type
            && packet_out->po_buf_size >= packet_out->po_used_size + need
            //&& packet_out->po_stream_frames_idx < XQC_MAX_STREAM_FRAME_IN_PO
            && packet_out->po_stream_frames_idx > 0)
            /* Avoid Head-of-Line blocking. */
            //&& packet_out->po_stream_frames[packet_out->po_stream_frames_idx - 1].ps_stream_id == stream->stream_id)
        {
            return packet_out;
        }
        /* Only try to fill the last packet now */
        break;
    }

    packet_out = xqc_packet_out_get_and_insert_send(send_queue, pkt_type);
    if (packet_out == NULL) {
        return NULL;
    }

    if (pkt_type == XQC_PTYPE_0RTT) {
        send_queue->sndq_conn->zero_rtt_count++;
    }

    return packet_out;
}


int
poc_write_packet_header(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    if (packet_out->po_used_size > 0) {
        return XQC_OK;
    }

    int ret = XQC_OK;

    xqc_pkt_type_t pkt_type = packet_out->po_pkt.pkt_type;

    if (pkt_type == XQC_PTYPE_SHORT_HEADER && packet_out->po_used_size == 0) {
        ret = xqc_gen_short_packet_header(packet_out,
                                          conn->dcid_set.current_dcid.cid_buf, conn->dcid_set.current_dcid.cid_len,
                                          XQC_PKTNO_BITS, packet_out->po_pkt.pkt_num,
                                          conn->key_update_ctx.cur_out_key_phase);

    } else if (pkt_type != XQC_PTYPE_SHORT_HEADER && packet_out->po_used_size == 0) {
        ret = xqc_gen_long_packet_header(packet_out,
                                         conn->dcid_set.current_dcid.cid_buf, conn->dcid_set.current_dcid.cid_len,
                                         conn->scid_set.user_scid.cid_buf, conn->scid_set.user_scid.cid_len,
                                         conn->conn_token, conn->conn_token_len,
                                         conn->version, XQC_PKTNO_BITS);
    }

    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|gen header error|%d|", ret);
        return ret;
    }
    packet_out->po_used_size += ret;

    return XQC_OK;
}

xqc_packet_out_t *
poc_write_packet_for_stream(xqc_connection_t *conn, xqc_pkt_type_t pkt_type, unsigned need, xqc_stream_t *stream)
{
    int ret;
    xqc_packet_out_t *packet_out;

    if (pkt_type == XQC_PTYPE_NUM) {
        pkt_type = xqc_state_to_pkt_type(conn);
    }

    //packet_out = xqc_send_queue_get_packet_out_for_stream(conn->conn_send_queue, need, pkt_type, stream);
    packet_out = poc_send_queue_get_packet_out_for_stream(conn->conn_send_queue, need, pkt_type, stream);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_queue_get_packet_out_for_stream error|");
        return NULL;
    }

    packet_out->po_path_id = XQC_INITIAL_PATH_ID;

    if (packet_out->po_used_size == 0) {
        ret = poc_write_packet_header(conn, packet_out);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_packet_header error|");
            goto error;
        }
    }

    return packet_out;

error:
    xqc_maybe_recycle_packet_out(packet_out, conn);
    return NULL;
}



ssize_t
poc_gen_stream_frame(xqc_packet_out_t *packet_out,
    xqc_stream_id_t stream_id, uint64_t offset, uint8_t fin,
    const unsigned char *payload, size_t size, size_t *written_size)
{
    /* 
     * 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */

    /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Stream ID (i)                       ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         [Offset (i)]                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         [Length (i)]                        ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Stream Data (*)                      ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    unsigned char *dst_buf = packet_out->po_buf + packet_out->po_used_size;
    size_t dst_buf_len = packet_out->po_buf_size - packet_out->po_used_size;

    *written_size = 0;
    /*  variable length integer's most significant 2 bits */
    unsigned stream_id_bits, offset_bits, length_bits;
    /* variable length integer's size(byte) */
    unsigned stream_id_len, offset_len, length_len;
    /* 0b00001XXX point to second byte */
    unsigned char *p = dst_buf + 1;
    /* fin_only means there is no stream data */
    uint8_t fin_only = (fin && !size);

    unsigned int idx = packet_out->po_stream_frames_idx;
    unsigned int prev_idx = idx - 1;
   
#if 1
    /* Try to combine with previous stream frame */
    if (idx > 0 && packet_out->po_frame_types == XQC_FRAME_BIT_STREAM /* No other frames */
        && packet_out->po_stream_frames[prev_idx].ps_stream_id == stream_id
        && packet_out->po_stream_frames[prev_idx].ps_offset + packet_out->po_stream_frames[prev_idx].ps_length == offset
        && packet_out->po_stream_frames[prev_idx].ps_length_offset > 0 /* Length field is present */)
    {
        unsigned char *p_type = packet_out->po_buf + packet_out->po_stream_frames[prev_idx].ps_type_offset;
        printf("p_type = %p\n", p_type);
        unsigned char *p_length = packet_out->po_buf + packet_out->po_stream_frames[prev_idx].ps_length_offset;
        size_t append_size = 0;

        /* Length is 2 Bytes */
        if ((*p_length & 0xC0) != 0x40) {
            goto new_frame;
        }

        if (!fin_only) {
            append_size = xqc_min(size, dst_buf_len);
            memcpy(dst_buf, payload, append_size);
            xqc_vint_write(p_length, packet_out->po_stream_frames[prev_idx].ps_length + append_size, 1, 2);
            packet_out->po_stream_frames[prev_idx].ps_length += append_size;
            if (append_size != size) {
                fin = 0;
            }
        }

        if (fin) {
            *p_type |= 0x01;
            packet_out->po_stream_frames[prev_idx].ps_has_fin = fin;
        }

        *written_size = append_size;
        return append_size;
    }
#endif
new_frame:
    stream_id_bits = xqc_vint_get_2bit(stream_id);
    stream_id_len = xqc_vint_len(stream_id_bits);
    if (offset) {
        offset_bits = xqc_vint_get_2bit(offset);
        offset_len = xqc_vint_len(offset_bits);

    } else {
        offset_len = 0;
    }

    if (!fin_only) {
        ssize_t n_avail;

        n_avail = dst_buf_len - (p + stream_id_len + offset_len - dst_buf);

        /* 
         * If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size <= n_avail) {
            /* length_len set to 2 bytes, easy to combine with other stream frame */
            length_bits = 1;
            length_len = 2;
            n_avail -= length_len;
            if (size > n_avail) {
                size = n_avail;
                fin = 0;
            }

        } else {
            /* reserve ACK, must have length. */
            size = n_avail;
            length_bits = 1;
            length_len = 2;
            size -= length_len;
            fin = 0;
        }

        if (n_avail <= 0 || size > n_avail) {
            return -XQC_ENOBUF;
        }

        xqc_vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;

        if (offset_len) {
            xqc_vint_write(p, offset, offset_bits, offset_len);
        }
        p += offset_len;

        memcpy(p + length_len, payload, size);
        *written_size = size;

        if (length_len) {
            xqc_vint_write(p, size, length_bits, length_len);
            packet_out->po_stream_frames[idx].ps_length_offset = (unsigned int)(p - packet_out->po_buf);
        }

        p += length_len + size;

    } else {
        /* check if there is enough space to put Length */
        length_len = 1 + stream_id_len + offset_len < dst_buf_len ? 1 : 0;
        if (1 + stream_id_len + offset_len + length_len > dst_buf_len) {
            return -XQC_ENOBUF;
        }
        xqc_vint_write(p, stream_id, stream_id_bits, stream_id_len);
        p += stream_id_len;

        if (offset_len) {
            xqc_vint_write(p, offset, offset_bits, offset_len);
        }
        p += offset_len;

        if (length_len) {
            *p++ = 0;
        }
    }

    dst_buf[0] = 0x08
                 | (!!offset_len << 2)
                 | (!!length_len << 1)
                 | (!!fin << 0);

    packet_out->po_stream_frames[idx].ps_type_offset = (unsigned int)(dst_buf - packet_out->po_buf);
    packet_out->po_stream_frames[idx].ps_offset = offset;
    packet_out->po_stream_frames[idx].ps_length = (unsigned int)size;
    packet_out->po_stream_frames[idx].ps_is_used = 1;
    packet_out->po_stream_frames[idx].ps_stream_id = stream_id;
    packet_out->po_stream_frames[idx].ps_has_fin = fin;
    packet_out->po_stream_frames_idx++;

    packet_out->po_frame_types |= XQC_FRAME_BIT_STREAM;
    printf("dst_buf:%p\n", dst_buf);

    return p - dst_buf;
}


int
poc_write_stream_frame_to_packet(xqc_connection_t *conn,
    xqc_stream_t *stream, xqc_pkt_type_t pkt_type, uint8_t fin,
    const unsigned char *payload, size_t payload_size, size_t *send_data_written)
{
    xqc_packet_out_t *packet_out;
    int n_written;
    /* We need 25 bytes for stream frame header at most, and left bytes for stream data.
     * It's a trade-off value, bigger need bytes for higher payload rate. */
    const unsigned need = 50;
    packet_out = poc_write_packet_for_stream(conn, pkt_type, need, stream);
    //packet_out = xqc_write_packet_for_stream(conn, pkt_type, need, stream);
    if (packet_out == NULL) {
        return -XQC_EWRITE_PKT;
    }
   //n_written = poc_gen_stream_frame(packet_out,
   n_written = poc_gen_stream_frame(packet_out,
                                     stream->stream_id, stream->stream_send_offset, fin,
                                     payload,
                                     payload_size,
                                     send_data_written);
   
   printf("packet_out = %p, packet_out->po_list.prev = %p, packet_out->po_list.next = %p, n_written=%d, next->next:%p\n", packet_out, 
            packet_out->po_list.prev,packet_out->po_list.next, n_written, packet_out->po_list.next->next);
  
   if (n_written < 0) {
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return n_written;
    }
    stream->stream_send_offset += *send_data_written;
    stream->stream_conn->conn_flow_ctl.fc_data_sent += *send_data_written;
    packet_out->po_used_size += n_written;
    packet_out->po_stream_id = stream->stream_id;
    packet_out->po_stream_offset = stream->stream_send_offset;
    
    return XQC_OK;
}

size_t
poc_stream_send(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size, uint8_t fin)
{
    xqc_connection_t *conn = stream->stream_conn;

    int ret;
    xqc_stream_ready_to_write(stream);
    size_t send_data_written = 0;
    size_t offset = 0; /* the written offset in send_data */
    uint8_t fin_only = fin && !send_data_size;
    uint8_t fin_only_done = 0;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;


    while (offset < send_data_size || fin_only) {

        ret = xqc_stream_do_send_flow_ctl(stream);
        if (ret) {
            ret = -XQC_EAGAIN;
        }
        ret = poc_write_stream_frame_to_packet(conn, stream, pkt_type,
        //ret = xqc_write_stream_frame_to_packet(conn, stream, pkt_type,
                                               fin,
                                               send_data + offset,
                                               send_data_size - offset,
                                               &send_data_written);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_stream_frame_to_packet error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return ret;
        }

        offset += send_data_written;
        if (fin_only) {
            fin_only_done = 1;
            break;
        }
    }

    xqc_stream_shutdown_write(stream);

    if (offset == 0 && !fin_only_done) {
        if (ret == -XQC_EAGAIN) {
            return -XQC_EAGAIN; /* -XQC_EAGAIN not means error */
        } else {
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return ret;
        }
    }

    return offset;

}

int
poc_crypto_stream_send(xqc_stream_t *stream, 
    xqc_hs_buffer_t *buf, xqc_pkt_type_t pkt_type)
{
    xqc_list_head_t crypto_data_list;
    xqc_init_list_head(&crypto_data_list);
    xqc_list_add_tail(&buf->list_head, &crypto_data_list);

    return xqc_crypto_stream_send(stream, &crypto_data_list, pkt_type);
}

xqc_int_t
poc_h3_stream_send_buffer(xqc_h3_stream_t *h3s)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &h3s->send_buf) {
        xqc_list_buf_t *list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = list_buf->buf;


        if (buf->data != NULL) {
            /* buf with bytes remain and buf with fin only */
            if (buf->consumed_len < buf->data_len
                    || (buf->data_len == 0 && buf->fin_flag))
            {
                /* send buffer with transport stream */
                ssize_t sent = poc_stream_send(h3s->stream, buf->data + buf->consumed_len,
                //ssize_t sent = xqc_stream_send(h3s->stream, buf->data + buf->consumed_len,
                        buf->data_len - buf->consumed_len, buf->fin_flag);
                if (sent < 0) {
                    /* don't print XQC_EAGAIN and XQC_ESTREAM_RESET */
                    if (sent != -XQC_EAGAIN && sent != -XQC_ESTREAM_RESET) {
                        xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_stream_send error|ret:%z|", sent);
                    }

                    return sent;
                }

                buf->consumed_len += sent;
                if (buf->consumed_len != buf->data_len) {
                    return -XQC_EAGAIN;
                }

            } else if (buf->data_len > 0) {
                xqc_log(h3s->log, XQC_LOG_ERROR, "|send_buf is empty|buf->consumed_len:%uz"
                        "|buf->data_len:%uz", buf->consumed_len, buf->data_len);
            }
        } else {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|send_buf is NULL|");
        
        }

        xqc_list_buf_free(list_buf);
    }   

    return XQC_OK;

}

/* 用于发送已经格式化好并存放在xqc_var_buf_t中的header */
ssize_t
poc_h3_request_send_headers_raw_data(xqc_h3_stream_t *h3s, xqc_var_buf_t *data, uint8_t fin)
{
    ssize_t processed = 0, ret = 0;
    xqc_h3_conn_t   *h3c;
    h3c = h3s->h3c;   
    processed += data->data_len;

    xqc_var_buf_t *send_data = xqc_var_buf_create(data->data_len);
    if (send_data == NULL) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|malloc error|stream_id:%ui|fin:%d|",
                h3s->stream_id, (unsigned int)fin);
        return -XQC_EMALLOC;
    }
    xqc_var_buf_save_data(send_data, data->data, data->data_len); 
       

    h3s->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    ret = xqc_h3_frm_write_headers(&h3s->send_buf, send_data, fin);
    if (ret != XQC_OK) {
        printf("|write HEADERS frame error|stream_id:%ui|fin:%d|",
                (unsigned int)h3s->stream_id, (unsigned int)fin);
        //xqc_var_buf_free(data);
        return ret;
    }
    printf("|send header data len:%d|\n", (int)send_data->data_len);

    /* send HEADERS frame */
    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_FIN_SENT) {
        h3s->flags &= ~XQC_HTTP3_STREAM_FLAG_FIN_SENT;
    }
    //ret = xqc_h3_stream_send_buffer(h3s);
    ret = poc_h3_stream_send_buffer(h3s);
    if (ret == -XQC_EAGAIN) {
        printf("|send HEADERS frame eagain|stream_id:%ui|fin:%ud|",
                (unsigned int)h3s->stream_id, (unsigned int)fin);
        return processed;

    } else if (ret < 0) {
        printf("|send HEADERS frame error|%d|stream_id:%ui|fin:%ui|",
                (int)ret, (unsigned int)h3s->stream_id, (unsigned int)fin);
        return ret;
    }


    h3s->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    //xqc_engine_main_logic_internal(h3c->conn->engine);
    return processed;
}


/* 用于从qpack中构建header的数据*/
ssize_t
poc_h3_request_header_qpack_encoder(xqc_h3_stream_t *h3s, xqc_http_headers_t *headers, xqc_var_buf_t *data)
{
    xqc_int_t ret;

    ret = xqc_qpack_enc_headers(h3s->qpack, h3s->stream_id, headers, data);
    if (ret != XQC_OK) {
        printf("|write HEADERS frame error|stream_id:%ui|",
                (unsigned int)h3s->stream_id);
        return ret;
    }
    return ret;
}

/* 用于格式化header */
xqc_int_t 
poc_h3_request_format_headers(xqc_h3_request_t *h3_request,
                              xqc_http_headers_t *headers_in,
                              xqc_http_headers_t *headers,
                              uint8_t fin)
{
    int pt = 0, i = 0;
    xqc_int_t ret = XQC_OK;

    xqc_var_buf_t *lowercase_buf = xqc_var_buf_create(XQC_H3_HEADERS_LOWERCASE_BUF_SIZE);
    if (NULL == lowercase_buf) {
        printf("|malloc buf for lowercase error|");
        return -XQC_EMALLOC;
    }

    headers_in->headers = xqc_malloc(headers->count * sizeof(xqc_http_header_t));
    if (headers_in->headers == NULL) {
        printf("|malloc error|");
        ret = -XQC_H3_EMALLOC;
        goto end;
    }

    headers_in->capacity = headers->count;
    headers_in->total_len = 0;

    /* make pseudo headers first */
    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len > 0
            && *((unsigned char *)headers->headers[i].name.iov_base) == ':')
        {
            ret = xqc_h3_request_copy_header(&headers_in->headers[pt],
                                             &headers->headers[i], lowercase_buf);
            if (ret != XQC_OK) {
                printf("|copy header error|ret:%d|", ret);
                goto end;
            }

            headers_in->total_len +=
                (headers->headers[pt].name.iov_len + headers->headers[pt].value.iov_len);
            pt++;
        }
    }

    /* copy other headers */
    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len > 0
            && *((unsigned char *)headers->headers[i].name.iov_base) != ':')
        {
            ret = xqc_h3_request_copy_header(&headers_in->headers[pt],
                                             &headers->headers[i], lowercase_buf);
            if (ret != XQC_OK) {
                printf("|copy header error|ret:%d|", ret);
                goto end;
            }

            headers_in->total_len +=
                (headers->headers[pt].name.iov_len + headers->headers[pt].value.iov_len);
            pt++;
        }
    }

    headers_in->count = pt;

end:
    xqc_var_buf_free(lowercase_buf);
    return ret;
}




