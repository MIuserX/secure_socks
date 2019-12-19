#!/usr/bin/python3

import socket
import struct

BUFSIZE=1024

class Socks5(object):
    
    simple_hello = b'\x05' + b'\x01' b'\x00'

    def __init__(self):
        pass

    @staticmethod
    def complete_hello():
        return b'\x05' + b'\x01' b'\x00'

    @staticmethod
    def custom_hello(length, methods):
        return b'\x05' + length + methods

    @staticmethod
    def is_noauth_reply(reply):
        if reply[0:1] == b'\x05' and reply[1:2] == b'\x00':
            return True
        return False

    @staticmethod
    def is_connection_ok(reply):
        if reply[0:1] == b'\x05' and\
            reply[1:2] == b'\x00' and\
            reply[2:3] == b'\x00':
            return True
        return False

    @staticmethod
    def addr_packet(raw_data=None, ip=None, port=None):
        #+----+-----+-------+------+----------+----------+
        #|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        #+----+-----+-------+------+----------+----------+
        #| 1  |  1  | X'00' |  1   | Variable |    2     |
        #+----+-----+-------+------+----------+----------+
        #cooked_ip = struct.unpack("!L", socket.inet_aton(ip))[0]

        prefix = b'\x05' + b'\x01' + b'\x00'

        if raw_data:
            return prefix + raw_data
        elif ip is not None and port is not None:
            ip_x = ip.split(".")
            cooked_ip = struct.pack("<BBBB", int(ip_x[0]), int(ip_x[1]), int(ip_x[2]), int(ip_x[3]))
            return prefix + b'\x01' + cooked_ip + struct.pack(">H", port)

    @staticmethod
    def hello_to_server(sock, dst_addr, dst_port):
        """
        shanck hands with socks5 server and connect to target
        """

        try:
            # handshack
            sock.send(Socks5.simple_hello)
            if not Socks5.is_noauth_reply(sock_to_proxy.recv(BUFSIZE)):
                raise Exception("Failed to handshack with proxy")

            # send addr
            sock.send(Socks5.addr_packet(ip=vps_addr, port=vps_port))
            if not Socks5.is_connection_ok(sock_to_proxy.recv(BUFSIZE)):
                raise Exception("Failed to connect target")
        except Exception as e:
            raise e


class SSocks(object):

    def __init__(self):
        pass

    @staticmethod
    def hello_to_server(sock, encrypter, dst):
        try:
            # handshack
            sock.send(encrypter.encrypt(Socks5.simple_hello))
            reply = sock.recv(BUFSIZE)
            en_len = (struct.unpack("i", reply[0:4]))[0]
            origin_data = encrypter.decrypt(reply[4:])
            if not Socks5.is_noauth_reply(origin_data):
                raise Exception("Failed to handshack with vps")
    
            # send addr
            sock.send(encrypter.encrypt(Socks5.addr_packet(dst)))
            reply = sock.recv(BUFSIZE)
            en_len = (struct.unpack("i", reply[0:4]))[0]
            origin_data = encrypter.decrypt(reply[4:])
            if not Socks5.is_connection_ok(origin_data):
                raise Exception("Failed to connect target")
        except Exception as e:
            raise e

    @staticmethod
    def accept_hello(sock, encrypter):
        pass