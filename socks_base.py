#!/usr/bin/python3

import socket
import struct

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
