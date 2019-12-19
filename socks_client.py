# -*- coding: utf-8 -*-
"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
# custom codes
from socks_base import Socks5
from socks_base import SSocks
from encrypt import MyEncrypt
import struct

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050
# Parameter to bind a socket to a device, using SO_BINDTODEVICE
# Only root can set this option
# If the name is an empty string or None, the interface is chosen when
# a routing decision is made
# OUTGOING_INTERFACE = "eth0"
OUTGOING_INTERFACE = ""

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'



encrypter = MyEncrypt(b'abcdefgh')



class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def proxy_loop_of_client(socket_src, socket_dst):
    """ Wait for network activity """
    sendlen = -1
    sendbuff = None

    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    #### 来源于 Sserver 的密文，接收完整后，解密发给 client
                    if sendlen == -1:
                        # -1: buff无数据，等待数据
                        sendlen = (struct.unpack("i", data[0:4]))[0]
                        sendbuff = data[4:]
                        sendlen -= (len(data) - 4)                        
                    elif sendlen > 0:
                        # > 0: buff有数据，但不是完整的密文，需要继续读取数据
                        sendbuff += data
                        sendlen -= len(data)

                    if sendlen == 0:
                        # 0: buff数据已足够，执行发送
                        socket_src.send(encrypter.decrypt(sendbuff))
                        sendbuff = None
                        sendlen = -1
                    elif sendlen < -1:
                        raise Exception("sendlen < -1")
                else:
                    #### 来源于 client 的明文，直接加密发给 Sserver 
                    socket_dst.send(encrypter.encrypt(data))

        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_vps_over_socks5_proxy(proxy_addr, proxy_port, vps_addr, vps_port, dst_data):
    """ Connect to desired destination """
    sock_to_proxy = create_socket()
    try:
        sock_to_proxy.connect((proxy_addr, proxy_port))

        # 第一阶段很简单，
        # 就是连接上一级 socks5 proxy，
        # 并打通到 vps 的链接，

        Socks5.hello_to_server(sock_to_proxy, vps_addr, vps_port)
        print("connection to vps OK")

        # 现在这个阶段我方已与 socks5 proxy 建立了连接，
        # socks5 proxy 也与 vps 建立了连接，
        # 接下来要与 vps 进行加密认证，并连接上实际的

        SSocks.hello_to_server(sock_to_proxy, encrypter, dst_data)
        print("connection to target OK")

        return sock_to_proxy
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def connect_to_socks5_proxy(proxy_addr, proxy_port, dst_addr, dst_port):
    """ Connect to desired destination """
    sock_to_proxy = create_socket()
    try:
        sock_to_proxy.connect((proxy_addr, proxy_port))

        #### handshack
        sock_to_proxy.send(Socks5.simple_hello)
        if not Socks5.is_noauth_reply(sock_to_proxy.recv(BUFSIZE)):
            error("Failed to handshack with proxy", Exception("Bad handshack"))
            return 0

        #### send addr
        sock_to_proxy.send(Socks5.addr_packet(dst_addr, dst_port))
        if not Socks5.is_noauth_reply(sock_to_proxy.recv(BUFSIZE)):
            error("Failed to connect vps", Exception("Bad connection"))
            return 0

        #### handshack
        #sock_to_proxy.send(Socks5.simple_hello)
        #if not Socks5.is_noauth_reply(sock_to_proxy.recv(BUFSIZE)):
        #    error("Failed to handshack with proxy", Exception("Bad handshack"))
        #    return 0

        #print("connect success")

        return sock_to_proxy
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def get_dst(wrapper):
    """ Client request details """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False

    # 将 ATYP | DST.ADDR | DST.PORT 都转回去
    if s5_request[3:4] == ATYP_IPV4 or s5_request[3:4] == ATYP_DOMAINNAME:
        return s5_request[3:len(s5_request)]
    
    return False


#def request_client(wrapper):
#    """ Client request details """
#    # +----+-----+-------+------+----------+----------+
#    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
#    # +----+-----+-------+------+----------+----------+
#    try:
#        s5_request = wrapper.recv(BUFSIZE)
#    except ConnectionResetError:
#        if wrapper != 0:
#            wrapper.close()
#        error()
#        return False
#    # Check VER, CMD and RSV
#    if (
#            s5_request[0:1] != VER or
#            s5_request[1:2] != CMD_CONNECT or
#            s5_request[2:3] != b'\x00'
#    ):
#        return False
#    # IPV4
#    if s5_request[3:4] == ATYP_IPV4:
#        dst_addr = socket.inet_ntoa(s5_request[4:-2])
#        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
#    # DOMAIN NAME
#    elif s5_request[3:4] == ATYP_DOMAINNAME:
#        sz_domain_name = s5_request[4]
#        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
#        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
#        dst_port = unpack('>H', port_to_unpack)[0]
#    else:
#        return False
#
#    #dst_addr = "127.0.0.1"
#    #dst_port = 1080
#    print("dst_addr={} dst_port={}".format(dst_addr, str(dst_port)))
#    return (dst_addr, dst_port)


def request(wrapper):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    #dst = request_client(wrapper)
    dst = get_dst(wrapper)

    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    if dst:
        #socket_dst = connect_to_dst(dst[0], dst[1])
        #socket_dst = connect_to_socks5_proxy("127.0.0.1", 1080, dst[0], dst[1])
        socket_dst = connect_to_vps_over_socks5_proxy("127.0.0.1", 1080, "100.80.129.81", 9051, dst)
    if not dst or socket_dst == 0:
        rep = b'\x01'
    else:
        rep = b'\x00'
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':
        proxy_loop_of_client(wrapper, socket_dst)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    return True


def connection(wrapper):
    """ Function run by a thread """
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock


def bind_port(sock):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


def main():
    """ Main function """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
