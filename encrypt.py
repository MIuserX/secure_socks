#!/usr/bin/env python
# encoding: utf-8

import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


#加密内容需要长达16位字符，所以进行空格拼接
def pad(text):
    while len(text) % 16 != 0:
        text += b' '
    return text


#加密秘钥需要长达16位字符，所以进行空格拼接
def pad_key(key):
    while len(key) % 16 != 0:
        key += b' '
    return key


class MyEncrypt(object):
    
    def __init__(self, key):
        #进行加密算法，模式ECB模式，把叠加完16位的秘钥传进来
        self.aes = AES.new(pad_key(key), AES.MODE_ECB)
    
    def encrypt(self, bytes_data):
        len_ = struct.pack("i", len(bytes_data))
        return self.aes.encrypt(pad(len_ + bytes_data))

    def decrypt(self, bytes_data):
        data_packet = self.aes.decrypt(bytes_data)
        len_ = (struct.unpack("i", data_packet[0:4]))[0]
        return data_packet[4:len_+4]


if __name__ == '__main__':
    xstr = 'fasfdsahf wqer qasdl是的骄傲去玩儿人w'
    print("lenof(x)=" + str(len(xstr)))
    
    my_encrypt = MyEncrypt(b'abcdefgh')
    
    en_ = my_encrypt.encrypt(xstr)
    print("lenof(en)=" + str(len(en_)))

    de_ = my_encrypt.decrypt(en_)
    print("lenof(de)=" + str(len(de_)))
    print("de=" + de_ + "=")
    
