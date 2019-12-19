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
    
    def encrypt1(self, bytes_data):
        len_ = struct.pack("i", len(bytes_data))
        return self.aes.encrypt(pad(len_ + bytes_data))

    def decrypt(self, bytes_data):
        data_packet = self.aes.decrypt(bytes_data)
        len_ = (struct.unpack("i", data_packet[0:4]))[0]
        return data_packet[4:len_+4]

    def encrypt(self, bytes_data):
        src_len = struct.pack("i", len(bytes_data))
        en_data = self.aes.encrypt(pad(src_len + bytes_data))
        return struct.pack("i", len(en_data)) + en_data
        

if __name__ == '__main__':
    xstr = '骄傲去玩儿人'
    bstr = xstr.encode(encoding="utf-8")
    print("lenof(bytes)=" + str(len(bstr)))

    my_encrypt = MyEncrypt(b'abcdefgh')
    
    en_ = my_encrypt.encrypt(bstr)
    print("lenof(en)=" + str(len(en_)))

    de_len = (struct.unpack("i", en_[0:4]))[0]
    de_ = my_encrypt.decrypt(en_[4:])

    print("lenof(de)=" + str(de_len))
    print("de=" + (de_.decode(encoding="utf-8"))[0:de_len] + "=")