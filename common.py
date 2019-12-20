# encoding: utf-8

class Buffer(object):

    def __init__(self, bytes_data):
        if bytes_data:
            self.__data = bytes_data[0:]
            self.__len = len(self.__data)
        else:
            self.__data = None
            self.__len = 0
        self.__idx = 0

    def pop(self, nbytes): 
        if (not self.__data) or self.__idx >= self.__len or nbytes < 1:
            return None
        rt = self.__data[self.__idx:self.__idx+nbytes]
        self.__idx += len(rt)
        return rt

    def is_empty(self):
        if (not self.__data) or self.__idx >= self.__len:
            return True
        return False