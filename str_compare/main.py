import sys


class str_compare:
    MODE_SAME = 0
    MODE_SPECIAL = 1

    def __init__(self, file1: str, file2: str, mode: int):
        f1 = open(file1, "rb")
        f2 = open(file2, "rb")
        buf1 = f1.read()
        buf2 = f2.read()

        if mode == self.MODE_SAME:
            pass
        elif mode == self.MODE_SPECIAL:
            pass
        else:
            return
        # 搜可理解的字符串。

    def str_extract(self, buf: bytes):

        str_list = []

        pass

    SIGN_LIST = " -_?@<>"

    def if_str_alpha_collections(self, buf: bytes):
        str = ""
        for i in buf:
            if chr(i).isalpha():
                str += chr(i)
            elif 0x2f >= i >= 0x20:
                str += chr(i)
            elif 0x40 >= i >= 0x3a:
                str += chr(i)
            elif 0x60 >= i >= 0x60:
                str += chr(i)
            elif 0x7e >= i >= 0x7b:
                str += chr(i)
            else:
                return str
        return str
        pass

    def if_str_num_collections(self: bytes):
        pass

    def if_str_sign_serial(self, buf: bytes):
        pass
