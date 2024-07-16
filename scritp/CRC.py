# coding: utf-8

""" 
    ctf-MISC
    the width or height problem of a picture
    modify the picture's width or height by CRC value.
 """

import binascii
import struct

def mod_crc(path, crc_code):

    crcbp = open(path, "rb").read()  #name is the picture's name or path
    for i in range(1024):
        for j in range(1024):
            data = crcbp[12:16] + struct.pack('>i',i) + struct.pack('>i', j) +crcbp[24:29]
            crc32 = binascii.crc32(data) & 0xffffffff
            if crc32 == crc_code:
                print(i,j)
                print("hex", hex(i), hex(j))
    return 0

if __name__ == '__main__':
    mod_crc()  # input .png path and crc code
    pass