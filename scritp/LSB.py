# coding:utf-8

#  ctf-MISC
#  图片LSB隐写 也可以用kali里面的zsteg

import PIL.Image
def foo():
    im = PIL.Image.open('file name')  #file name or file path
    im2 = im.copy()
    pix = im2.load()
    width, height = im2.size

    for x in range(0, width):
        for y in range(0, height):
            if pix[x, y] & 0x1 ==0:
                pix[x, y] = 0
            else:
                pix[x, y] = 255
    im2.show()
    pass
if __name__ == '__main__':
    foo()
    print('ok.')
    pass