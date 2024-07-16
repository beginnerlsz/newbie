hex_string = "66 00 6C 00 61 00 67 00 7B 00 38 00 37 00 30 00 63 00 35 00 61 00 37 00 32 00 38 00 30 00 36 00 31 00 31 00 35 00 63 00 62 00 35 00 34 00 33 00 39 00 33 00 34 00 35 00 64 00 38 00 62 00 30 00 31 00 34 00 33 00 39 00 36 00 7D"

# 去除所有 '00'
cleaned_hex_string = hex_string.replace('00', '')

# 将去除 '00' 的十六进制字符串转换为字节码
byte_data = bytes.fromhex(cleaned_hex_string)

# 将字节码以 UTF-8 解码
utf8_string = byte_data.decode('utf-8')

print(utf8_string)