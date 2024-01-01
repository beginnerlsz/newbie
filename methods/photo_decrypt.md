# 图片文件隐写(图片内容被加密)
  *这种情况下，以16进制格式打开文件只能看到被加密的内容*
## 加密图片解密
1. Bftools(windows cmd)
- 命令格式
  1. Bftools.exe decode braincopter decode_picture -output output_file
  2. Bftools.exe run output_file
2. SilentEye
   *windows 下 图形化图片加解密工具*
- 方法
-  silentEye打开目标图片，decode命令查看到隐藏文件，保存
## jpeg解密
*stegdect*
- 分析工具 stegdetect 工具探测加密方式
  ```cmd
  stegdetect xxx.jpg  #加密方式隐藏较浅
  stegdetect -s 敏感度(数字) xxx.jpg  #隐藏较深
  ```
- 解密
  1. Jphide
    *Jphide是基于最低有效位LSB的JPEG格式图像隐写算法*
    - 用jphs工具解密: 打开jphswin.exe -> open jpeg 打开图片 -> seek -> 输入密码，确认密码 -> 保存
  2. Outguess
    *一般用于解密文件信息*
    - 应用场景: Outguess加密的图片
    - 该工具使用前需要先编译 `./configure && make && make install`
    - 格式
      ```cmd
      outguess -r decode_file outputfile
      ```
  3. F5
    *解密文件信息*
    - 使用场景: F5加密的图片
    - 将解密图片与工具放到统一目录下，cmd进入该目录
    - 格式
      ```cmd
      Java Extract decode_file -p password 
      ```
    - 结果存储在output.txt中