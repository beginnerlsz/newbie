# Metasploit渗透框架

***在msfconsole中利用`back`命令回退,`exit`命令会直接退出msf控制台***

1. 常见术语

   POC: proof of concept 证明漏洞存在的代码，无攻击性

   EXP: Exploit 利用漏洞进行的一些操作，具有攻击性

   payload: 有效载荷，攻击代码，即exploit的核心

   Team Server: 服务端，C2服务器，Beacon payload 控制器

   Beacon: Cobalt Strike 工具运行在目标机器上的payload，隐蔽的与Team Server 通信，接受指令，实现长期控制

## MSF模块介绍

### Auxiliary 辅助

- 主要功能: 信息收集

- 模块利用

  1. search: 搜索模块(模糊搜索), search aux /scanner/discovery

  2. use: 使用模块，参数可以是模块路径，也可以是search之后的id

  3. option: 查看模块选项信息，*Reqiuired为yes的是必须要设置的选项*
  4. set 模块选项名称 值: 设置选项值
  5. run: 运行模块

### Payloads 攻击载荷

- 主要功能: 在目标机与攻击机之间建立连接。在目标机上执行代码

#### payload类型

1. signales 独立载荷：单一功能代码片段，目标机上独立执行
2. stagers 传输器载荷：在目标机与攻击机之间建立初步连接，体积小，便于注入
   1. Bind型：攻击者需要主动连接目标系统上的端口
   2. Reverse型：目标系统连接攻击者
3. stages传输体载荷：传输体载荷在传输器载荷建立稳定链接后被传输到目标系统
   - Meterpreter：可交互payload，运行在内存中
4. Stageless payload：不分阶段payload，包含所有必须组件的单一二进制文件，体积大，无需额外的下载或连接步骤即可执行
5. staged payload：分阶段payload，首先通过小传输器载荷建立连接，然后下载传输体载荷

*注意：4和5的主要区别在于payload路径，不分阶段payload路径为 /meterpreter_payload名称；分阶段payload路径为 /meterpreter/payload名称*

#### msfvenom生成payload

- 两个必选项：-p  指定payload  -f  指定payload输出格式

### Exploit 漏洞利用

- 功能: 漏洞利用
- search 漏洞编号          搜索漏洞
- use 漏洞路径/search后的id       利用漏洞
- set      设置选项的值
- check     检查目标是否存在漏洞
- run      运行攻击模块  

### Meterpreter拓展

通常用于利用漏洞后建立稳定的控制通道

#### 常用shell

1. reverse_tcp: 基于tcp反弹shell
2. bind_tcp: tcp正向连接shell，适用于目标主机无法访问外网
3. reverse_http: http式的反向连接
4. reverse_https: https的反向连接

#### Meterpreter 操作

- background: 将当前session挂起
- sessions -l: 列出所有session
- sessions -i id: 进入某个session
- help: 帮助信息





