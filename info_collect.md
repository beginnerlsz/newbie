# 渗透测试--信息收集

## 域名信息收集

### whois

1. whois协议

    查询域名的IP以及所有者等信息的传输协议

    用来查询域名是否被注册，以及注册域名的详细信息的数据库(如域名所有人，域名注册商)

2. whois查询

    - web接口查询

        [阿里云](https://whois.aliyun.com)

        [全球whois查询](https://www.whois365.com/cn/)

        [站长之家](https://whois.chinaz.com/)

    - whois 命令行查询

        ```bash
        ┌──(kali㉿kali)-[~]
        └─$ whois zhihu.com   
        Domain Name: ZHIHU.COM
        Registry Domain ID: 1030643753_DOMAIN_COM-VRSN
        Registrar WHOIS Server: whois.dnspod.cn
        Registrar URL: http://www.dnspod.cn
        Updated Date: 2022-04-18T04:54:44Z
        Creation Date: 2007-06-15T17:28:11Z
        Registry Expiry Date: 2029-09-29T11:59:59Z
        Registrar: DNSPod, Inc.
        Registrar IANA ID: 1697
        Registrar Abuse Contact Email:
        Registrar Abuse Contact Phone:
        Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
        Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
        Name Server: NS3.DNSV5.COM
        Name Server: NS4.DNSV5.COM
        DNSSEC: unsigned
        URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
        >>> Last update of whois database: 2024-05-21T12:54:36Z <<<
        ```

    - python 脚本查询

        *运行这个脚本要运行虚拟环境*

        [whois_check.py](./yjtools/)

        [whois_check_socket](./yjtools/)

        ```cmd
        (venv) F:\ProgramFiles\penetration\yjtools>python whois_check.py
        输入查询 Whois 的域名：zhihu.com
        域名：['ZHIHU.COM', 'zhihu.com']
        邮箱：abuse@dnspod.com
        注册人：REDACTED FOR PRIVACY
        注册时间：2007-06-15 17:28:11
        更新时间：[datetime.datetime(2022, 4, 18, 4, 54, 44), datetime.datetime(2022, 4, 18, 12, 54, 47)]

        (venv) F:\ProgramFiles\penetration\yjtools>
        (venv) F:\ProgramFiles\penetration\yjtools>python whois_check_socket.py
        >>> 输入查询 Whois 的域名：>>> zhihu.com
        Domain Name: ZHIHU.COM
        Registry Domain ID: 1030643753_DOMAIN_COM-VRSN
        Registrar WHOIS Server: whois.dnspod.cn
        Registrar URL: http://www.dnspod.cn
        Updated Date: 2022-04-18T04:54:44Z
        Creation Date: 2007-06-15T17:28:11Z
        Registry Expiry Date: 2029-09-29T11:59:59Z
        Registrar: DNSPod, Inc.
        Registrar IANA ID: 1697
        Registrar Abuse Contact Email:
        Registrar Abuse Contact Phone:
        Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
        Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
        Name Server: NS3.DNSV5.COM
        Name Server: NS4.DNSV5.COM
        DNSSEC: unsigned
        URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
        >>> Last update of whois database: 2024-05-21T13:02:23Z <<<
        ```

### whois 反查

whois 反查，可以通过注册人、注册人邮箱、注册人手机电话反查 Whois 信息

1. Whois反查方式
   1. 根据已知域名反查，分析出此域名的注册人、邮箱、电话等字段；
   2. 根据已知域名 WHOIS 中的注册邮箱来反查得出其它域名 WHOIS 中注册邮箱与此相同的域名列表；
   3. 根据已知域名 WHOIS 中的注册人来反查得出其它域名 WHOIS 中注册人与此相同的域名列表；

    缺点：很多公司都是DNS解析的运营商注册的,查到的是运营商代替个人和公司注册的网站信息。

    - [主站](https://whois.chinaz.com/)

        - [域名反查](https://whois.chinaz.com/reverse?ddlSearchMode=0)

        - [邮箱反查](https://whois.chinaz.com/reverse?ddlSearchMode=1)

        - [注册人反查](https://whois.chinaz.com/reverse?ddlSearchMode=2)

        - [电话反查](https://whois.chinaz.com/reverse?ddlSearchMode=3)

### 备案信息

备案号是网站是否合法注册经营的标志，可以用网页的备案号反查出该公司旗下的资产

[ICP/IP地址/域名信息备案管理系统](https://beian.miit.gov.cn/#/Integrated/index)

[站长之家](http://icp.chinaz.com/)

[ICP备案查询](http://icp.chinaz.com/)

### 子域名

#### GoogleHacking

[Google Hacking Database](https://www.exploit-db.com/google-hacking-database)

- 高级搜索语法

    |字符|注释|例子|注释|
    |----|----|----|----|
    |intext|寻找正文中含有关键字的网页|intext:后台登录|将只返回正文中包含"后台登录" 的网页|
    |intitle|寻找标题中含有关键字的网页|intitle:后台登录|"intitle: login password" 会返回标题含有login，而页面里面随便什么地方含有password的网页|
    |allintitle|可以指定多个词，'intitle: login intitle: password" 和"allintitle: login password"的搜索结果是一样的。|allintitle: 后台登录 管理员|返回标题中含有后台登录和管理员的页面|
    |inurl|指定url中的关键词|inurl:login|返回url中包含login的网页|
    |allinurl|同时指定url中多个关键词|allinurl:login admin|返回url中包含login和admin的页面|
    |site|指定访问站点|site:baidu.com inurl:login|只在baidu.com中查找url中包含login的网页|
    |filetype|指定文件类型|site:baidu.com filetype:pdf|将只返回 baidu.com 站点上文件类型为 pdf 的网页|
    |link|指定链接的网页 |link:www.baidu.com|将返回所有包含指向www.baidu.com 的网页|
    |related|相似类型的网页|related:www.xjtu.edu.cn|将返回与www.xjtu.edu.cn 相似的页面，相似指的是网页的布局相似|
    |info|返回站点的指定信息|info:www.baidu.com|将返回百度的一些信息|
    |define|返回某个词语的定义|define:Hacker|将返回关于 Hacker 的定义|
    |cache|网页快照，谷歌将返回给你它存储下来的历史页面|cache:www.hackingspirits.com guest|将返回指定网站的缓存，并且正文中含有guest|

- 举例:

    |语法 |注释|
    |-----|----|
    |inurl://admin/login.php|查找管理员登录页面|
    |inurl:/phpmyadmin/index.php| 查找后台数据库管理页面|
    |site:baidu.com inurl:Login| 只在baidu.com 中查找url中含有 Login的网页|
    |site:baidu.com filetype:pdf| 只返回baidu.com站点上文件类型为pdf的网页|
    |link:www.baidu.com| 返回所有包含指向www.baidu.com 的网页|
    |related:www.llhc.edu.cn| 返回与www.llhc.edu.cn 网页布局相似的页面|
    |site:xx.com intext:管理 site:xx.com inurl:login site:xx.com intitle:后台 |查找网站后台|
    |site:xx.com filetype:php site:xx.com filetype:asp site:xx.com filetype:jsp site:xx.com filetype:aspx|查看服务器使用的程序|
    |site:xx.com inurl:file site:xx.com inurl:load| 查看上传漏洞|

- index of

    利用 Index of 语法去发现允许目录浏览的 web 网站，就像在本地的普通目录一样。

    ```url
    index of /admin
    index of /passwd
    index of /password
    index of /mail
    "index of /" +passwd
    "index of /" +password.txt
    "index of /" +.htaccess
    "index of /root"
    "index of /cgi-bin"
    "index of /logs"
    "index of /config"
    ```
- 子域名获取

    site:zhihu.com

#### 第三方web接口

[DNS聚合器](https://dnsdumpster.com/)

https://www.dnsgrep.cn/



#### 网络空间安全搜索引擎

   - [FOFA](https://fofa.info/)

      FOFA 是白帽汇推出的一款网络空间搜索引擎，它通过进行网络空间测绘，能够帮助研究人员或者企业迅速进行网络资产匹配，例如进行漏洞影响范围分析、应用分布统计、应用流行度排名统计等。

   - [鹰图](https://hunter.qianxin.com/)

      奇安信网络空间测绘平台（简称HUNTER平台），可对全球暴露在互联网上的服务器和设备进行：资产探测、端口探活、协议解析、应用识别。

   - [zoomeye](https://www.zoomeye.org/)

      钟馗之眼 ZoomEye 是启明星辰推出的一个检索网络空间节点的搜索引擎。通过后端的分布式爬虫引擎对全球节点的分析，对每个节点的所拥有的特征进行判别，从而获得设备类型、固件本、分布地点、开放端口服务等信息。

   - [shodan](https://www.shodan.io/)

#### SSL证书查询

[地址1-crt.sh](https://crt.sh/)

[地址2-facebook](https://developers.facebook.com/tools/ct/search/)

#### JS文件发现子域名

[JSFinder](./JSFinder/)

#### 子域名收集工具

- 被动子域枚举

    收集子域信息的过程不会产生任何流量，目的是要隐身且留下很少或没有足迹。

    1. 证书透明度

        证书透明度日志通过设计包含了由参与的CA针对任何给定域颁发的所有证书，SSL/TLS证书通常包含域名、子域名和电子邮件地址。这些日志是公开的，这使得它们成为攻击者的信息宝库。通过查看证书透明度日志，攻击者可以收集有关组织基础结构的大量信息。
        
        1. ~~CTFR--被动子域枚举~~

            滥用证书透明度日志，几秒钟内获取子域名

            [CTFR](./ctfr/)

            [CTFR仓库](https://github.com/UnaPibaGeek/ctfr)
        
        2. [ssl证书](#ssl证书查询)

    2. 搜索引擎

        [网络空间安全搜索引擎](#网络空间安全搜索引擎)

        [高级搜索语法](#googlehacking)

    3. DNS聚合器

        [第三方Web接口](#第三方web接口)

- 主动子域枚举

    攻击者通过探测目标组织管理的基础结构来收集子域信息，主动枚举会产生检测可能导致的流量。

    1. 暴力枚举：通过字典直接访问子域名，通过状态码判断是否存在。

       1. 子域名挖掘机

            https://gitee.com/yijingsec/LayerDomainFinder

       2. Subdomainsbrute

            高并发的DNS暴力枚举工具

            [github地址](https://github.com/lijiejie/subDomainsBrute)
    
    2. DNS记录：DNS记录有时会显示子域信息。

        1. ~~Knockpy~~

            通过单词列表枚举目标域上的子域，旨在扫描DNS区域传输，并尝试绕过通配符DNS记录自动进行。

            [knockpy.py](./knock/)

        2. Subbrute

            根据DNS记录查询子域名，使用开放式解析器作为代理来规避DNS速率限制，该设计还提供了一层匿名性，不会将流量直接发送到目标的名称服务器。

            [Subbrute仓库](https://github.com/TheRook/subbrute)

1. OneForAll

    [OneForAll](./OneForAll/)

    [github地址](https://github.com/shmilylty/OneForAll)


2. subdomain3

    Subdomain3是新一代子域名爆破工具,它帮助渗透测试者相比与其他工具更快发现更多的信息,这些信息包括子域名,IP,CDN信息等

    [github地址](https://github.com/yanxiu0614/subdomain3)

3. ESD

    子域名收集工具

    [github地址](https://github.com/FeeiCN/ESD)

    [ESD文档](https://www.yuque.com/esd)

## IP信息收集

### IP反查域名

https://tool.chinaz.com/same

https://tools.ipip.net/ipdomain.php

https://www.dnsgrep.cn/

https://site.ip138.com/

- ***旁注***

    >如果渗透目标为虚拟主机，那么通过IP反查到的域名信息很有价值，因为一台物理服务器上面可能运行多个虚拟主机。这些虚拟主机有不同的域名，但通常共用一个IP地址。如果你知道有哪些网站共用这台服务器，就有可能通过此台服务器上其他网站的漏洞获取服务器控制权，进而迂回获取渗透目标的权限

### 域名查IP

http://ip.tool.chinaz.com/

https://ipchaxun.com/

https://site.ip138.com/

知道一个站点的域名需要得到它的IP以便之后获取端口信息或扫描等后续工作

### C段存活主机探测

查找与目标服务器IP处于同一个C段的服务器IP

- nmap

    [nmap 帮助文档](https://nmap.org/book/man.html)

    ```bash
    nmap -sP www.yijinglab.com/24
    namp -sP 192.168.1.*
    ```

    ```cmd
    F:\ProgramFiles\penetration\OneForAll>nmap -sP 192.168.31.*
    Starting Nmap 7.95 ( https://nmap.org ) at 2024-05-23 19:32 中国标准时间
    Nmap scan report for XiaoQiang (192.168.31.1)
    Host is up (0.00088s latency).
    MAC Address: 24:CF:24:EA:9A:53 (Beijing Xiaomi Mobile Software)
    Nmap scan report for 192.168.31.89
    Host is up.
    Nmap done: 256 IP addresses (2 hosts up) scanned in 2.43 seconds
    ```

- TxPortMap

    帮助信息

    ```cmd
    .\TxPortMap -h
    ```

    example:

    ```cmd
    .\TxPortMap -i www.zhihu.com/24 -p 80
    ```

### CDN(内容分发网络)

#### CDN判断

1. 多地ping

    用各种多地 ping 的服务，查看对应 IP 地址是否唯一

    http://ping.chinaz.com/

    https://ping.aizhan.com/

    http://www.webkaka.com/Ping.aspx

2. 国外访问

    因为有些网站设置CDN可能没有把国外的访问包含进去，所以可以这么绕过

    https://ping.sx/ping

#### CDN绕过

1. 查询子域名IP

    CDN 流量收费高，所以很多站长可能只会对主站或者流量大的子站点做了 CDN，而很多小站子站点又跟主站在同一台服务器或者同一个C段内，此时就可以通过查询子域名对应的 IP 来辅助查找网站的真实IP

    https://ip.tool.chinaz.com/ipbatch

2. MX(Mail Exchanger)记录邮件服务

    MX记录是一种常见的查找IP的方式。如果网站在与web相同的服务器和IP上托管自己的邮件服务器，那么原始服务器IP将在MX记录中

3. 查询历史DNS记录

    查看 IP 与 域名绑定的历史记录，可能会存在使用 CDN 前的记录;

    https://viewdns.info/iphistory/

    https://www.ip138.com/

    域名解析时会添加解析记录，这些记录有：A记录、AAAA记录、CNAME记录、MX记录、NS记录、TXT记录。

    [DNS记录类型](https://developer.aliyun.com/article/331012)

## 端口信息收集

[常用端口利用](https://edu.yijinglab.com/post/280)

### 端口扫描

[nmap参考指南](https://nmap.org/man/zh/)

- nmap功能

    1. 检测网络存活主机（主机发现）
    2. 检测主机开放端口（端口发现或枚举）
    3. 检测相应端口软件（服务发现）版本
    4. 检测操作系统，硬件地址，以及软件版本
    5. 检测脆弱性的漏洞（nmap的脚本）

- 端口状态

    Open 端口开启，数据有到达主机，有程序在端口上监控

    Closed 端口关闭，数据有到达主机，没有程序在端口上监控
    
    Filtered 数据没有到达主机，返回的结果为空，数据被防火墙或IDS过滤

    UnFiltered 数据有到达主机，但是不能识别端口的当前状态

    Open|Filtered 端口没有返回值，主要发生在UDP、IP、FIN、NULL和Xmas扫描中

    Closed|Filtered 只发生在IP ID idle扫描

- 基础用法

    ```cmd
    nmap -A -T4 192.168.1.1
    A：全面扫描\综合扫描
    T4：扫描速度，共有6级，T0-T5
    不加端口则扫描默认端口，1-1024 + nmap-service

    单一主机扫描：
    nmap 192.168.1.2

    子网扫描：
    nmap 192.168.1.1/24

    多主机扫描：
    nmap 192.168.1.1 192.168.1.10

    主机范围扫描：
    nmap 192.168.1.1-100

    IP地址列表扫描：
    nmap –iL target.txt

    扫描除指定IP外的所有子网主机：
    nmap 192.168.1.1/24 --exclude 192.168.1.1

    扫描除文件中IP外的子网主机：
    nmap 192.168.1.1/24 --excludefile xxx.txt

    扫描特定主机上的80,21,23端口：
    nmap –p 80,21,23 192.168.1.1
    ```

- 扫描全部端口

    ```cmd
    nmap -sS -v -T4 -Pn -p 0-65535 -oN FullTCP -iL liveHosts.txt

    -sS：SYN扫描,又称为半开放扫描，它不打开一个完全的TCP连接，执行得很快，效率高(一个完整的tcp连接需要3次握手，而-sS选项不需要3次握手)

    优点：Nmap发送SYN包到远程主机，但是它不会产生任何会话，目标主机几乎不会把连接记入系统日志。(防止对方判断为扫描攻击)，扫描速度快，效率高，在工作中使用频率最高
    缺点：它需要root/administrator权限执行

    -Pn：扫描之前不需要用ping命令，有些防火墙禁止ping命令。可以使用此选项进行扫描

    -iL：导入需要扫描的列表
    ```

- 扫描常用端口及服务信息

    nmap -sS -T4 -Pn -oG TopTCP -iL LiveHosts.txt

- 系统扫描：

    nmap -O -T4 -Pn -oG OSDetect -iL LiveHosts.txt

- 版本检测：

    nmap -sV -T4 -Pn -oG ServiceDetect -iL LiveHosts.txt

- NMAP漏洞扫描

    nmap -p445 -v --script smb-ghost 192.168.1.0/24

## 网站信息收集

### 操作系统

1. ping 判断：windows的TTL值一般为128，Linux则为64。
TTL大于100的一般为windows，几十的一般为linux。
2. nmap -O 参数
3. windows 大小写不敏感， linux 则区分大小写

### 网站服务 容器类型

1. F12查看响应头 Server 字段
2. whatweb ： https://www.kali.org/tools/whatweb/
3. wappalyzer 插件：+

    - Edge浏览器wappalyzer插件地址

    - Chrome浏览器wappalyzer插件地址

    apache ，nginx ，tomcat，IIS

    通过容器类型、版本可考虑对应容器存在的漏洞（解析漏洞）

### 脚本类型

主要是为了确定上传文件类型

1. php
2. jsp
3. asp/aspx
4. python

### 数据库类型

[sql注入判断数据库类型](https://edu.yijinglab.com/post/298)

- 常见数据库类型

    1. Oracle
    2. MySQL
    3. SQL Server
    4. Postgresql
    5. Mongodb
    6. Access

- 前端与数据库类型

    asp：SQL Server，Access

    .net：SQL Server

    php：MySQL，PostgreSQL

    java：Oracle，MySQL

- 常见数据库端口

    Oracle：默认端口 1521

    MySQL：默认端口 3306

    SQL Server：默认端口 1433

    Postgresql：默认端口 5432

    Mongodb：默认端口 27017

    Access：文件型数据库，不需要端口

### CMS(内容管理系统)识别

常见CMS：WordPress、Joomla、Drupal、dedecms(织梦)、Discuz、phpcms等

[CMS内容管理系统检索及安全分析平台](http://www.yunsee.cn/cms/)

- ~~CMS识别检测工具~~

    ~~[CMS-Exploit-Framework](https://github.com/Q2h1Cg/CMS-Exploit-Framework):一款CMS漏洞利用框架，通过它可以很容易地获取、开发CMS漏洞利用插件，并对目标应用进行测试。~~

    ~~[CMSeek](https://github.com/Tuhinshubhra/CMSeeK):使用Python3构建，超过170个CMS的基本CMS检测，包括版本检测、用户枚举、插件枚举、主题枚举、核心漏洞检测、配置泄露检测等。~~

    https://gitee.com/yijingsec/joomscan

    https://gitee.com/yijingsec/wpscan

    https://gitee.com/yijingsec/TPscan

### 敏感文件 目录

敏感文件探测工具:

~~[FileScan](https://github.com/Mosuan/FileScan)~~

#### 常见敏感目录 文件

- robots.txt

    纯文本文件，在这个文件中网站管理者可以声明该网站中不想被搜索引擎访问的部分，或者指定搜索引擎只收录指定的内容。当一个搜索引擎（又称搜索机器人或蜘蛛程序）访问一个站点时，它会首先检查该站点根目录下是否存在robots.txt，如果存在，搜索机器人就会按照该文件中的内容来确定访问的范围；如果该文件不存在，那么搜索机器人就沿着链接抓取

- crossdomain.xml

    跨域，顾名思义就是需要的资源不在自己的域服务器上，需要访问其他域服务器。跨域策略文件是一个xml文档文件，主要是为web客户端(如Adobe Flash Player等)设置跨域处理数据的权限。

    重点查看 allow-access-from 字段获取网站目录信息

    Google Hacking 语法:

    ```url
    inurl:crossdomain filetype:xml intext:allow-access-from
    ```

- sitemap.xml

    方便网站管理员通知搜索引擎他们网站上有哪些可供抓取的网页。最简单的 Sitemap 形式，就是XML 文件，在其中列出网站中的网址以及关于每个网址的其他元数据（上次更新的时间、更改的频率以及相对于网站上其他网址的重要程度为何等），以便搜索引擎可以更加智能地抓取网站。

    Google Hacking 语法:

    ```url
    inurl:sitemap filetype:xml
    ```

- 后台目录
- 网站安装目录
- 网站上传目录
- mysql管理页面
- phpinfo
- 网站文本编辑器
- 测试文件
- 网站备份文件（.rar、.zip、.7z、.tar、.gz、.bak）

    可以通过路径猜解，猜测备份文件名下载备份文件。

- DS_Store文件
- vim编辑器备份文件（.swp）
- WEB-INF/web.xml文件

    WEB-INF是Java的Web应用的安全目录，如果想在页面中直接访问其中的文件，必须通过web.xml文件对要访问的文件进行相应映射才能访问。

    - WEB-INF主要包含以下文件或目录：

        WEB-INF/web.xml：Web应用程序配置文件，描述了servlet和其他的应用组件及命名规则

        WEB-INF/database.properties：数据库配置文件

        WEB-INF/classes/：一般用来存放Java类文件（.class）

        WEB-INF/lib/：用来存放打包好的库（.jar）

        WEB-INF/src/：用来存放源代码

    通过找到 web.xml 文件，推断 class 文件的路径，最后直接下载 class 文件，再通过反编译 class 文件，得到网站源码

#### 源码泄露

- Github泄露

    ```url
    site:Github.com smtp
    site:Github.com smtp @qq.com
    site:Github.com smtp @126.com
    site:Github.com smtp @163.com
    site:Github.com smtp @sina.com.cn
    site:Github.com smtp password
    site:Github.com String password smtp
    site:Github.com sa password
    site:Github.com root password
    site:Github.com User ID='sa';Password
    site:Github.com svn
    site:Github.com svn username
    site:Github.com svn password
    site:Github.com svn username password
    site:Github.com inurl:sql
    site:Github.com password
    site:Github.com ftp ftppassword
    site:Github.com 密码
    site:Github.com 内部
    ```

- .git泄露

    GoogleHacking 语法:

    ```url
    ".git" intitle:"index of"
    ```

    脚本工具：

    [GitHack](https://github.com/lijiejie/GitHack)

- .svn泄露

    跟git一样，都是用来版本迭代的一个功能。具体一点就是使用svn checkout功能来更新代码。

    GoogleHacking语法:
    ```url
    ".svn" intitle:"index of"
    ```

    脚本工具:

    [SvnExploit](https://github.com/admintony/svnExploit)

#### 敏感目录收集

1. 网页中寻找

    在robots.txt中看能否发现敏感目录

    F12源代码链接处

    通过查看一些图片的属性路径，运气好会发现很多隐藏的目录

    结合域名+目录，用御剑进行扫描

    手动输入一些常见的后台管理地址进行访问

2. 其他端口中寻找

    有时候网站的不同端口中有一些便是专门的后台管理地址。

    例如： http://www.xxx.com:8080

3. 网站分目录下寻找

    有的时候网站会把管理地址放在一个分目录下，有的时候一个网站比较大，后台管理页面也比较多，就要分目录的去找，

    例如： http://www.xxx.com/test/admin/manage.php

    你可以通过一些方式获取到网站的目录，然后在这个目录下进行扫描。当一个网站你扫描根目录没有任何收获时，这个时候通过分析网站的目录结构，然后扫描域名+目录，就能找出它的后台管理地址。

4. 子域名下寻找
    有的时候网站的管理地址会放在子域名下，所以主站什么都找不到的情况下，如果发现子域名，就通过这些方法去子域名下找一下吧。

    例如： http://admin.xxx.com/login

#### 目录扫描探测

[dirsearch](https://github.com/maurosoria/dirsearch)

[dirmap](https://github.com/H4ckForJob/dirmap)

### 网站WAF(Web Application FireWall)识别

[常见waf拦截页面总结](https://edu.yijinglab.com/post/299)

- wafw00f

    [源码](https://github.com/EnableSecurity/wafw00f)

    [kalitools](https://www.kali.org/tools/wafw00f/)

- nmap

    ```cmd
    nmap –p80,443 --script http-waf-detect ip

    nmap –p80,443 --script http-waf-fingerprint ip
    ```

- sqlmap

    SQLmap中自带了识别WAF的模块，可以识别出网站的WAF种类。如果安装的WAF没有什么特征，识别出来的就是Generic(Unknown)。

### 指纹信息收集

- web

    [潮汐指纹](http://finger.tidesec.net/) 

    [云悉指纹](https://www.yunsee.cn/)

- ~~ssh_scan~~

    SSH配置和策略扫描程序

    [ssh_scan](https://github.com/mozilla/ssh_scan)

- ~~w12scan~~

    一款网络资产发现引擎，通过Web接口下发任务，会自动将相关的资产聚合在一起方便分析使用

    [w12scan](https://github.com/w-digital-scanner/w12scan)

    [配置参考](https://www.bugku.com/thread-3810-1-1.html)

### 其他信息收集

- ~~sslscan~~

    kali自带的工具，能够基于服务器的安全通信来分析服务器的配置文件。

## 自动化信息收集

### ARL灯塔

[仓库地址](https://github.com/Aabyss-Team/ARL/)

#### 安装

- 方式一

    ```bash
    git clone https://gitee.com/yijingsec/LinuxEnvConfig.git
    cd LinuxEnvConfig
    sudo bash LinuxEnvConfig.sh
    ```
    
    选择安装ARL对应的序号，脚本会自动安装并运行ARL，启动完毕后会返回服务访问的URL地址及默认登录账号密码 admin/arlpass

- 方式二

    ```bash
    cd /opt/
    mkdir docker_arl
    wget -O docker_arl/docker.zip https://github.com/Aabyss-Team/ARL/archive/refs/tags/2.6.2-1.zip
    cd docker_arl
    unzip -o docker.zip
    cd 解压文件名/docker
    docker-compose pull
    docker volume create arl_db
    docker-compose up -d
    ```

    ARL一共有五个容器，必须全部处在Up状态，ARL才能正常运行

    访问地址：https://ip:5003

    *注意：如果实在vps上，则需要在安全组(华为云)上开启5003端口*

### EHole

[github仓库](https://github.com/EdgeSecurityTeam/EHole)

**本地识别**

```cmd
# URL地址需带上协议,每行一个
EHole finger -l url.txt
```

**FOFA识别**

注意：从FOFA识别需要配置高级版 FOFA 密钥以及邮箱，注册用户无法直接使用，在config.ini内配置好密钥以及邮箱即可使用。

```cmd
#支持单IP或IP段
EHole finger -f 192.168.1.1/24
```
**结果输出**

```cmd
#结果输出至export.json文件
EHole finger -l url.txt -json export.json
```