# Linux普通用户无法使用docker命令

## 方法一（实测有效）

### 添加dockers用户组

```bash
sudo groupadd docker
```

一般来说这一步可以跳过，在安装的时候安装程序会自动创建

### 将用户添加到docker组

```bash
sudo gpasswd -a $USER docker
```

### 更新用户组

```bash
newgrp docker
```

### 测试命令

```bash
docker images ## 列出所有镜像
```

## 方法二

将当前用户加入dockers组

```bash
sudo usermod -aG docker $USER
```

执行完命令后重新登录