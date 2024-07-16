# Docker安装

## Docker Engine - Ubuntu

### 前提

#### 卸载旧版本

官方文档

> Moreover, Docker Engine depends on `containerd` and `runc`. Docker Engine bundles these dependencies as one bundle: `containerd.io`. If you have installed the `containerd` or `runc` previously, uninstall them to avoid conflicts with the versions bundled with Docker Engine.

```bash
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
```

### 安装方法

#### 使用apt仓库下载

1. 配置Docker apt 仓库

   ```bash
   # Add Docker's official GPG key:
   sudo apt-get update
   sudo apt-get install ca-certificates curl
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   
   # Add the repository to Apt sources:
   echo \
     "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
     $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
     sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   sudo apt-get update
   ```

   > *Note*
   >
   > If you use an Ubuntu derivative distro, such as Linux Mint, you may need to use `UBUNTU_CODENAME` instead of `VERSION_CODENAME`.

2. 安装 Docker 包

   - 最新版：

   ```bash
   sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

   - 指定版本：

     ```bash
     # List the available versions:
     apt-cache madison docker-ce | awk '{ print $3 }'
     
     5:26.1.0-1~ubuntu.24.04~noble
     5:26.0.2-1~ubuntu.24.04~noble
     ...
     
     VERSION_STRING=5:26.1.0-1~ubuntu.24.04~noble
     sudo apt-get install docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-buildx-plugin docker-compose-plugin
     ```

3. 验证是否安装成功

   ```bash
   sudo docker run hello-world
   ```

**更新 Docker Engine**

根据步骤2中指定版本的方法

#### 从package下载

用这种用方法的话每次更新都需要下载新的文件

1. 官网下载安装包https://download.docker.com/linux/ubuntu/dists/

2. 选择与自己系统对应的Ubuntu的版本

3. 在`pool/stable/`选择系统架构

4. Download the following `deb` files for the Docker Engine, CLI, containerd, and Docker Compose packages:

   - `containerd.io_<version>_<arch>.deb`
   - `docker-ce_<version>_<arch>.deb`
   - `docker-ce-cli_<version>_<arch>.deb`
   - `docker-buildx-plugin_<version>_<arch>.deb`
   - `docker-compose-plugin_<version>_<arch>.deb`

5. 安装`.deb`包,这里的路径应该是自己的下载路径

   ```bash
   sudo dpkg -i ./containerd.io_<version>_<arch>.deb \
     ./docker-ce_<version>_<arch>.deb \
     ./docker-ce-cli_<version>_<arch>.deb \
     ./docker-buildx-plugin_<version>_<arch>.deb \
     ./docker-compose-plugin_<version>_<arch>.deb
   ```

6. 验证

   ```bash
   sudo service docker start
   sudo docker run hello-world
   ```

# docker-compose 安装

1. 下载 compose standalone 

   ```bash
   curl -SL https://github.com/docker/compose/releases/download/v2.27.1/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
   ```

2. 赋予执行权限

   ```bash
   sudo chmod +x /usr/local/bin/docker-compose
   ```

   

# 卸载

1. Uninstall the Docker Engine, CLI, containerd, and Docker Compose packages:

   

   ```console
   $ sudo apt-get purge docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
   ```

2. Images, containers, volumes, or custom configuration files on your host aren't automatically removed. To delete all images, containers, and volumes:

   

   ```console
   $ sudo rm -rf /var/lib/docker
   $ sudo rm -rf /var/lib/containerd
   ```

You have to delete any edited configuration files manually.