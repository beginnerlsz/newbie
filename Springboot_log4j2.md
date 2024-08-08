# Springboot

## Springboot 简介

### 常见端点信息

- Spring Boot 1.x 默认内置路由根路径以 `/`开头
- Spring Boot 2.x 默认内置路由根路径以 `/actuator`开头
- `/manage` `/management`
- Spring Boot Actuator 默认内置路由名`/env` 或`/appenv`
- [常见端点信息](https://docs.spring.io/spring-boot/docs/2.1.1.RELEASE/reference/html/production-ready-endpoints.html)

### SpringBoot 漏洞特征

- 小绿叶 favicon.ico

- 404报错页面 -- Whitelable Error Page

- 漏洞识别脚本

  [SB-Actuator](../src/info_collect/directory/SB-Actuator)

  [SpringBoot-Scan](../src/info_collect/directory/SpringBoot_Scan)

## Apache Log4j2

### 漏洞简介

`Lookup` 功能下`Jndi Lookup` 模块允许在输出日志信息时通过相应协议去请求远程主机上的资源。没有对输入进行过滤和验证。

### 漏洞范围

- 组件
  - Apache Struts2
  - Apache Solr
  - Apache Druid
  - Apache Flink
  - spring-boot-strater-log4j2
- Log4j2版本
  - 2.0 - 2.15.0-rc1

