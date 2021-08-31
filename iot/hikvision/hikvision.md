# Hikvision
fofa搜索指纹 app="HIKVISION-视频监控"

## 摄像头弱口令漏洞
### 漏洞说明
默认口令admin/12345
### 涉及范围
/
### 检测方法
**pocsuite**
poc_camera_weakpass.py

### 利用方法
/

## 登录绕过漏洞
### 漏洞说明
通过浏览器访问，在cookie中加入特定的信息，能够绕过登录界面，直接访问main界面。
### 检测方法
**pocsuite**
poc_camera_anonymous_access.py

## 信息泄露漏洞
### 漏洞说明
hikvision特定版本的摄像头，访问后面页面，能够查看当前摄像头画面，用户信息等。
### 检测方法
**pocsuite**
poc_camera_info_leakage
**手动访问**
访问一下路径，查看敏感信息
- `/Security/users?auth=YWRtaW46MTEK`
- `/Security/users?auth=YWRtaW46MTEK`


## 流媒体服务器弱口令漏洞
fofa指纹 title="流媒体管理服务器"
### 漏洞说明
默认口令admin/12345
### 监测方法
**pocsuite**
poc_server_weakpass.py


## 流媒体顾服务任意文件下载漏洞

### 漏洞说明
杭州海康威视系统技术有限公司流媒体管理服务器存在弱口令漏洞，攻击者可利用该漏洞登录后台通过文件遍历漏洞获取敏感信息

### 检测方法
**pocsuite**
poc_server_file_download.py


## 视频接入网关

### 漏洞说明

### 检测方法
