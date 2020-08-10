# -*- coding: utf-8 -*-
# author: seven
# docker默认监听2375端口
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads
import json

class DockerUnauthPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 9, 2020'
    createDate = 'Aug 9, 2020'
    name = 'docker未授权访问'
    appName = 'docker'
    appVersion = 'v1.0.0'
    vulType = '未授权访问'
    protocol = 'http'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 2375
        url = f'http://{host}:{port}/version'
        res = requests.get(url)
        if res.status_code == 200 and 'ApiVersion' in res.text:
            obj = json.loads(res.text)
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['api'] = obj.get('ApiVersion','')
            result['extra'] = obj.get('ApiVersion','')  
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(DockerUnauthPOC)