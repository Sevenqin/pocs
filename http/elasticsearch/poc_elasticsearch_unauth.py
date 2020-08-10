# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads
import json

class ElasticsearchUnauthPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 9, 2020'
    createDate = 'Aug 9, 2020'
    name = 'es未授权访问'
    appName = 'elasticsearch'
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
        # host = self.getg_option("rhost")
        # port = self.getg_option("rport") or 9200
        url = self.url
        if not url.startswith('http'):
            url = 'http://'+url
        try:
            res = requests.get(url)
            if res.status_code == 200 and 'version' in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                obj = json.loads(res.text)
                version = obj.get('version',{}).get('number','')
                result['VerifyInfo']['evidence'] = version
                result['extra'] = version
        except:
            pass        
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(ElasticsearchUnauthPOC)