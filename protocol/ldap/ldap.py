# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output, logger, POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import ldap3


class LdapAnonymousPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 11, 2020'
    createDate = 'Jul 11, 2020'
    name = 'ldap'
    appName = 'ldap'
    appVersion = 'v1.0.0'
    vulType = '匿名登录'
    protocol = 'ldap'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 389
        result = {}
        if check_anonymous(host,port):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['extra'] = 'anonymous登录'
        return self.parse_output(result)

    def _attack(self):
        return self._verify()


def check_anonymous(host, port):
    try:
        info = '{}:{}\t'.format(host,port)
        server = ldap3.Server(
            host, port, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(server, auto_bind=True)
        if len(server.info.naming_contexts) > 0:
            info += u'%s:%d //存在ldap匿名访问漏洞:\n' % (host, port)
            logger.info(info)
            return True
    except Exception as e:
        info += str(e)
        logger.info(info)
    return False


register_poc(LdapAnonymousPOC)
