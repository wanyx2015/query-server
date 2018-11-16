# -*- coding: utf-8 -*-

import requests
import json
from Crypto.Hash import SHA256
from binascii import b2a_hex, a2b_hex
import time

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("ASCII") # <- or any other encoding of your choice
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

if __name__ == '__main__':
    # url = 'https://crp.chinadep.com/api/d/qryData'
    url = 'https://crp.chinadep.com/api/p/crp/'
    memId = '0000109'
    jobId = 'JON20171122000000091'
    serialNo = '1201611161916567677531846'
    appKey = '02DF41BAAB249FB5F42BB6DB7FFE4A3377AFFDA59C849506EEDA52351E65B0F345'
    hash_str = str.encode(memId + serialNo + jobId + appKey)
    hash_inst = SHA256.new(hash_str)

    digest = hash_inst.digest()
    digest_str = b2a_hex(digest)
    print(digest)
    print(digest_str)
    data = {
        'pubReqInfo': {'memId': memId,
                      'serialNo': serialNo,
                      'jobId': 'JON20161005000000076',
                      'timeStamp': str(int(time.time())),
                      'authMode': '00',
                      'reqSign': digest_str},
        'busiInfo': {"identityNumber":"340103198511030017", "name":"黄默"},
    }

    jsonified = json.dumps(data, cls=MyEncoder)
    print('jsonified', jsonified)
    print(10*'*' + '\n' )
    print(requests.post(url, json.dumps(data, cls=MyEncoder)).content)

