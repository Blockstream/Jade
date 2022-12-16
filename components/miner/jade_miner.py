#!/usr/bin/env python

import sys
import logging
from binascii import unhexlify as uh
from jadepy import JadeAPI
import binascii
import requests
import time
import serial

jadehandler = logging.StreamHandler()
jadehandler.setLevel(logging.INFO)

logger = logging.getLogger('jade')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)

logger = logging.getLogger('jade-device')
logger.setLevel(logging.DEBUG)
logger.addHandler(jadehandler)


create_jade_fn = JadeAPI.create_serial
kwargs = {'device': None, 'timeout': 1}

rpc_cookie = None


host = "127.0.0.1:18443"

if len(sys.argv) == 2:
    address = sys.argv[1]
elif len(sys.argv) == 3:
    address = sys.argv[1]
    rpc_cookie = sys.argv[2]
elif len(sys.argv) == 4:
    address = sys.argv[1]
    rpc_cookie = sys.argv[2]
    host = sys.argv[3]
else:
    print('Error, missing address')
    sys.exit(1)


if not rpc_cookie:
    with open("/home/lnahum/.bitcoin/regtest/.cookie") as f:
      rpc_cookie = f.read()

rpc_pwd = rpc_cookie.split(":")[1]
url = f"http://__cookie__:{rpc_pwd}@{host}"
headers = {'Content-Type': 'application/json'}

params = {
    "rules": ["segwit"]  # request a template with segwit support
}

with create_jade_fn(**kwargs) as jade:
    response = requests.post(url, json={"method": "getblocktemplate", "params": [params]}, headers=headers)
    t = response.json()['result']
    bits = int.from_bytes(uh(t['bits']), byteorder='big', signed=False)
    res = jade.mine(t['version'], uh(t['previousblockhash']), uh(t['target']), t['curtime'], bits, t['height'], address)
    session = requests.Session()
    while isinstance(res, (bool)) and res:
       # mining started successfully or we have updated our template

       # let's check if we already found a solution
       try:
           res = jade.jade.read_response()
           res = res['result']
       except EOFError:
           res = True

       if isinstance(res, (bool)) and res:
           time.sleep(2)
       else:
           # indeed a solution was found
           response = session.post(url, json={"method": "submitblock", "params": [binascii.hexlify(res).decode("utf-8")]}, headers=headers)
           block_submitted_answer = response.json()
           print(block_submitted_answer)
           time.sleep(0.5)
       # we should check this how often?
       try:
           response = session.post(url, json={"method": "getblocktemplate", "params": [params]}, headers=headers)
           if response.json()['result']['previousblockhash'] != t['previousblockhash']:
               # we got a new block header
               t = response.json()['result']
               bits = int.from_bytes(uh(t['bits']), byteorder='big', signed=False)
               res = jade.mine(t['version'], uh(t['previousblockhash']), uh(t['target']), t['curtime'], bits, t['height'], address)
           else:
               res = True
       except Exception as e:
            session = requests.Session()
