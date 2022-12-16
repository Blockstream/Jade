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

if len(sys.argv) == 2:
    address = sys.argv[1]
else:
    print('Error, missing address')
    sys.exit(1)

url_template = "https://jademiner.blockstream.com/node/template"
url_block = "https://jademiner.blockstream.com/node/block"

with create_jade_fn(**kwargs) as jade:
    response = requests.get(url_template)
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
           response = session.post(url_block, data={"block": binascii.hexlify(res).decode("utf-8")})
           block_submitted_answer = response.json()
           print(block_submitted_answer)
           time.sleep(0.5)
       # we should check this how often?
       try:
           response = requests.get(url_template)
           if response.json()['result']['previousblockhash'] != t['previousblockhash']:
               # we got a new block header
               t = response.json()['result']
               bits = int.from_bytes(uh(t['bits']), byteorder='big', signed=False)
               res = jade.mine(t['version'], uh(t['previousblockhash']), uh(t['target']), t['curtime'], bits, t['height'], address)
           else:
               res = True
       except Exception as e:
            session = requests.Session()
