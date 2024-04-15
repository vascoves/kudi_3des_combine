import json
import binascii
import secrets
import re
from pyDes import *


#XOR 3DES 2 components
def xorKeys2(a,b):
    
    c1 = int(str(a),16)
    c2 = int(str(b),16)
    result = int(c1) ^ int(c2)
    #print (hex(result))
    key = hex(result)[2:34]
    if len(key) < 32:
        padd = '0' * (32-len(key))
        result_xor = padd + key
    else:
        result_xor = key

    return result_xor.upper()

def xorKeys3(a,b,c):
  c1 = int(str(a),16)
  c2 = int(str(b),16)	
  c3 = int(str(c),16)	
  result=int(c1) ^ int(c2) ^ int(c3)
  key = hex(result)[2:34]
  if len(key) < 32:
    padd = '0' * (32-len(key))
    result_xor = padd + key
  else:
    result_xor = key
  return result_xor.upper()    

def getKCV(skey):
	zeroComp = '00000000000000000000000000000000'
	encryptedKey = encrypt3DES(skey,zeroComp)
	kcv = str(binascii.hexlify(encryptedKey)[0:6])
	return kcv

def encrypt3DES(skey,sdata):
	key = binascii.unhexlify(skey)
	data = binascii.unhexlify(sdata)
	key3DES = triple_des(key, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_NORMAL)
	encryptedData = key3DES.encrypt(data)
	return encryptedData

def lambda_handler(event, context):
	
  print(event)
  data = event["body-json"]
  if "components" not in data:
    raise Exception ("unprocessable entity")
  else:
    components = data = event["body-json"]["components"]
    num_comp = len(components)
    if num_comp not in [2,3]:
      raise Exception ("only accept 2 or 3 components")
    else:
      for comp in components:
        if not re.match(r'^[\dABCDEF]{32}$', comp):
          raise Exception ("Key malformed")
      if num_comp == 2:
        key_comb = xorKeys2(components[0],components[1])
      if num_comp == 3:
        key_comb = xorKeys3(components[0],components[1],components[2])
  key_kcv = getKCV(key_comb).upper()[2:8]
  result = {
    "combined_key" : 
            {
                "value" : key_comb,
                "KCV" : key_kcv
            },
    "components" : components

  }
  return result


#if __name__ == "__main__": lambda_handler("", "")