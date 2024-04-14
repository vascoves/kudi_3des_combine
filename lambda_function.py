import json
import binascii
import secrets
from pyDes import *


#XOR 3DES 2 components
def xorKeys3DES(a,b):

    length = 32
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
    data = event["'body-json"]
    if "components" in data:
      return {
        'statusCode': 422,
        'headers': {'Content-Type': 'application/json'},                
        'body': 'Missing parameters'
      }
	
    '''

    comp_list = []
    comp1 = generateRandomKey(128)
    c1 = int(comp1,16)
    #print(getKCV(comp1).upper()[2:8])
    data_c1 = {
		"number" : 1,
		"value" : comp1.upper(),
		"KCV" : getKCV(comp1).upper()[2:8]
    }
    comp_list.append(data_c1)   
	
    comp2 = generateRandomKey(128)
    c2 = int(comp2,16)
    #print(getKCV(comp2).upper()[2:8])
    
    data_c2 = {
		"number" : 2,
		"value" : comp2.upper(),
		"KCV" : getKCV(comp2).upper()[2:8]
    }    
	
    comp_list.append(data_c2)   
    comp3 = generateRandomKey(128)
    c3 = int(comp3,16)	
    #print(getKCV(comp3).upper()[2:8])	
    
    data_c3 = {
		"number" : 3,
		"value" : comp3.upper(),
		"KCV" : 
    }      
    comp_list.append(data_c3)   
	

    getKCV(comp3).upper()[2:8]

    resultKey = xorKeys3(c1,c2,c3)
    #print(resultKey.upper())
    data["masterKey"] = resultKey.upper()
    #print(getKCV(resultKey).upper()[2:8])
    data["KCV"] = getKCV(resultKey).upper()[2:8]
    data["type"] = "3DES"
    data["componets"] = comp_list	

	
    response = {
      "combined_key" : 
	            {
                  "value" : 
                  "KCV" :
              },
			"components" :

    }
	  '''
    return data


#if __name__ == "__main__": lambda_handler("", "")