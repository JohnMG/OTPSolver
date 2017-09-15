#Author: John Massy-Greene
#Program Details: A TOTP Calculator
#Date: 11/09/2017
#Version 1

import time
import base64
import hmac
import hashlib
import binascii
import math


paddedLength = 8
#currentTime = round(time.mktime(time.gmtime()))
currentTime = time.time()
print("This is the time in UTC: "+str(time.gmtime()))
print("This is local system time: "+str(time.time()))
print("This is the epoch seconds: "+str(currentTime))
initialTime = 0
timeStep = 30
digits = 6

sharedKey = '44KKCPXF6WT772ZK'
skBytes = base64.b32decode(sharedKey)
print("Key as hex: "+str(binascii.hexlify(skBytes)))

T = math.floor(currentTime/timeStep)

byteLen = T.bit_length()//8
extra = paddedLength-byteLen

tAsBytes = T.to_bytes((byteLen+extra), byteorder='big')
print(type(tAsBytes))
print("This is T as bytes: "+str(binascii.hexlify(tAsBytes)))
m = hashlib.sha1


hm = hmac.new(skBytes, tAsBytes, hashlib.sha1)
print("Final Hex: "+str(binascii.hexlify(hm.digest())))
hmBytes = hm.digest()
lastByte = hmBytes[19]
mask =  0x0f
offset = lastByte & mask
print(offset)

partCode = hmBytes[offset:offset+4]
print("Part is: "+str(binascii.hexlify(partCode)))
partCode2 = int.from_bytes(partCode, byteorder='big')
finalCode = partCode2 % (10**digits)
print(finalCode)



