#!/usr/bin/python3
"""
Author: John Massy-Greene
Program Details: Integration tests for OTPSolver. Makes sure
                 program calculates correct values. Majority of
                 tests taken from RFC4226 and RFC6238
Date: 7/3/2018
"""
import subprocess
min = 18
max = -1
s1 = 'python3 otpsolver.py'

# Tests for counter based/hotp below #
print("------------------------------------------------------------")
print("Starting tests for counter based one time pin")
expectedValues1 = ['755224', '287082', '359152', '969429', '338314',
                  '254676', '287922', '162583', '399871', '520489']

key = ' 3132333435363738393031323334353637383930'
keyType = ' key=hex'

for x in range(10):
    strx = str(x)
    inputString = s1+key+" "+strx+keyType
    output = subprocess.check_output(inputString, shell=True).decode("UTF-8")
    value = output[min:max]

    outcome = "HOTP Test "+strx+": "
    if(value == expectedValues1[x]):
        print(outcome+"SUCCESS")
    else:
        print(outcome+"FAIL")

print("------------------------------------------------------------")

# Tests for time based/totp below #
print("------------------------------------------------------------")
print("Starting tests for time based one time pin")
expectedValues2 = ['94287082', '46119246', '90693936', '07081804', '68084774',
                  '25091201', '14050471', '67062674', '99943326', '89005924',
                  '91819424', '93441116', '69279037', '90698825', '38618901',
                  '65353130', '77737706', '47863826']

hashMode = [' hash=sha1', ' hash=sha256', ' hash=sha512']

akey = [' 3132333435363738393031323334353637383930',
        ' 3132333435363738393031323334353637383930313233343536373839303132',
        ' 3132333435363738393031323334353637383930'+
         '3132333435363738393031323334353637383930'+
         '3132333435363738393031323334353637383930'+
         '31323334']

times = [' 1970:01:01:00:00:59', ' 2005:03:18:01:58:29', ' 2005:03:18:01:58:31',
         ' 2009:02:13:23:31:30', ' 2033:05:18:03:33:20', ' 2603:10:11:11:33:20']

timeArg = ' --timebased'
digitNum = ' d=8'
evCounter = 0

for x in range(len(times)):
    for y in range(len(hashMode)):
        strCounter = str(evCounter)
        inputString = s1+akey[y]+times[x]+keyType+timeArg+hashMode[y]+digitNum
        output = subprocess.check_output(inputString, shell=True).decode("UTF-8")
        value = output[min:max]

        outcome = "TOTP Test "+strCounter+": "
        if(value == expectedValues2[evCounter]):
            print(outcome+"SUCCESS")
        else:
            print(outcome+"FAIL")
            print(value)
            print(expectedValues2[evCounter])
            print("------------------------------------------------------------")

        evCounter+=1
        
print("------------------------------------------------------------")

# Tests for mixing of arguments below #
print("------------------------------------------------------------")
print("Mixed Test Type 1: Mixing up the positions of optional arguments")

mixedNum = 0
mixedInputs = []
s2 = s1+akey[0]+times[0]
mixedInputs.append(s2+keyType+timeArg+hashMode[0]+digitNum)
mixedInputs.append(s2+digitNum+hashMode[0]+timeArg+keyType)
mixedInputs.append(s2+hashMode[0]+digitNum+keyType+timeArg)
mixedInputs.append(s2+timeArg+digitNum+keyType+hashMode[0])

for x in range(len(mixedInputs)):
    mixedNum += 1
    output = subprocess.check_output(mixedInputs[x], shell=True).decode("UTF-8")
    value = output[min:max]

    outcome = "Mixed Test "+str(mixedNum)+": "
    if(value == expectedValues2[0]):
        print(outcome+"SUCCESS")
    else:
        print(outcome+"FAIL")



print("\nMixed Test Type 2: Same key different encoding")

aKey = {' 3132333435363738393031323334353637383930':' key=hex',
      ' GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ':' key=base32',
      ' MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=':' key=base64'}
zeroNum = " 0"
for key in aKey.keys():
    mixedNum += 1
    inputs = s1+key+zeroNum+aKey[key]
    output = subprocess.check_output(inputs, shell=True).decode("UTF-8")
    value = output[min:max]

    outcome = "Mixed Test "+str(mixedNum)+": "
    if(value == expectedValues1[0]):
        print(outcome+"SUCCESS")
    else:
        print(outcome+"FAIL")

#Using expectedValues2 since it has 2 leading zeros for the 6 digit pin
print("\nMixed Test Type 3: Same key and time. Different digit length of the pin")
digits = [' d=6', ' d=7', ' d=8']
expectedValues3 = ['005924', '9005924', '89005924']
key = ' 3132333435363738393031323334353637383930'
keyType = ' key=hex'

for x in range(3):
    mixedNum += 1
    inputs = s1+key+times[3]+timeArg+keyType+digits[x]
    output = subprocess.check_output(inputs, shell=True).decode("UTF-8")
    value = output[min:max]

    outcome = "Mixed Test "+str(mixedNum)+": "
    if(value == expectedValues3[x]):
        print(outcome+"SUCCESS")
    else:
        print(outcome+"FAIL")


print("\nMixed Test Type 4: Testing calculation of T by using non zero T0 value")



    
