#!/usr/bin/env python
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
import sys
import re

paddedLength = 8
digits = 6
timeStep = 30
initialTime = 0
currentTime = 0
sharedKey = ""
counter = 0
T = 0
verbose = False
totp = False
extraArgs = ["d=", "--timebased", "ts=", "--verbose"]
maxCount = 4294967296

'''
Arguments needed:
- Key
- Counter/Time (String -> depending on time based extra parsing required)
Optionals:
- Time based -> Boolean (default = false)
- digits -> integer(6 or 8)
- verbose -> boolean (print out debug stuff) (default = false)
- timestep -> integer (relies on time based being true) (default = 30)
matches = [st for st in e if d in st]
'''

def handleArgs():
    argsLen = len(sys.argv)
    args = sys.argv[1:argsLen]
    argsLen -= 1
    print(argsLen)
    
    if(argsLen < 2 or argsLen > 6):
        proper_usage()
        return 0
    if(check_shared_key(args[0]) == 0):
        return 0
    
    if(argsLen >= 3):
        digits = [x for x in args if extraArgs[0] in x]
        if(len(digits) == 1):
            if(check_digit_args(digits[0])==0):
                return 0
        else:
            return 2
        
        timeBool = [x for x in args if extraArgs[1] in x]
        if(len(timeBool) == 1):
            totp = True
        else:
            return 2
        
        tsCheck = [x for x in args if extraArgs[2] in x]
        if(len(tsCheck) == 1):
            if(check_time_step(ts_check[0])==0):
               return 0
        else:
            return 2

        verbCheck = [x for x in args if extraArgs[3] in x]
        if(len(verbCheck) == 1):
            verbose = True
        else:
            return 2
        
    if(check_counter(args[1]) == 0):
        return 0

    return 1
        
#NEED EXTRA CHECKING TO MAKE SURE WEIRD INPUT ISN'T GIVEN TO COMMANDS
               
            
def check_shared_key(key):
    sharedKey = key
    try:
        base64.b32decode(sharedKey)
    except binascii.Error:
        print("The key provided is not base32. Program exiting\n")
        return 0
            
def check_digit_args(digit):
    digArgP = "^d=([0-9])$"
    result = 0
    dmatcher = re.compile(digArgP)
    result = dmatcher.match(digit)
    if(result):
        digits = int(result.group(1))
        if(digits == 6 or digits == 8):
            result = 1
    if(result==0):
        print("digits must be 6 or 8")
    return result

def check_time_step(time):
    timeP = "^ts=([0-9]{2-3})$"
    result = 0
    
    tmatcher = re.compile(timeP)
    matching = tmatcher.match(time)
    if(matching):
        ts = int(result.group(1))
        if(ts > 0):
            result = 1
    if(result == 0):
        print("Timestep must be a number between 1 and 99")
    return result


#If regular count then its a value between 0 and 4294967296
#If time based value then its either string "now" or
#or a date time of the form "YYYY:MM:DD hh:mm:ss"
def check_counter(counter):
    result = 0
    intC = 0
    timePattern1 = "^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})(:(\d{3}))?$"
    timePattern2 = "now"

    if(totp == False):
        if(counter.isdigit() == False):
            print("Counter must be an integer value")
        intC = int(counter)
        if(intC > maxCount):
            print("Counter must be a value that can fit into 8 bytes")
        result = 1

    else:
        matcher = re.compile(timePattern1)
        matches = matcher.match(counter)
        if(matches):
            if((handle_custom_time(counter, matches)) == 1):
                result = 1
        elif(counter == timePattern2):
            currentTime = time.time()
            result = 1
        else:
            print("time must be either be the string \"now\" or of the forms:")
            print("- YYYY:MM:DD hh:mm:ss")
            print("- YYYY:MM:DD hh:mm:ss:xxx")
            print("- where hh is 24 hour time and xxx is milliseconds")

    return result
        
#Need to test this function
def handle_custom_time(time, regmatch):
    result = 0
    
    year = regmatch.group(1)
    month = regmatch.group(2)
    day = regmatch.group(3)
    hour = regmatch.group(4)
    minu = regmatch.group(5)
    sec = regmatch.group(6)
    if(regmatch.group(8) != None):
        milli = str(int(regmatch.group(8))/1000)
    else:
        milli = 0

    try:
        tup = time.strptime("{} {} {} {} {} {}"
                            .format(year, month, day, hour, minu, sec),
                            "%Y %m %d %H %M %S")
        ctime = time.mktime(tup)
        currentTime = ctime+milli
        result = 1
    except ValueError:
        pass

    return result
        
        
def proper_usage():
    print("Usage: otpsolver.py [key] [[counter] or [time]] [d=digits]")
    print("                    [--timebased] [ts=timestep] [--verbose]\n")
    print("Arguments:")
    print("key         => A base32 secret key")
    print("counter     => a integer value that can fit into 8 bytes. Can use this OR time")
    print("time        => use the word 'now' to use the current system time or use a time"+
                          "in the form of dd:mm:yy hh:mm:ss")
    print("digits      => Specify the digits for the OTP. 6 ~ 8")
    print("--timebased => use this if you want TOTP instead of HOTP")
    print("timestep    => a value expressed in seconds that you want the TOTP to use as the window of"+
                          "how often the code changes")
    print("--verbose   => use this to print debugging messages")
        
''''
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
'''

def main():
    proceed = handleArgs()
    print("This is digits: "+str(digits))
    print("This is verbose: "+str(verbose))
    print("This is timestep: "+str(timeStep))
    print("This is timebased: "+str(totp))
    print("This is key: "+sharedKey)
    if(proceed == 0):
        sys.exit()
    elif(proceed == 2):
        proper_usage()

if __name__ == "__main__":
    main()
