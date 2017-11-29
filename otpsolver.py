#!/usr/bin/env python
#Author: John Massy-Greene
#Program Details: A TOTP Calculator
#Date: 11/09/2017
#Version 1

import time
import datetime
import calendar
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
#taking out currentTime on the basis that we'll just use counter with TOTP(i.e. time becomes the counter value)
#currentTime = 0
sharedKey = ""
counter = 0
T = 0
verbose = False
totp = False
extraArgs = ["d=", "--timebased", "ts=", "--verbose"]
maxCount = 4294967296

'''
Arguments needed:
- Key (needs to be at least 128 bits or 16 bytes )
- Counter/Time (String -> depending on time based extra parsing required)
Optionals:
- Time based -> Boolean (default = false)
- digits -> integer(6 or 8)
- verbose -> boolean (print out debug stuff) (default = false)
- timestep -> integer (relies on time based being true) (default = 30)
matches = [st for st in e if d in st]

Future arguments required:
- Base32/Base64/HEX
- SHA1/SHA256/SHA512
'''

def handleArgs():
    global verbose
    global totp
    
    argsLen = len(sys.argv)
    args = sys.argv[1:argsLen]
    argsLen -= 1

    
    if(argsLen < 2 or argsLen > 6):
        proper_usage()
        return 0
    if(check_shared_key(args[0]) == 0):
        return 0
    
    if(argsLen >= 3):
        #check to make sure no weird args passed
        checkArgs = args[2:]
        if(check_bad_args(checkArgs) == True):
            return 2
        
        digits = [x for x in args if extraArgs[0] in x]
        if(len(digits) >= 1):
            if(len(digits) > 1):
                return 2
            if(check_digit_args(digits[0])==0):
                return 0
        
        timeBool = [x for x in args if extraArgs[1] in x]
        if(len(timeBool) >= 1):
            if(len(timeBool) == 1):
                totp = True
            else:
                return 2
        
        tsCheck = [x for x in args if extraArgs[2] in x]
        if(len(tsCheck) >= 1):
            if(len(tsCheck) == 1):
                if(check_time_step(tsCheck[0])==0):
                    return 0
            else:
                return 2

        verbCheck = [x for x in args if extraArgs[3] in x]
        if(len(verbCheck) >= 1):
            if(len(verbCheck) == 1):
                verbose = True
            else:
                return 2
        
    if(check_counter(args[1]) == 0):
        return 0

    return 1
        
#NEED EXTRA CHECKING TO MAKE SURE WEIRD INPUT ISN'T GIVEN TO COMMANDS
#This check function is sorta awful
def check_bad_args(argList):
    result = False
    argPatterns = ["d=[0-9]+", "--verbose", "--timebased", "ts=[0-9]+"]
    for x in argList:
        for y in argPatterns:
            matcher = re.compile(y)
            matched = matcher.match(x)
            if(matched):
                break
        else:
            return True
        

    return result

#The shared key must be at least 128 bits and recommended 160 according to RFC4226
#Will not enforce this. But will instead provide warning.
def check_shared_key(key):
    global sharedKey
    sharedKey = key
    try:
        base64.b32decode(sharedKey)
        length = len(sharedKey)*5
        #if(length < 128):
            #print("The key provided is less than 128 bits. This is only a warning. Program continuing.")
    except(binascii.Error, TypeError):
        print("The key provided is either not Base32 or you don't have correct padding")
        return 0
            
def check_digit_args(digit):
    global digits
    digArgP = "^d=([0-9]+)$"
    result = 0
    dmatcher = re.compile(digArgP)
    result = dmatcher.match(digit)

    if(result):
        digit = int(result.group(1))
        if(digit == 6 or digit == 8):
            result = 1
            digits = digit
        else:
            result = 0
    if(result==0):
        print("digits must be 6 or 8")
    return result

def check_time_step(timer):
    global timeStep

    timeP = "^ts=([0-9]{1,3})$"
    result = 0

    tmatcher = re.compile(timeP)
    matching = tmatcher.match(timer)
    if(matching):
        timeStep = int(matching.group(1))
        if(timeStep > 0):
            result = 1
    if(result == 0):
        print("Timestep must be a number between 1 and 99")
    return result


#If regular count then its a value between 0 and 4294967296
#If time based value then its either string "now" or
#or a date time of the form "YYYY:MM:DD:hh:mm:ss:{milliseconds}"
#where milliseconds is optional
def check_counter(count):
    global counter
    global totp
    global currentTime
    result = 1
    intC = 0
    timePattern1 = "^(\d{4}):(\d{2}):(\d{2}):(\d{2}):(\d{2}):(\d{2})(:(\d{3}))?$"
    timePattern2 = "now"

    if(totp == False):
        if(count.isdigit() == False):
            print("Counter must be a non-zero positive integer value")
            result = 0
        else:
            intC = int(count)
            if(intC > maxCount):
                print("Counter must be a value that can fit into 8 bytes")
                result = 0
            elif(intC == 0):
                print("Counter must be a non-zero positive integer value")
                result = 0
            else:
                counter = count

    else:
        matcher = re.compile(timePattern1)
        matches = matcher.match(count)
        if(matches):
            if((handle_custom_time(matches)) == 1):
                result = 1
        elif(count == timePattern2):
            handle_now_time()
            result = 1
        else:
            print_time_error()

    return result
        
#Need to test this function
def handle_custom_time(regmatch):
    global counter
    result = 0
    
    year = regmatch.group(1)
    month = regmatch.group(2)
    day = regmatch.group(3)
    hour = regmatch.group(4)
    minu = regmatch.group(5)
    sec = regmatch.group(6)
    if(regmatch.group(8) != None):
        milli = float(regmatch.group(8))/1000
    else:
        milli = float(0)

    try:
        tup = time.strptime("{} {} {} {} {} {}"
                            .format(year, month, day, hour, minu, sec),
                            "%Y %m %d %H %M %S")
        ctime = float(calendar.timegm(tup))+milli
        counter = ctime
        result = 1
    except ValueError:
        print_time_error()

    return result

def handle_now_time():
    global counter

    theTime = datetime.datetime.utcnow()
    millis = round(float(theTime.microsecond)/1000)/1000
    theTime = str(theTime)
    tup = time.strptime(theTime, "%Y-%m-%d %H:%M:%S.%f")
    ctime = round(float(calendar.timegm(tup)),3)
    ctime += millis
    counter = ctime
    

def print_time_error():
    print("time must be either be the string \"now\" or of the forms:")
    print("- YYYY:MM:DD:hh:mm:ss")
    print("- YYYY:MM:DD:hh:mm:ss:xxx")
    print("- where hh is 24 hour time and xxx is milliseconds")
        
        
def proper_usage():
    print("Usage: otpsolver.py [key] [[counter] or [time]] [d=digits]")
    print("                    [--timebased] [ts=timestep] [--verbose]\n")
    print("Arguments:")
    print("key         => A base32 secret key")
    print("counter     => a integer value that can fit into 8 bytes. Can use this OR time")
    print("time        => use the word 'now' to use the current system time or use a time"+
                          "in the form of dd:mm:yy hh:mm:ss"+
                          "must be paired the option --timebased")
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
    print("This is counter: "+str(repr(counter)))
    #print("This is the time: "+str(currentTime))
    print(str(time.time()))
    if(proceed == 0):
        sys.exit()
    #elif(proceed == 2):
    #    proper_usage()

if __name__ == "__main__":
    main()
