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


digits = 6
timeStep = 30
#initialTime = T0
initialTime = 0
#taking out currentTime on the basis that we'll just use counter with TOTP(i.e. time becomes the counter value)
#currentTime = 0
sharedKey = ""
counter = 0
verbose = False
totp = False
extraArgs = ["d=", "--timebased", "ts=", "--verbose"]
#maxCount should not be 4294967296. This is maximum value of 4 bytes signed
#changed maxCount to (2**63)-1 which is the maximum value of 8 bytes signed
#Later on in the program the sign gets masked out anway
maxCount = ((2**63)-1)

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
- initialTime or T0 as RFC4226 calls it
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
            counter = time.time()
            result = 1
        else:
            print_time_error()

    return result
        
#Need to test this function
#Found after some testing this function handles dates past the time
#07/02/2016 06:28:16
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
    print("time        => use the word 'now' to use the current system time or use a time")
    print("               in the form of yy:mm:dd:hh:mm:ss (milliseconds optional)")
    print("               must be paired the option --timebased")
    print("digits      => Specify the digits for the OTP. 6 ~ 8")
    print("--timebased => use this if you want TOTP instead of HOTP")
    print("timestep    => a value expressed in seconds that you want the TOTP to use as the window of"+
                          "how often the code changes")
    print("--verbose   => use this to print debugging messages")

'''
Note to self: this function is here so that in future
you can test whether the key given is base64, base32 or hex
For the moment it only converts base32 keys to bytes
'''
def key_to_bytes(key):
    result = 0
    result = base64.b32decode(key)
    return key

def totp_algorithm(count, key):
    global initialTime
    global timeStep

    T = math.floor((count-initialTime)/timeStep)
    result = hotp_algorithm(T, key)
    return result


def hotp_algorithm(count, key):
    global digits
    mask1 = 0x0f
    mask2 = 0x7fffffff
    hashAlg = hashlib.sha1()
    
    byteKey = key_to_bytes(key)
    byteCounter = count.to_bytes(8, byteorder='big', signed=False)

    hmacsha1 = hmac.new(byteKey, byteCounter, hashAlg)
    HS = hmacsha1.digest()
    offset = HS[19]&mask1
    fullCode = HS[offset:offset+4]
    fullCode = fullCode&mask2

    finalCode = fullCode % (10**digits)
    return finalCode
    
    

def main_calculation():
    global totp
    global sharedKey
    global counter
    result = 0
    
    if(totp):
        result = totp_algorithm(sharedKey, counter)
    else
        result = hotp_algorithm(sharedKey, counter)

    return 0



def main():
    proceed = handleArgs()
    result  = 0
    '''print("This is digits: "+str(digits))
    print("This is verbose: "+str(verbose))
    print("This is timestep: "+str(timeStep))
    print("This is timebased: "+str(totp))
    print("This is key: "+sharedKey)
    print("This is counter: "+str(repr(counter)))
    #print("This is the time: "+str(currentTime))
    print(repr(time.time()))'''
    if(proceed == 0):
        sys.exit()
    elif(proceed == 1):
        result = main_calculation()
    elif(proceed == 2):
        proper_usage()

    if(result!=0):
        print("This is the code: "+result)

if __name__ == "__main__":
    main()
