#!/usr/bin/python3

#Author: John Massy-Greene
#Program Details: A TOTP Calculator
#Date: 11/09/2017
#Update: 6/3/2018
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
sharedKey = ""
counter = 0
verbose = False
totp = False
extraArgs = ["d=","--timebased", "ts=", "--verbose", "T0=", "hash=", "key="]
#maxCount should not be 4294967296. This is maximum value of 4 bytes signed
#changed maxCount to (2**63)-1 which is the maximum value of 8 bytes signed
#Later on in the program the sign gets masked out anway
maxCount = ((2**63)-1)
hashAlgorithm = hashlib.sha1
#keyEncoding will be a string that tells the program to decode the key
#based on whether it is hexademical, base32 or base64. Default is base32
keyEncoding = "base32"
verboseInfo = ["----- Algorithm Variables -----\n"]


'''
TO DO:
Still need to implement the verbose 
'''
#The return codes are as follows:
# 0 = Arguments handled successfully
# 1 = Arguments given are not correct
def handleArgs():
    global verbose
    global totp

    minArgs = 2
    maxArgs = 9
    
    argsLen = len(sys.argv)
    args = sys.argv[1:argsLen]
    argsLen -= 1

    
    if(argsLen < minArgs or argsLen > maxArgs):
        return 1
    
    if(argsLen >= 3):
        #check to make sure no weird args passed
        checkArgs = args[2:]
        if(check_bad_args(checkArgs) == True):
            return 1
        
        digits = [x for x in args if extraArgs[0] in x]
        if(len(digits) >= 1):
            if(len(digits) > 1):
                return 1
            if(check_digit_args(digits[0])==0):
                return 1
        
        timeBool = [x for x in args if extraArgs[1] in x]
        if(len(timeBool) >= 1):
            if(len(timeBool) == 1):
                totp = True
            else:
                return 1
            
        initTimeCheck = [x for x in args if extraArgs[4] in x]
        if(len(initTimeCheck) >= 1):
            if(len(initTimeCheck) > 1):
                return 1
            if(check_initial_time(initTimeCheck[0]) == 0):
                return 1
        
        tsCheck = [x for x in args if extraArgs[2] in x]
        if(len(tsCheck) >= 1):
            if(len(tsCheck) == 1):
                if(check_time_step(tsCheck[0])==0):
                    return 1
            else:
                return 1

        verbCheck = [x for x in args if extraArgs[3] in x]
        if(len(verbCheck) >= 1):
            if(len(verbCheck) == 1):
                verbose = True
            else:
                return 1

        hashCheck = [x for x in args if extraArgs[5] in x]
        if(len(hashCheck) >= 1):
            if(len(hashCheck) == 1):
                if(check_hashing(hashCheck[0]) == 0):
                    return 1
            else:
                return 1

        keyCheck = [x for x in args if extraArgs[6] in x]
        if(len(keyCheck) >= 1):
            if(len(keyCheck) == 1):
                if(check_key_type(keyCheck[0]) == 0):
                    return 1
            else:
                return 1
#check for initial time after checking for timebool but before the counter
#add code to handle the case that initial time comes before the counter
    if(check_shared_key(args[0]) == 0):
        return 1

    if(check_counter(args[1]) == 0):
        return 1

    return 0
        
#NEED EXTRA CHECKING TO MAKE SURE WEIRD INPUT ISN'T GIVEN TO COMMANDS
#This check function is sorta awful
def check_bad_args(argList):
    result = False
    argPatterns = ["d=[0-9]+",
                   "T0=\d{4}:\d{2}:\d{2}:\d{2}:\d{2}:\d{2}(:\d{3})?",
                   "T0=now","--verbose", "--timebased", "ts=[0-9]+",
                   "^hash=(sha1|sha256|sha512)$",
                   "^key=(hex|base32|base64)$"]
    for x in argList:
        for y in argPatterns:
            matcher = re.compile(y)
            matched = matcher.match(x)
            if(matched):
                break
        else:
            return True
        
    return result

def check_key_type(keyType):
    global keyEncoding
    result = 0
    keyPattern =  "^key=(hex|base32|base64)$"

    kMatcher = re.compile(keyPattern)
    matching = kMatcher.match(keyType)
    if(matching):
        keyEncoding = matching.group(1)
        result = 1

    return result

#The shared key must be at least 128 bits and recommended 160 according to RFC4226
#Will not enforce this. But will instead provide warning.
def check_shared_key(key):
    global sharedKey
    global keyEncoding
    types = ["hex", "base32", "base64"]
    result = 1

    sharedKey = key

    if(keyEncoding == types[0]):
        try:
            binascii.unhexlify(sharedKey)
        except(binascii.Error, TypeError):
            print("The key provided is either not in hexadecimal format")
            print("or you don't have correct padding")
            result = 0
    elif(keyEncoding == types[1]): 
        try:
            base64.b32decode(sharedKey)
        except(binascii.Error, TypeError):
            print("The key provided is either not Base32")
            print("or you don't have correct padding")
            result = 0
    elif(keyEncoding == types[2]):
        try:
            base64.b64decode(sharedKey)
        except(binascii.Error, TypeError):
            print("The key provided is either not Base64")
            print("or you don't have correct padding")
            result = 0

    return result
            
def check_digit_args(digit):
    global digits
    digArgP = "^d=([0-9]+)$"
    result = 0
    dmatcher = re.compile(digArgP)
    matches = dmatcher.match(digit)

    if(matches):
        digit = int(matches.group(1))
        if(digit >= 6 and digit <= 8):
            result = 1
            digits = digit
            
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

def check_hashing(hashType):
    global hashAlgorithm
    result = 0
    hashPattern = "^hash=(sha1|sha256|sha512)$"
    hashes = ["sha1","sha256","sha512"]

    hMatcher = re.compile(hashPattern)
    matching = hMatcher.match(hashType)
    if(matching):
        shaType = matching.group(1)
        if(shaType == hashes[0]):
            hashAlgorithm = hashlib.sha1
            result = 1
        elif(shaType == hashes[1]):
            hashAlgorithm = hashlib.sha256
            result = 1 
        elif(shaType == hashes[2]):
            hashAlgorithm = hashlib.sha512
            result = 1
    else:
        print("The hash algorithm must be either sha1, sha256 or sha512")

    return result

def check_counter(count):
    global counter
    global totp
    global currentTime
    global initialTime
    result = 0
    intC = 0

    if(totp == False):
        if(count.isdigit() == False):
            print("Counter must be an integer value >= 0")
        else:
            intC = int(count)
            if(intC > maxCount):
                print("Counter must be a value that can fit into 8 bytes")
            elif(intC < 0):
                print("Counter must be an integer value >= 0")
            else:
                counter = int(count)
                result = 1 

    else:
        timeResult = general_time_check(count)
        if(timeResult != -1):
            counter = timeResult
            result = 1
        if(counter < initialTime):
            print("Current Time must be greater than or equal to T0")
            result = 0

    return result

def check_initial_time(aTime):
    global initialTime
    global totp
    result = 0
    if(totp != False):
        aTime = aTime[3:]
        timeResult = general_time_check(aTime)
        if(timeResult != -1):
            initialTime = timeResult
            result = 1
    else:
        print("T0 is only suitable for time-based OTP")

    return result


#If regular count then its a value between 0 and 4294967296
#If time based value then its either string "now" or
#or a date time of the form "YYYY:MM:DD:hh:mm:ss:{milliseconds}"
#where milliseconds is optional
def general_time_check(aTime):
    
    result = -1
    timePattern1 = "^(\d{4}):(\d{2}):(\d{2}):(\d{2}):(\d{2}):(\d{2})(:(\d{3}))?$"
    timePattern2 = "now"

    matcher = re.compile(timePattern1)
    matches = matcher.match(aTime)
    if(matches):
        timeHandled = handle_custom_time(matches)
        if(timeHandled != -1):
            result = timeHandled
    elif(aTime == timePattern2):
        result = time.time()
    else:
        print_time_error()


    return result


#Found after some testing this function handles dates past the time
#07/02/2016 06:28:16
# result will be -1 when the time is not correct as all correct times
# in Unix epoch are >= 0
def handle_custom_time(regmatch):
    result = -1
    
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
        result = ctime
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
    print("                    [--timebased] [ts=timestep] [--verbose]")
    print("                    [T0=time] [hash=sha1|sha256|sha512]")
    print("                    [key=hex|base32|base64]\n")
    print("Arguments:")
    print("key         => A base32, base64 or hexademical secret key")
    print("counter     => a integer value that can fit into 8 bytes. Can use this OR time")
    print("time        => use the word 'now' to use the current system time or use a time")
    print("               in the form of yy:mm:dd:hh:mm:ss (milliseconds optional)")
    print("               must be paired the option --timebased")
    print("--timebased => use this if you want TOTP instead of HOTP\n")
    print("----------Optional Arguments Below----------------------------------")
    print("timestep    => a value expressed in seconds that you want the TOTP to use as the window of"+
                          "how often the code changes")
    print("digits      => Specify the digits for the OTP. 6 ~ 8")
    print("--verbose   => use this to print debugging messages")
    print("T0          => The starting time used in TOTP. See time for usage details")
    print("hash        => what hashing algorithm you would like used. Default is sha1")
    print("key         => what encoding the key is supposed to use. Default is base32")

'''
Note to self: this function is here so that in future
you can test whether the key given is base64, base32 or hex
For the moment it only converts base32 keys to bytes
'''
def key_to_bytes(key):
    global keyEncoding
    types = ["hex","base32","base64"]
    result = 0

    if(keyEncoding == types[0]):
        result = binascii.unhexlify(key)
    elif(keyEncoding == types[1]):
        result = base64.b32decode(key)
    elif(keyEncoding == types[2]):
        result = base64.b64decode(key)
        
    return result

def totp_algorithm(key, count):
    global initialTime
    global timeStep
    global verbose
    global verboseInfo

    T = math.floor((count-initialTime)/timeStep)
    if(verbose):
        verboseInfo.append("This is T=((T1 - T0)/timestep): "+str(T))
        
    result = hotp_algorithm(key, T)
    return result


def hotp_algorithm(key, count):
    global digits
    global hashAlgorithm
    global verbose
    global verboseInfo
    
    mask1 = 0x0f
    mask2 = 0x7fffffff
    hashAlg = hashAlgorithm
    
    byteKey = key_to_bytes(key)
    byteCounter = count.to_bytes(8, byteorder='big', signed=False)

    hmacsha = hmac.new(byteKey, byteCounter, hashAlg)
    HS = hmacsha.digest()
    HSlen = len(HS)-1
    
    offset = HS[HSlen]&mask1
    fullCode = HS[offset:offset+4]
    fullCodeNum = int.from_bytes(fullCode, byteorder='big', signed=False)
    fullCodeNum = fullCodeNum&mask2

    finalCode = fullCodeNum % (10**digits)
    finalCodeString = str(finalCode)
    while(len(finalCodeString) < digits):
        finalCodeString = "0" + finalCodeString
    finalCode = finalCodeString
        
        
    if(verbose):
        verboseInfo.append("hmac(key, counter) in hex: "+HS.hex())
        verboseInfo.append("full pin in hex: "+fullCode.hex())
        verboseInfo.append("full pin in integer format: "+str(fullCodeNum))

    return finalCode
    
    

def main_calculation():
    global totp
    global sharedKey
    global counter
    global verbose
    result = 0

        
    if(totp):
        result = totp_algorithm(sharedKey, counter)
    else:
        result = hotp_algorithm(sharedKey, counter)

    return result

def collect_general_information():
    global totp
    global keyEncoding
    global sharedKey
    global counter
    global hashAlgorithm
    global digits
    global timeStep
    global initialTime
    global verboseInfo

    infoString = "OTP Algorithm Type: "
    if(totp):
        infoString = infoString+"time-based"
    else:
        infoString = infoString+"counter"

    verboseInfo.append(infoString)
    verboseInfo.append("Key Encoding: "+keyEncoding)
    verboseInfo.append("Key: "+sharedKey)
    verboseInfo.append("Counter Value: "+str(counter))

    hashAlgMap = {hashlib.sha1:"sha1", hashlib.sha256:"sha256",hashlib.sha512:"sha512"}
    verboseInfo.append("Hashing Algorithm: "+hashAlgMap[hashAlgorithm])
    verboseInfo.append("Digits in Pin: "+str(digits))

    if(totp):
        verboseInfo.append("Time Step: "+str(timeStep))
        verboseInfo.append("T0 as counter value: "+str(initialTime))

    verboseInfo.append("\n------- Algorithm Calculations Below ------\n")
    
    return
    
def print_verbose_information():
    global verboseInfo
    
    for x in range(len(verboseInfo)):
        print(verboseInfo[x])
    print("\n--------Verbose Information Finished-----------")

def main():
    global verbose
    proceed = handleArgs()
    result  = 0

    if(proceed == 1):
        proper_usage()
        sys.exit()
    else:
        if(verbose):
            collect_general_information()
        result = main_calculation()

        if(verbose):
            print_verbose_information()
        print("This is the code: "+result)

if __name__ == "__main__":
    main()
