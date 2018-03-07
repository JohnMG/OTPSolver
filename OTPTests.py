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
# ---------------- Tests for Counter Based ------------------------ #
print("------------------------------------------------------------")
print("Starting tests for counter based one time pin")
expectedValues = ['755224', '287082', '359152', '969429', '338314',
                  '254676', '287922', '162583', '399871', '520489']

key = ' 3132333435363738393031323334353637383930'
keyType = ' key=hex'

for x in range(10):
    strx = str(x)
    inputString = s1+key+" "+strx+keyType
    output = subprocess.check_output(inputString, shell=True).decode("UTF-8")
    value = output[min:max]

    outcome = "HOTP Test "+strx+": "
    if(value == expectedValues[x]):
        print(outcome+"SUCCESS")
    else:
        print(outcome+"FAIL")

print("------------------------------------------------------------")
print("------------------------------------------------------------")
print("Starting tests for time based one time pin")
