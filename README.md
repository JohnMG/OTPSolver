# OTPSolver

## Background
The Australian Cyber Security Growth Network had a CTF during September 2017. 
One of the challenges was to find the One Time Pin(OTP) to login into their network using a Time-Based OTP algorithm and their base32 key '44KKCPXF6WT772ZK'.

In this repository you will find the following files:
* TOTPCalc.py: The code I used to solve the challenge.
* otpsolver.py: An extension of TOTPCalc that calculates One Time Pins based on a number of variables and was made in accordance with RFC4226 and RFC6238. These RFC's specify that a One Time Pin is made with the following factors: 
  * A secret key
  * An integer counter based variable if using HMAC-based OTP(HOTP) or a time variable if using Time-based OTP(TOTP) 
* OTPTests.py - A script for automatic testing of otpsolver. Was quite helpful in finding bugs and errors.

## How To Use otpsolver.py
Basic usage of the program can be determined by calling it with no arguments. Calling it with no arguments will result in output similiar to a unix man page that gives the arguments it will require. Also to note that the program requires python 3.X in order to function correctly.

### To calculate a basic HMAC-based OTP
otpsolver.py key counter
* key: This is the secret key which should be encoded in base32 format
* counter: An integer that has a value of 0 <= x <= 2^63-1 (maximum bit value of 8 bytes signed)

### To calculate a basic Time-based OTP
otpsolver.py key counter --timebased
* key: This is the secret key which should be encoded in base32 format
* counter: This argument can have one of two styles:
  * "now" - A string that tells the program you want to use the current unix epoch
  * "yy:mm:dd:hh:mm:ss:xxxx" - a string that specifies: the year, month, day, hour, minute, seconds and milliseconds. It should be noted that milliseconds are optional.
* --timebased: An argument that explicitly tells the program you want to use the TOTP algorithm. MUST be used if wanting to use timebased authentication as the program defaults to HOTP.

### Optional arugments
* --timebased - Tells the program you want to use TOTP algorithm. When using this the counter must be the appropriate value.
* d=X - This specifies how many digits should be in your one time pin. The values of x are: 6 <= x <= 8
* hash=X - This specifies the hashing algorithm you want to use in the calculation of the OTP. X can have the following values: sha1,sha256 or sha512
* key=X - What encoding the secret key is in. X can have the following values: hex,base32 or base64
* ts=X - The timestep used in the TOTP algorithm. Values of x are: 0 <= x <= 2^63-1 
* T0=time - The initial time used in TOTP algorithm. The value of time must be of the same format as the counter
* --verbose - This gives the additional information that shows the values that was used to calculate the OTP

## Default Arguments
* d=6
* hash=sha1
* T0=0 - 0 being the epoch value
* ts=30
* key=base32




## Notes and Addenum
1. This code can be used to calculate one time pins but should by no means used as the basis for an authenticator or used to secure  any applications. I cannot guarantee your communications or applications will be secure.

2. There might be some research I could do into the resynchronisation for HOTP counter when the client and server counter don't match and the clients counter is outside of the servers window search range. Based on this section of RFC4226 https://tools.ietf.org/html/rfc4226#section-7.4
