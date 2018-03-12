# OTPSolver
The Australian Cyber Security Growth Network had a CTF during September 2017. 
One of the challenges was to find the One Time Pin(OTP) to login into their network using a Time-Based OTP algorithm and their base32 key '44KKCPXF6WT772ZK'.

In this repository you will find the following files:
* TOTPCalc.py - The code I used to solve the challenge.
* otpsolver.py - An extension of TOTPCalc that calculates One Time Pins based on a number of variables and was made
                 in accordance with RFC4226 and RFC6238. These RFC's specify that a One Time Pin is made with
                 the following factors: * A secret key
                                        * An integer counter based variable if using HMAC-based OTP(HOTP) or a time variable if using Time-based OTP(TOTP) 
* OTPTests.py - A script for automatic testing of otpsolver. Was quite helpful in finding bugs and errors.


3. There might be some research I could do into the resynchronisation for HOTP counter when the client and server counter don't match and the clients counter is outside of the servers window search range. Based on this section of RFC4226 https://tools.ietf.org/html/rfc4226#section-7.4
