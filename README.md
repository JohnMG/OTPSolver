# OTPSolver
The Australian Cyber Security Growth Network had a CTF during September 2017. 
One of the challenges was to find the One Time Pin to login into their network using Time Based One Time Pin algorithm and their base 32 key '44KKCPXF6WT772ZK'.
TOTPCalc.py is the code I used to solve that challenge. I'm putting it up on github for a few reasons:
1. I don't have to redo it sometime in future
2. Get to practice my python
3. There might be some research I could do into the resynchronisation for HOTP counter when the client and server counter don't match and the clients counter is outside of the servers window search range. Based on this section of RFC4226 https://tools.ietf.org/html/rfc4226#section-7.4
