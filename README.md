# Secure AES128 for ATMega8515

**Authors:** Ryad Benadjila, Victor Lomné, Emmanuel Prouff, Thomas Roche

## Introduction

The members of ANSSI's laboratory of embedded security has developed two versions of AES128 for ATMega8515 device.
The implementation codes are published for research and pedagogical purposes only.

The platform on which the code has been tests is the 
[WB Electronics 64 Kbit ATMega chipcard](http://www.infinityusb.com/default.asp?show=store&ProductGrp=8):
it is made of an ATMega8515 embedded in a smartcard form factor, which represents a realistic SCA attacks
target.

The ATMega8515 component is not a secure one; in particular it works with an external clock and
contains no hardware random generator. The information leakage is consequently particularly high and there
is almost no jittering (traces' acquisition should therefore not suffer from too much desynchronization). To
secure the implementation, it has been chosen to apply state of the art techniques : basic countermeasures
for Version1 and improved countermeasures for Version2.

## The project

The AES128 implementations have been embedded in a minimal OS based on the open source OS SOSSE
(cf. www.mbsks.franken.de/sosse/). The AES128 API can therefore be executed through the ISO-7816 interface of the card
(implemented in software by the SOSSE OS HAL). The list of available APDUs and their basic description are given in 
the pdf file ``secureAES128_atmega8515.pdf``. For information, a python script is also provided which launches 
an AES128 encryption et get the result (cf. ``testingScript/script-AES128-enc.py``) .

The project sources (OS + secure AES128) are provided in two different archives (one for each version,
*low security* or *high security*) : Version1 and Version2. The sources files contain many comments which should clarify
the choices made to secure the algorithms. The (modified/simplified) sources
iof SOSSE still contain the original comments.


## Licenses
SOSSE source codes are released under GPL v2 License. Our specific source codes (for aesv1 and aesv2) are 
released under the BSD License. See the LICENSE file in each source folder for more information. 
