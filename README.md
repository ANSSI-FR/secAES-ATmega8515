# Secure AES128 for ATmega8515

**authors:** Ryad Benadjila, Victor Lomné, Emmanuel Prouff, Thomas Roche

### Introduction

The members of ANSSI's laboratoty of embedded security has developped two versions of AES128 for ATmega-8515 device. The implementation codes are published for research and pedagogical puroposes only.
The ATmega-8515 component is not a secure one; in particular it works with an external clock and
contains no hardware random generator. The information leakage is consequently particularly high and there
is almost no jittering (traces' acquisition should therefore not suffer from too much desynchronisation). To
secure the implementation, it has been chosen to apply state of the art techniques : basic countermeasures
for version 1 and improved countermeasures for version 2.

### The project

The AES128 implementations have been embedded in a minimal OS based on the open source OS SOSSE
(cf. www.mbsks.franken.de/sosse/). The AES128 API can therefore be executed through the iso7816 interface of the card. The list of available APDUs and their basic description are given in the pdf file ``secureAES128_atmega8515.pdf``. For information, a python script is also provided which launches an AES128 encryption et get the
result (cf. ``testingScript/script-AES128-enc.py``) .

The project sources (OS + secure AES128) are provided in two different archives (one for each version,
*low security* or *high security*) : Version1 and Version2. The sources files contain many comments which should clarify
the choices made to secure the algorithms. The (modified/simplified) sources
of SOSSE still contain the original comments.
