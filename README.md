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

### Quick Start

The AES128 implementations have been embedded in a minimal OS based on the open source OS SOSSE
(cf. www.mbsks.franken.de/sosse/). The AES128 API can therefore be executed through the ISO-7816 interface of the card
(implemented in software by the SOSSE OS HAL). The list of available APDUs and their basic description are given in 
the pdf file ``secureAES128_atmega8515.pdf``. For information, a python script is also provided which launches 
an AES128 encryption et get the result (cf. ``testingScript/script-AES128-enc.py``) .

The project sources (OS + secure AES128) are provided in two different archives (one for each version,
*low security* or *high security*) : Version1 and Version2. The sources files contain many comments which should clarify
the choices made to secure the algorithms. The (modified/simplified) sources
iof SOSSE still contain the original comments.

### Cautionary Notes 

For efficiency reasons, the assembly code of AES Version1 assumes that the global variable ``maskedSbox`` has an address correctly aligned on 
a memory block of 256 bytes.

Unfortunately, with the tested **avr-gcc** version 5.4.0, the ``__attribute__((aligned(256)))`` does not
optimize the variables placement in SRAM resulting in a possible overflow (due to the very constrained 544 bytes of SRAM in the
ATMega8515).

This inclined us to force this alignment using a zero padding through a crafted global variable declared before maskedSbox:
the addresses and the proper alignment can be checked using **avr-objdump** on the produced ELF binary. If you use
versions of **avr-gcc** different from 5.4.0, please check and adapt this zero padding.

### Using the internal trigger

In order to make acquisitions easier, we have implemented a trigger on the ISO7816-2 pin
C4 (see the figure below). This pin is unused by the ISO7816-3 layer, and since it is connected to an internal
pin of the ATMega8515, we can use it without perturbing the APDU communication with a reader.

The pin C4 is set high before executing the AES, and set low after its execution. You can play around with the
``trig_high()`` and ``trig_low()`` functions calls inside the AES (it is safe to call them from C and assembly).

```
      -------------+------------- 
     |   C1        |         C5  | 
     |             |             | 
     +-------\     |     /-------+ 
     |   C2   +----+    +    C6  | 
     |        |         |        | 
     +--------|         |--------+ 
     |   C3   |         |    C7  | 
     |        +----+----+        | 
     +-------/     |     \-------+ 
     |   C4=TRIG   |         C8  | 
     |             |             | 
      -------------+------------- 
```

You can activate the trigger when compiling the source code using the ``WITH_AES_TRIG`` toggle:

```
$ CFLAGS="-DWITH_AES_TRIG" make
```

## Licenses
SOSSE source codes are released under GPL v2 License. Our specific source codes (for aesv1 and aesv2) are 
released under the BSD License. See the LICENSE file in each source folder for more information. 
