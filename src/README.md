#Compilation 
Run ``make`` (you must have avr-gcc installed on your PC). This will create ``aesv1-<DDMMYY>-<HHMMSS>.hex``, ``aesv2-<DDMMYY>-<HHMMSS>.hex`` and ``eedata.hex`` in the folder build. It is also possible to only compile ``aesv1`` or ``aesv2`` by specifying the appropriate target when executing ``make``. Note that ``aesv1`` and ``aesv2`` respectively correspond to the two versions described in the ``secureAES128_atmega8515.pdf`` document. You can also clean everything by using the ``clean`` target.

#Loading in the ATMega8515 card
Load the files ``eedata.hex`` (in EEPROM int.) and ``aesv1-<DDMMYY>-<HHMMSS>.hex`` or ``aesv2-<DDMMYY>-<HHMMSS>.hex`` (in FLASH) in the ATMega8515 component. You can for instance use the **Infinity USB Unlimited** Reader and IDE from wb\_electronics for this step.

#Licenses
SOSSE source codes are released under GPL v2 License. Our specific source codes (for aesv1 and aesv2) are released under the BSD License. See the LICENSE file in each source folder for more information. 


