#!/usr/bin/python

"""
This script shows how to communicate with the Masked AES on ATMega8515 smartcard chip.

"""



####################################################################################################
####################################################################################################
####################################################################################################
# import some libraries

from smartcard.System import readers
from smartcard.ATR import ATR
from smartcard.util import BinStringToHexList, HexListToBinString, toHexString, toBytes
from Crypto.Cipher import AES
from random import randint
import sys

####################################################################################################
####################################################################################################
####################################################################################################
# APDU commands for AES

### APDU command to Read/Write EEPROM
l_APDUSOSSEReadEEPROM  = [0x80, 0x04]
l_APDUSOSSEWriteEEPROM = [0x80, 0x02]

### APDU command to Set/Get AES Key
l_APDUSOSSESetKey = [0x80, 0x10]
l_APDUSOSSEGetKey = [0x80, 0x12]

### APDU command to Set/Get AES Input
l_APDUSOSSESetInput = [0x80, 0x20]
l_APDUSOSSEGetInput = [0x80, 0x22]

### APDU command to Set/Get AES Mask
l_APDUSOSSESetMask = [0x80, 0x30]
l_APDUSOSSEGetMask = [0x80, 0x32]

### APDU command to Get AES Ouput
l_APDUSOSSEGetOutput = [0x80, 0x42]

### APDU command to launch AES encryption
l_APDUSOSSEAESEnc = [0x80, 0x52]


def run_aes(l_secretKey,l_input,l_mask):

	lengthKey  = len(l_secretKey)
	lengthInput= len(l_input)
	lengthMask = len(l_mask)

	##################################################
	# send Write Command
	print "Set Key"
	
	# build complete Read APDU
	l_APDUSOSSESetKey_complete = []
	l_APDUSOSSESetKey_complete += l_APDUSOSSESetKey 
	# unused P1
	l_APDUSOSSESetKey_complete.append(0)
	# unused P2
	l_APDUSOSSESetKey_complete.append(0)
	# key length
	l_APDUSOSSESetKey_complete.append(lengthKey)
	# key value
	l_APDUSOSSESetKey_complete += l_secretKey
	 
	# send Write APDU
	print "send APDU: %s" % toHexString(l_APDUSOSSESetKey_complete)
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSESetKey_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Read Command
	print "Read Key"
	
	# build complete Read APDU
	l_APDUSOSSEGetKey_complete = []
	l_APDUSOSSEGetKey_complete += l_APDUSOSSEGetKey 
	# unused P1
	l_APDUSOSSEGetKey_complete.append(0)
	# unused P2
	l_APDUSOSSEGetKey_complete.append(0)
	# key length
	l_APDUSOSSEGetKey_complete.append(lengthKey)
	
	# send Read APDU
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSEGetKey_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Write Command
	print "Set Input"
	
	# build complete Read APDU
	l_APDUSOSSESetInput_complete = []
	l_APDUSOSSESetInput_complete += l_APDUSOSSESetInput 
	# unused P1
	l_APDUSOSSESetInput_complete.append(0)
	# unused P2
	l_APDUSOSSESetInput_complete.append(0)
	# input length
	l_APDUSOSSESetInput_complete.append(lengthInput)
	# input value
	l_APDUSOSSESetInput_complete += l_input
	 
	# send Write APDU
	print "send APDU: %s" % toHexString(l_APDUSOSSESetInput_complete)
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSESetInput_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Read Command
	print "Read Input"
	
	# build complete Read APDU
	l_APDUSOSSEGetInput_complete = []
	l_APDUSOSSEGetInput_complete += l_APDUSOSSEGetInput 
	# unused P1
	l_APDUSOSSEGetInput_complete.append(0)
	# unused P2
	l_APDUSOSSEGetInput_complete.append(0)
	# input length
	l_APDUSOSSEGetInput_complete.append(lengthInput)
	
	# send Read APDU
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSEGetInput_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Write Command
	print "Set Mask"
	
	# build complete Read APDU
	l_APDUSOSSESetMask_complete = []
	l_APDUSOSSESetMask_complete += l_APDUSOSSESetMask 
	# unused P1
	l_APDUSOSSESetMask_complete.append(0)
	# unused P2
	l_APDUSOSSESetMask_complete.append(0)
	# mask length
	l_APDUSOSSESetMask_complete.append(lengthMask)
	# mask value
	l_APDUSOSSESetMask_complete += l_mask
	 
	# send Write APDU
	print "send APDU: %s" % toHexString(l_APDUSOSSESetMask_complete)
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSESetMask_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Read Command
	print "Read Mask"
	
	# build complete Read APDU
	l_APDUSOSSEGetMask_complete = []
	l_APDUSOSSEGetMask_complete += l_APDUSOSSEGetMask 
	# unused P1
	l_APDUSOSSEGetMask_complete.append(0)
	# unused P2
	l_APDUSOSSEGetMask_complete.append(0)
	# mask length
	l_APDUSOSSEGetMask_complete.append(lengthMask)
	
	# send Read APDU
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSEGetMask_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Read Command
	print "Launch AES 128"
	
	# build complete Read APDU
	l_APDUSOSSEAESEnc_complete = []
	l_APDUSOSSEAESEnc_complete += l_APDUSOSSEAESEnc 
	# unused P1
	l_APDUSOSSEAESEnc_complete.append(0)
	# unused P2
	l_APDUSOSSEAESEnc_complete.append(0)
	# unused P3
	l_APDUSOSSEAESEnc_complete.append(0)
	
	# send Read APDU
	response,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSEAESEnc_complete)
	
	print "data: %s" % toHexString(response)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# send Read Command
	print "Read Output"
	
	# build complete Read APDU
	l_APDUSOSSEGetOutput_complete = []
	l_APDUSOSSEGetOutput_complete += l_APDUSOSSEGetOutput 
	# unused P1
	l_APDUSOSSEGetOutput_complete.append(0)
	# unused P2
	l_APDUSOSSEGetOutput_complete.append(0)
	# output length
	l_APDUSOSSEGetOutput_complete.append(lengthInput)
	
	# send Read APDU
	ciphertext,sw1,sw2 = o_deviceConnection.transmit(l_APDUSOSSEGetOutput_complete)
	
	print "data: %s" % toHexString(ciphertext)
	print "sw  : %s" % toHexString([sw1]) + toHexString([sw2])
	
	
	##################################################
	# check encryption
	
	# transform the key in binary string
	keyBinaryString = HexListToBinString(l_secretKey)
	
	# define size of key
	AES.key_size = lengthKey
	
	# create an AES engine in ECB mode
	o_cryptoEngine = AES.new(keyBinaryString, AES.MODE_ECB)
	
	# allocate memory for ciphertext2
	ciphertext2 = [0]*lengthInput
	
	# compute the expected ciphertext
	ciphertext2 = BinStringToHexList(o_cryptoEngine.encrypt(HexListToBinString(l_input)))
	
	# display
	print "\n"
	print "--- AES128 encryption ---"
	print "plaintext : %s" % toHexString(l_input)
	print "key       : %s" % toHexString(l_secretKey)
	print "mask      : %s" % toHexString(l_mask)
	print "ciphertext: %s" % toHexString(ciphertext)
	print "checking  : %s" % toHexString(ciphertext2)
	
	# check that ciphertext computed by the card is equal to ciphertext computed in Python
	if(ciphertext == ciphertext2):
		print "encryption ok :-)"
	        print "\n"
                return 0
	else:
		print "encryption ko :-("
	        print "\n"
                return 1

####################################################################################################
####################################################################################################
####################################################################################################
# example of a use of AES 128

##################################################
# open connection with the smartcard

# get list of available smartcard reader(s)
l_listReaders = readers()

# by default the chosen reader is the first one in the reader list, 
# in case this should be modified, the reader number can be given in 
# a unique argument of the python script.
readerNum = 0;
if (len(sys.argv) == 2):
    readerNum = int(sys.argv[1]);
    
# open a connection with the first available smartcard reader
o_deviceConnection = l_listReaders[readerNum].createConnection()

# open a connection with the smartcard chip
o_deviceConnection.connect()

##################################################
# run the AES

# generate random inputs
l_secretKey = [0]*16
l_input     = [0]*16
l_mask      = [0]*18

for i in range(16):
    l_secretKey[i] = randint(0,255)
    l_input[i] = randint(0,255)
    l_mask[i] = randint(0,255)
l_mask[16] = randint(0,255)
l_mask[17] = randint(0,255)

# run the aes
run_aes(l_secretKey,l_input,l_mask)

##################################################
# close connection with the smartcard
o_deviceConnection.disconnect()
