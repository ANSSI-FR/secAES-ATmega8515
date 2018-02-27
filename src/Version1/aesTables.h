#ifndef _AES_TABLES_H
#define _AES_TABLES_H

// Useful definitions
#define UCHAR   unsigned char
#define p_UCHAR unsigned char*


// global variables
#define AESCARDGF256              256
#define AESKeySize                 16
#define AESInputSize               16
#define AESOutputSize              16
#define AESMaskSize                18 // 1 mask per state byte + 1 sbox input mask + 1 sbox output mask
#define AESStateSize AESInputSize

// global variables for the input/output of AES128
UCHAR secret       [AESKeySize];
UCHAR input        [AESInputSize];
UCHAR mask         [AESMaskSize];

// global variables to store the intermediate state of AES128
UCHAR masksState   [AESStateSize];
UCHAR keyState     [AESStateSize];

// Global variable to store the re-computed table in RAM 
// NOTE: the alignment property is used as an hyptohesis in the AES assembly
// directive
// FIXME: some versions of avr-gcc seem to ignore this alignment attribute, yielding in
// a bad behaviour of the code. A proper way of dealing with this would be to throw a
// known error (with a specific APDU) if the program detects that the maskedSbox table is
// not aligned, or deal programmatically with this issue through a dynamic pointer adjustment
// before the AES is called.
__attribute__((aligned(256))) UCHAR maskedSbox       [AESCARDGF256];
// Global variable to store the indices of the permutation table used to shuffle the processing
UCHAR permIndices      [AESStateSize];
// Global variable to store the indices of the permutation table used to shuffle the processing 
// during the ShiftRows processing
UCHAR t_permShiftRows  [AESStateSize];

#endif
