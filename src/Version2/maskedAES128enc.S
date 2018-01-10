;*                                                                           
;*****************************************************************************
;*                                                                          
;*                  MODULE : AES128-ENC PRIMITIVE                         
;*                                                                          
;*****************************************************************************
;*****************************************************************************
;*                                                                            
;* File : maskedAES128enc.S                                                   
;*                                                                            
;* Project :  Test Vehicule                                                   
;*                                                                            
;* Description: AES encryption function with the following security features  
;*           --> All operations are performed in random order. To generate a 
;*           --> random order (aka a random permutation) over [0..15], a permutation
;*           --> permIndices is pre-processed from the masks and the fixed permutation
;*           --> G=permGFSixteen such that for every i in [0..15]:
;*           -->        permIndices [i] = G(G(G(G(x^m0)^m1)^m2)^m3)
;*           --> with m1||m0 = mask[0] and m3||m2 = mask[1]
;*           
;*           --> Affine masking is used for all operations. (see [FMPR10]) 
;*           -->  -->  each byte of the internal state is represented in the form 
;*           -->  -->            Affine(x) = a*x xor b
;*           -->  --> with a = permIndices[2] || permIndicesBis[2] if a != 0
;            -->  --> and a = permIndices[3] || permIndicesBis[3] otherwise.
;*           
;*           --> Same multiplicative mask "a" for all bytes of the state
;*           --> linear steps protected with first-order masking.
;*           -->  -->  (one mask / state byte)
;*           -->  -->  MixColumns "artificialy" masked at second order
;*           -->  sbox processing protected with the table-recomputation method.
;*           -->  key schedule is also affine masked.
;*                                                   
;* Bibliography: [Koc99], [RPD09], [FMPR10], [Wil01], [CJRR99] 
;*                                                                            
;*---------------------------------------------------------------------------
;* Author(s): V. LOMNE, E. PROUFF, T. ROCHE                                                       
;*                                                                            
;*---------------------------------------------------------------------------
;* the inputs "message", "key" and "mask" are assumed to be stored in global 
;*            variables, "input", "key" and "mask" respectively.
;* the output is directly stored in the global variable "input"             
;*
;* 7 arrays are defined in "aesTables.c" for temporary storing 
;* of intermediate data:
;*    - unsigned char secret           [AESKeySize];
;*    - unsigned char input            [AESInputSize];
;*    - unsigned char mask             [AESMaskSize];
;*                                                     
;*    - unsigned char masksState       [AESStateSize];
;*    - unsigned char keyState         [AESStateSize];
;*     
;*    - unsigned char maskedSbox       [256];//recomputed s-box
;*    - unsigned char permIndices      [16]; //shuffling array 1
;*    - unsigned char permIndicesBis   [16]; //shuffling array 2
;*    - unsigned char permIndicesSR    [16]; //t_shiftRow(permIndice())
;*    - unsigned char t_permShiftRows  [16]; //temporary array
;*     
;*
;* do not erase these registers:
;*    - Rcon[0] stored in r24
;*    - round counter stored in r25
;*---------------------------------------------------------------------------
;* COMPLEXITY: 80000 cycles
;*---------------------------------------------------------------------------
;* HISTORY:
;*----------------------------------------------------------------------------
;* V 1.00 | 16/03/14 | First  version (DPA book implementation)     
;* V 2.00 | 23/03/14 | Second version (18 masks instead of 6)       
;* V 2.01 | 18/05/14 | Improved to avoid BUS leakage during SubBytes    
;* V 3.00 | 28/11/14 | Operations Shuffling    
;* V 3.01 | 17/02/15 | keyExpansion on the fly   
;* V 4.01 | 17/03/15 | Affine masking + several permuations 
;* V 4.02 | 30/03/15 | Save RAM memory (#input=#output=#maskedState)    
;*****************************************************************************

.global asm_maskedAES128enc

#define registerRcon                r24
#define registerRoundCounter        r25
#define mask_multiplicative         r13
#define mask_multiplicative_inverse r14
#define maskedState               input

;****************************************************************************************************
;*******************************             LUT                  ***********************************
;****************************************************************************************************

// table representing the SBox transformation
sbox:
.byte 0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76
.byte 0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0
.byte 0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15
.byte 0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75
.byte 0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84
.byte 0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF
.byte 0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8
.byte 0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2
.byte 0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73
.byte 0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB
.byte 0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79
.byte 0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08
.byte 0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A
.byte 0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E
.byte 0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF
.byte 0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16

// table representing the field multiplication by 2
xtime:
.byte 0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e
.byte 0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e
.byte 0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e
.byte 0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e
.byte 0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e
.byte 0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe
.byte 0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde
.byte 0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe
.byte 0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05
.byte 0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25
.byte 0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45
.byte 0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65
.byte 0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85
.byte 0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5
.byte 0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5
.byte 0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5

// table representing the ShiftRows transformation
t_shiftRows:
.byte 0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3

// Permutation over GF(16) used to generate a shuffling permutation for the operations order
permGFSixteen:
.byte 0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0X0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02

// Constants Array for the key Expansion
Rcon:
.byte 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x36

// Two Tables to process a field multplication over GF(256): a*b = alog ( log(a) + log(b) mod 255)
LogTable:
.byte   0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3 
.byte 100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193 
.byte 125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120 
.byte 101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142 
.byte 150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56 
.byte 102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16 
.byte 126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186 
.byte  43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87 
.byte 175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232 
.byte  44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160 
.byte 127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183 
.byte 204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157 
.byte 151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209 
.byte  83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171 
.byte  68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165 
.byte 103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7 

ALogTable:
.byte   1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53 
.byte  95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170 
.byte 229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49 
.byte  83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205 
.byte  76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136 
.byte 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154 
.byte 181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163 
.byte 254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160 
.byte 251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65 
.byte 195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117 
.byte 159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128 
.byte 155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84 
.byte 252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202 
.byte  69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14 
.byte  18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23 
.byte  57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1 

;****************************************************************************************************
;*******************************            MACROS                ***********************************
;****************************************************************************************************

;----------------------------------------------------------------------------------------------------
.MACRO saveContext
;save all register values in the stack (64 cycles)
PUSH r31
PUSH r30
PUSH r29
PUSH r28
PUSH r27
PUSH r26
PUSH r25
PUSH r24
PUSH r23
PUSH r22
PUSH r21
PUSH r20
PUSH r19
PUSH r18
PUSH r17
PUSH r16
PUSH r15
PUSH r14
PUSH r13
PUSH r12
PUSH r11
PUSH r10
PUSH r9
PUSH r8
PUSH r7
PUSH r6
PUSH r5
PUSH r4
PUSH r3
PUSH r2
PUSH r1
PUSH r0
.ENDM

;----------------------------------------------------------------------------------------------------
.MACRO loadContext
;load all register values from the stack (64 cycles)
POP r0
POP r1
POP r2
POP r3
POP r4
POP r5
POP r6
POP r7
POP r8
POP r9
POP r10
POP r11
POP r12
POP r13
POP r14
POP r15
POP r16
POP r17
POP r18
POP r19
POP r20
POP r21
POP r22
POP r23
POP r24
POP r25
POP r26
POP r27
POP r28
POP r29
POP r30
POP r31
.ENDM


;****************************************************************************************************
;*******************************       AES  SUBFUNCTIONS          ***********************************
;****************************************************************************************************
;**** 1. keyExpansion
;**** 2. addRoundKey
;**** 3. maskedSubBytes
;**** 4. ShiftRows
;**** 5. MixColumns

;----------------------------------------------------------------------------------------------------
;------------------------------        Key expansion             ------------------------------------
;----------------------------------------------------------------------------------------------------
keyExpansion:
; performs the AES keyExpansion corresponding to the ith round, register registerRcon is updated and 
; also the global arry keyState.
; REQUIRE: register registerRcon must contain the AES round constant, and register mask_multiplicative 
;          must contain the multiplicative masked (built thanks to buildMultiplicativeMask).
; NOTE: registers r0-r15, r16, r17, r18, r19, Z are modified
; COMPLEXITY: 214 cycles

; Compute the round key
MOV   r18,registerRoundCounter                ; r18 = 11 - round counter = 11 - i
LDI   r19,0x0B
SUB   r19,r18                                 ; r19 = 11 - registerRoundCounter = i
LDI   r30,lo8(Rcon)
LDI   r31,hi8(Rcon)
CLR   r1                                      ; will be used to propagate carry
ADD   r30, r19
ADC   r31, r1
LPM   r16, Z                                  ; r16 = RCon[i]
MOV   r17, mask_multiplicative
RCALL GF256_mult
MOV   registerRcon, r16                       ; registerRcon = mask_multiplicative * RCon[i]

; load RAM address of masksState in X = r26:r27 and get the SBox prcessing masks
LDI   r26,lo8(mask)                           ; X = #masks
LDI   r27,hi8(mask)
ADIW  r26, 16                                 ; X  = #masks + 16
LD    r20, X+                                 ; r20 = masks [16] =  sbox_input_mask
LD    r21,  X                                 ; r21 = masks [17] =  sbox_output_mask

;load keyState in r0 to r15 (33 cycles)
LDI r26,lo8(keyState)
LDI r27,hi8(keyState)
LD r0,X+
LD r1,X+
LD r2,X+
LD r3,X+
LD r4,X+
LD r5,X+
LD r6,X+
LD r7,X+
LD r8,X+
LD r9,X+
LD r10,X+
LD r11,X+
LD r12,X+
EOR r12, r20
LD r13,X+
EOR r13, r20
LD r14,X+
EOR r14, r20
LD r15,X+
EOR r15, r20

LDI r16,lo8(maskedSbox)
LDI r17,hi8(maskedSbox)
CLR r18                                    ; will be used to propagate carries
CLR r19                                    ; will be used to prevent HD leakages

; BEGIN Securely Process the transformation (r0,r1,r2,r3) <-- (sbox(r13)^Rcon[i],sbox(r14),sbox(r15),sbox(r12))
;       intermediate results x are either in the form mask_multiplicative*x ^ sbox_intput_mask or mask_multiplicative*x ^ sbox_output_mask
; 1st element
MOVW r30,r16                               ; Z  = #maskedSbox
ADD r30,r13
ADC r31,r18
LD  r19,Z                                  ; r19 = maskedSbox [mask_multiplicative*key[13]^sbox_input_mask] = mask_multiplicative * Sbox[key[13]] ^sbox_output_mask
EOR r0,registerRcon                        ; r0  = mask_multiplicative*(key[0] ^ RCon[i]) ^ sbox_intput_mask
EOR r0,r19                                 ; r0  = mask_multiplicative*(key[0] ^ Sbox[key[13] ^ RCon[i]) ^ sbox_intput_mask ^ sbox_output_mask
EOR r0,r21                                 ; r0  = mask_multiplicative * Sbox[key[13]] ^ sbox_intput_mask

; 2nd element
MOVW r30,r16
ADD r30,r14
ADC r31,r18
LD  r19,Z
EOR r1,r19
EOR r1,r21

; 3rd element
MOVW r30,r16
ADD r30,r15
ADC r31,r18
LD  r19,Z
EOR r2,r19
EOR r2,r21

; 4th element
MOVW r30,r16
ADD r30,r12
ADC r31,r18
LD  r19,Z
EOR r3,r19
EOR r3,r21
; END Securely Process the transformation (r0,r1,r2,r3) <-- (sbox(r13)^Rcon[i],sbox(r14),sbox(r15),sbox(r12))

; BEGIN Process the transformation of the 3 other columns
EOR r12, r20
EOR r13, r20
EOR r14, r20
EOR r15, r20
EOR r4,r0
EOR r5,r1
EOR r6,r2
EOR r7,r3
EOR r8,r4
EOR r9,r5
EOR r10,r6
EOR r11,r7
EOR r12,r8
EOR r13,r9
EOR r14,r10
EOR r15,r11
; END Process the transformation of the 3 other columns

;load address of "keyState"
LDI r26,lo8(keyState)
LDI r27,hi8(keyState)
ST X+,r0
ST X+,r1
ST X+,r2
ST X+,r3
ST X+,r4
ST X+,r5
ST X+,r6
ST X+,r7
ST X+,r8
ST X+,r9
ST X+,r10
ST X+,r11
ST X+,r12
ST X+,r13
ST X+,r14
ST X+,r15
RET

;----------------------------------------------------------------------------------------------------
;-----------------------------     addRoundKey               ----------------------------------------
;----------------------------------------------------------------------------------------------------
addRoundKey:
; add the AES round key to maskedState
; REQUIRE: sub-function loadAndMaskKey and buildIndicesPermutation must have been runned prior this call
; NOTE: X, Y, Z, r16, r17, r18, r19, r20, r21, r22, r23, r24 are modified
; SECURITY: operations performed in a random order specified by permIndices + Affine Masking
; COMPLEXITY: 299 cycles

; load #keyState into r23||r22
LDI r22,lo8(keyState)
LDI r23,hi8(keyState)

; load #maskedState into r23||r22
LDI r20, lo8(maskedState)
LDI r21, hi8(maskedState)

; load #maskedState into Z=r31||r30
LDI r30, lo8(permIndices)
LDI r31, hi8(permIndices)

CLR r19                                    ; to deal with mask propagation
LDI r24, 16                                ; loop index
loop_addRoundKey:
MOVW r26, r22
MOVW r28, r20
LD  r18, Z+
ADD r26, r18
ADC r27, r19
ADD r28, r18
ADC r29, r19
LD  r16, X
LD  r17, Y
EOR r17, r16
ST  Y, r17
DEC r24
BRNE loop_addRoundKey

RET

;----------------------------------------------------------------------------------------------------
;-------------------------       maskedSubBytes         ---------------------------------------------
;----------------------------------------------------------------------------------------------------
maskedSubBytes:
; perform masked SubBytes, ie for each element i of maskedState: maskedState[i] = maskedSbox(maskedState[i]^masksState[i]^sbox_input_mask)^masksState[i]^sbox_output_mask
; note that, by construction, maskedState[i] equals sbox(maskedState[i])^maskState[i] after the processing
; NOTE: X, r16-r24, r0-r5 are modified
; SECURITY: processing is done in a random order specified in table permIndices + Affine masking
; COMPLEXITY: 771 cycles

;load RAM address of maskedSbox in r17||r16
LDI   r16,lo8 (maskedSbox)
LDI   r17,hi8 (maskedSbox)
;load RAM address of masksState in r19||r18
LDI   r18,lo8 (masksState)
LDI   r19,hi8 (masksState)
;load RAM address of maskedState in r21||r20
LDI   r20,lo8 (maskedState)
LDI   r21,hi8 (maskedState)
; init Y with the address of permIndices
LDI   r28,lo8 (permIndices)            ; Y = #permIndices
LDI   r29,hi8 (permIndices)

CLR    r0                              ; FOR SECURITY ONLY: clear rO
CLR    r1                              ; FOR SECURITY ONLY: clear r1
CLR    r2                              ; FOR SECURITY ONLY: clear r2 
CLR    r3                              ; FOR SECURITY ONLY: clear r3 
CLR    r5                              ; clear r5  (for adding carry)

; load RAM address of masksState in X = r26:r27
LDI   r26,lo8(mask)                    ; X = #mask
LDI   r27,hi8(mask)
ADIW  r26, 16                          ; X  = #masks + 16
LD     r1, X+                          ; r1 = masks [16] =  sbox_input_mask
LD     r2,  X                          ; r2 = masks [17] =  sbox_output_mask
      

LDI   r23, 16                          ; loop index j (downto)
loop_maskedSubBytes:

CLR   r22                              ; FOR SECURITY ONLY: clear r22

; load the random loop index into r4
LD    r4, Y+                           ; r4 = i

; load RAM address of maskedState in X = r26:r27
MOVW  r26,r20                          ; X  = #maskedState
ADD   r26, r4
ADC   r27, r5                          ; X  = #maskedState + i
LD    r22,  X                          ; r22 = maskedState [i] = unmaskedState [i] + masksState [i]
ST      X, r5                          ; FOR SECURITY ONLY: clear the value at address X (to prevent HD leakage)
LD     r5,  X                          ; FOR SECURITY ONLY: clear the R/W BUS to access RAM memory

; load RAM address of masksState in X = r26:r27
MOVW  r26,r18                          ; X  = #masksState
ADD   r26, r4
ADC   r27, r5                          ; X  = #masksState + i
LD     r3,  X                          ; r3 = masksState [i]

EOR   r22, r1                          ; r22 += r1 = unmaskedState [i] + masksState [i] + sbox_input_mask
EOR   r22, r3                          ; r22 is now masked with sbox_input_mask only = unmaskedState [i] + sbox_input_mask

MOVW  r26,r16                          ; FOR SECURITY ONLY:  X  = #maskedSbox
LD     r0,  X                          ; FOR SECURITY ONLY:  r0 = sbox (0 ^ sbox_input_mask)  + sbox_output_mask


ADD   r26,r22                          ; X  = #maskedSbox
ADC   r27, r5
LD    r24,  X                          ; r24 = sbox (unmaskedState [i])  + sbox_output_mask

EOR   r24, r3                          ; r24 = sbox (unmaskedState [i])  + sbox_output_mask + masksState [i]
EOR   r24, r2                          ; r24 = sbox (unmaskedState [i])  + masksState [i]

; load RAM address of maskedState in X = r26:r27
MOVW  r26,r20                          ; X  = #maskedState
ADD   r26, r4
ADC   r27, r5                          ; X  = #maskedState + i
ST      X, r5                          ; FOR SECURITY ONLY: clear the value at address X (to prevent HD leakage)
LD     r5,  X                          ; FOR SECURITY ONLY: clear the R/W BUS to access RAM memory
ST      X,r24                          ; update the value of maskedState [i] with r24

DEC   r23                              ; decrement loop index

BRNE  loop_maskedSubBytes

CLR   r22
CLR   r24
CLR    r0
CLR    r1
CLR    r2
CLR    r3

RET

;----------------------------------------------------------------------------------------------------
;-------------------------       shiftRows              ---------------------------------------------
;----------------------------------------------------------------------------------------------------
shiftRows:
; performs shiftRows on a 16-bytes array, called state, whose adress has been stored in 21||20
; REQUIRE: r20||r21 must equal the address of the shiftRows input and Y must equal the adress of a table with the 
;          sixteen elements of [0..15] in random order.
; NOTE: registers r0, r16 to r31 are modified, r25 is re-stored
; SECURITY: the processing is done in a random order which is specified in table permIndices (RAM)
; COMPLEXITY: 431 

PUSH r25            ; r25 contains the AES round counter

; -----
; FIRST STEP: perform t_permShiftRows = ShiftRows (state) in random order (specified by permutation permIndices)
; -----

LDI  r22, lo8(t_permShiftRows)
LDI  r23, hi8(t_permShiftRows)
CLR  r0
 
; i = 15
LDD  r18, Y + 15    ; r18 = permIndices(i) = x
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 14
LDD  r18, Y + 14    ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 13
LDD  r18, Y + 13    ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 12
LDD  r18, Y + 12    ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 11
LDD  r18, Y + 11    ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 10
LDD  r18, Y + 10    ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 9
LDD  r18, Y + 9     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 8
LDD  r18, Y + 8     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(i))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 7
LDD  r18, Y + 7     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 6
LDD  r18, Y + 6     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 5
LDD  r18, Y + 5     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 4
LDD  r18, Y + 4     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18       
ADC  r27, r0        
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 3             
LDD  r18, Y + 3     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 2
LDD  r18, Y + 2     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 1
LDD  r18, Y + 1     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))
; i = 0
LDD  r18, Y + 0     ; r18 = permIndices(i) = random index
MOVW r26, r20       ; X = #state (that is #maskedState or #masksState)
ADD  r26, r18
ADC  r27, r0   
LD   r19, X         ; r19 = state(permIndices(0))
MOVW r26, r22       ; X = #t_permShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(i)) = r19 = state(permIndices(i))


; --------
; SECOND STEP: perform state = t_permShiftRows in random order (specified by permutation permIndices)
; --------

LDI  r28, lo8(permIndices)
LDI  r29, hi8(permIndices)
LDI  r30, lo8(permIndicesSR)
LDI  r31, hi8(permIndicesSR)


;i = 15
LDD  r18, Y + 15     ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 15     ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 14
LDD  r18, Y + 14     ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 14     ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 13
LDD  r18, Y + 13     ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 13     ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 12
LDD  r18, Y + 12     ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 12     ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 11
LDD  r18, Y + 11     ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 11     ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 10
LDD  r18, Y + 10     ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 10     ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 9
LDD  r18, Y + 9      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 9      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 8
LDD  r18, Y + 8      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 8      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 7
LDD  r18, Y + 7      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 7      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 6
LDD  r18, Y + 6      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 6      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 5
LDD  r18, Y + 5      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 5      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 4
LDD  r18, Y + 4      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 4      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 3
LDD  r18, Y + 3      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 3      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 2
LDD  r18, Y + 2      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 2      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 1
LDD  r18, Y + 1      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 1      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))
;i = 15
LDD  r18, Y + 0      ; r18 = permIndices(i) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(i))
LDD  r18, Z + 0      ; r18 = t_shiftRows(permIndices(i))
MOVW r26, r20        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(i))) = t_permShiftRows(permIndices(i))

POP r25              ; r25 contains the AES round counter
RET

;----------------------------------------------------------------------------------------------------
;-------------------------         mixColumns             -------------------------------------------
;----------------------------------------------------------------------------------------------------
mixColumns:
; perform mixColumns operation on a state matrix whose address has been stored in Y with random access 
; specified in X
; REQUIRE: Y must equal the address of the shiftRows input, X must equal either permIndices or permIndicesBis
; NOTE: registers r0, r1, r2, r3, r4, r16, r17 are modified
; COMPLEXITY: 408 cycles

; BEGIN SECURITY pre_treatment
; erase contents of registers r0-r3 (to prevent HD leakages)
CLR r0
CLR r1
CLR r2
CLR r3
CLR r4                                ; will be used to add carries
CLR r30
CLR r31
; END SECURITY pre_treatment

LDI r16,lo8(xtime)                       ; save the adress of xtime table into r16||r17
LDI r17,hi8(xtime)
CLR r5                                   ; will be used to propagate carry in MC_subroutine

LD   r22, X
ANDI r22, 0x03                        ; r22 random value in [0..3] = rand
LSL  r22
LSL  r22                              ; r22 = 4*rand

MOVW r20, r28                         ; r21||r20 = #input_state

; i = 0
MOVW r28, r20                         ; Y = #input_state
LDI  r19, 0                           ; r19 = 4*i
EOR  r19, r22                         ; r19 = 4 * ( i ^ rand )    
ADD  r28, r19                         ;      Y = #(input_state 4 * ( i ^ rand ))
ADC  r29, r4                          ; i.e. Y = # of the column of input_state to process
CLR  r19                              ; prepare r19 for next iteration
RCALL MC_subroutine

; i = 1
MOVW r28, r20                         ; Y = #input_state
LDI  r19, 4                           ; r19 = 4*i
EOR  r19, r22                         ; r19 = 4 * ( i ^ rand )    
ADD  r28, r19                         ;      Y = #(input_state 4 * ( i ^ rand ))
ADC  r29, r4                          ; i.e. Y = # of the column of input_state to process
CLR  r19                              ; prepare r19 for next iteration
RCALL MC_subroutine

; i = 2
MOVW r28, r20                         ; Y = #input_state
LDI  r19, 8                           ; r19 = 4*i
EOR  r19, r22                         ; r19 = 4 * ( i ^ rand )    
ADD  r28, r19                         ;      Y = #(input_state 4 * ( i ^ rand ))
ADC  r29, r4                          ; i.e. Y = # of the column of input_state to process
CLR  r19                              ; prepare r19 for next iteration
RCALL MC_subroutine

; i = 3
MOVW r28, r20                         ; Y = #input_state
LDI  r19, 12                          ; r19 = 4*i
EOR  r19, r22                         ; r19 = 4 * ( i ^ rand )    
ADD  r28, r19                         ;      Y = #(input_state 4 * ( i ^ rand ))
ADC  r29, r4                          ; i.e. Y = # of the column of input_state to process
RCALL MC_subroutine

; BEGIN SECURITY post-treatment
; erase the contents of r0-r3 and r19
CLR r0
CLR r1
CLR r2
CLR r3
CLR r19
; END SECURITY post-treatment

RET

;----------------------------------------------------------------------------------------------------
;------------------------------   MC_subroutine  ------------------------------------------
;----------------------------------------------------------------------------------------------------
MC_subroutine:
; perform the mixcolumn operation on a a 4 bytes vector whose address is given in Y
; NOTE: r0, r1, r2, r3,, r5, r16 and r17 are modified. Z and Y are manipulated

; --------------------------------------------------------------------------------------------------------------------------------------
;      INSTRUCTIONS         |           INITIAL STATE                        |                         NEW STATE
; --------------------------------------------------------------------------------------------------------------------------------------
; pre-processing for the column
LDD r0, Y + 0                             ; r0 = 0                                         ->  r0 = Y[0]
MOV r3, r0                                ; r3 = 0                                         ->  r3 = Y[0] ; save Y[0] for future use
LDD r1, Y + 1                             ; r1 = 0                                         ->  r1 = Y[1]
EOR r0, r1                                ; r0 = Y[0]                                      ->  r0 = Y[0] + Y[1]
LDD r1, Y + 2                             ; r1 = Y[1]                                      ->  r1 = Y[2]
EOR r0, r1                                ; r0 = Y[0] + Y[1]                               ->  r0 = Y[0] + Y[1] + Y[2] 
LDD r1, Y + 3                             ; r1 = Y[2]                                      ->  r1 = Y[3]
EOR r0, r1                                ; r0 = Y[0] + Y[1] + Y[2]                        ->  r0 = Y[0] + Y[1] + Y[2] + Y[3] = temp
MOV r2, r0                                ; r2 = 0                                         ->  r2 = temp
; --------------------------------------------------------------------------------------------------------------------------------------

; --------------------------------------------------------------------------------------------------------------------------------------
;      INSTRUCTIONS         |           INITIAL STATE                        |                         NEW STATE
; --------------------------------------------------------------------------------------------------------------------------------------
; first byte
LDD r0, Y + 0                             ; r0 = Y[0] + Y[1] + Y[2] + Y[3]                 ->  r0 = Y[0]
LDD r1, Y + 1                             ; r1 = Y[3]                                      ->  r1 = Y[1]
EOR r0, r1                                ; r0 = Y[0]                                      ->  r0 = Y[0] + Y[1]
MOVW r30, r16                             ; r30||r31 = ??                                  ->  r30||r31 = #xtime
ADD r30, r0                               ; r30 = hi8(xtime)                               -> r30 = low8(xtime) + Y[0] + Y[1]
ADC r31, r5                               ; r31 = lo8(xtime)                               -> r31 = hi8(xtime)  + the carry possibly raised by previous addition
CLR r0                                    ; r0 = Y[0] + Y[1]                               -> r0 = 0
LPM r0, Z                                 ; r0  = 0                                        -> r0 = xtime (Y[0] + Y[1])
EOR r0, r2                                ; r0 = xtime (Y[0] + Y[1])                       ->  r0 = xtime (Y[0] + Y[1])  + \sum_{i=0}^3 Y[i]
LDD r1, Y + 0                             ; r1 = Y[1]                                      ->  r1 = Y[0]
EOR r0, r1                                ; r0 = xtime (Y[0] + Y[1])  + \sum_{i=0}^3 Y[i]  ->  r0 = xtime (Y[0] + Y[1])  + \sum_{i=1}^3 Y[i]
STD Y + 0, r0                             ; Y[0] masked with masksState[0]                 -> Y[0] = r0 (masked with (mixColumns(masksState))[0] )
; --------------------------------------------------------------------------------------------------------------------------------------

; second byte
LDD r0, Y + 1
LDD r1, Y + 2
EOR r0, r1
MOVW r30, r16
ADD r30, r0
ADC r31, r5
CLR r0
LPM  r0, Z
EOR r0, r2
LDD r1, Y + 1 
EOR r0, r1
STD Y + 1, r0

; third byte
LDD r0, Y + 2
LDD r1, Y + 3
EOR r0, r1
MOVW r30, r16
ADD r30, r0
ADC r31, r5
CLR r0
LPM  r0, Z
EOR r0, r2
LDD r1, Y + 2 
EOR r0, r1
STD Y + 2, r0

; fourth byte
LDD r0, Y + 3
EOR r0, r3
MOVW r30, r16
ADD r30, r0
ADC r31, r5
CLR r0
LPM  r0, Z
EOR r0, r2
LDD r1, Y + 3 
EOR r0, r1
STD Y + 3, r0

RET

;****************************************************************************************************
;*******************************       ELEMENTARY SUBFUNCTIONS          *****************************
;****************************************************************************************************
;**** 1. GF256_mult

;----------------------------------------------------------------------------------------------------
;------------------------------  Mult in GF256 subroutine  ------------------------------------------
;----------------------------------------------------------------------------------------------------
GF256_mult:
; GOAL: process the field product x*y in GF(256)
; INPUTS: x and y respecticely stored in r16 and r17
; OUTPUT; result stored in r16
; NOTE: r0 to r5, r16 to r18 and r30, r31 are used. Registers r0, r1, r18, r30 and r31 are re-stored.
; COMPLEXITY: 65 cycles

PUSH r0
PUSH r1
PUSH r18
PUSH r30
PUSH r31

; BEGIN SECURITY
CLR  r0
CLR  r1
; END SECURITY

CLR  r2                            ; to deal with mask propagation
CLR  r3
INC  r3
CLR  r5                            ; used to detect null operands

MUL     r16, r17                   ; r1||r0 = r17||r16
OR       r0, r1                    ; r0 = (r0 or r1) which equals 0 iff r0=r1=0
SUB      r0, r3                    ; r0 = r0 - 1
ADC      r5, r2                    ; r5 = 1 iff r0 or r1 is null and equals 0 otherwise
EOR      r5, r3                    ; r5 = 0 iff r0 or r1 is null and equals 1 otherwise

LDI  r30,lo8(LogTable)
LDI  r31,hi8(LogTable)             ; Z = # LogTable

ADD     r30, r16
ADC     r31, r2
LPM     r16, Z                     ; r16 = Log(x) 
LDI  r30,lo8(LogTable)
LDI  r31,hi8(LogTable)             ; Z = # LogTable
ADD     r30, r17
ADC     r31, r2
LPM     r18, Z                     ; r18 = Log(x)

ADD     r16, r18
ADC     r16, r2                    ; r16 = r16 + r2 + carry = (x + y) % 256 + 1(x+y>255) = z
ADD     r16, r3                    ; r16 = z + 1 % 256
SUB     r16, r3
ADC     r16, r2                    ; r16 = (z + 1 - 1)%256 + 1() which equals z if z<255 and 0 if z = 255

LDI  r30,lo8(ALogTable)
LDI  r31,hi8(ALogTable)            ; r31||r30 = # ALogTable
ADD     r30, r16
ADC     r31, r2
LPM     r16, Z                     ; r16 = ALogTable ( (x+y) % 255)

MUL     r16, r5
MOV     r16, r0                    ; r16 = ALogTable ( (x+y) % 255) if r16 and r17 are not null, equals 0 
                                   ;        otherwise
POP r31
POP r30
POP r18                                    
POP r1
POP r0
RET

;****************************************************************************************************
;*******************************       PRE-PROCESSING                  *****************************
;****************************************************************************************************
;**** 1. buildIndicesPermutation
;**** 2. buildMultiplicativeMask
;**** 3. computeAndStoreMaskedSbox
;**** 4. loadMasks
;**** 5. loadAndMaskInput
;**** 6. loadAndMaskKey
;**** 7. orderFromOneToTwo

;----------------------------------------------------------------------------------------------------
;------------------------------   buildIndicesPermutation  ------------------------------------------
;----------------------------------------------------------------------------------------------------
buildIndicesPermutation:
; GOAL: build 2 random permutations permIndices and permIndicesBis over GF(16) from the fixed permutation 
;       permGFSixteen and the two first masks of table mask.
;       Let F1 = permIndices, F2=perIndices, G = permGFSixteen, m1||m0 = mask[0] and m3||m2 = mask[1]
;                      F1(x) = G(G(G(G(x^m0)^m1)^m2)^m3) 
;                      F2(x) = G(G(G(G(G(G(G(x^m0)^m1)^m2)^m3)^m1)^m2)^m3)
; NOTE: r16, r17, r18, r19, r20, r21, r22, , r23, r26, r27, r30, r31

LDI  r26,lo8(mask)
LDI  r27,hi8(mask)
LD   r16, X+
MOV  r17, r16
ANDI r16, 0x0F                           ; define r16 = m0
SWAP r17
ANDI r17, 0x0F                           ; define r17 = m1
LD   r18, X
MOV  r19,r18
ANDI r18, 0x0F                           ; define r18 = m2
SWAP r19
ANDI r19, 0x0F                           ; define r19 = m3
LDI  r26,lo8(permIndices)                ; X = #permIndices
LDI  r27,hi8(permIndices)
LDI  r28,lo8(permIndicesBis)             ; X = #permIndicesBis
LDI  r29,hi8(permIndicesBis)
LDI  r20,lo8(permGFSixteen)              ; Z = #permGFSixteen
LDI  r21,hi8(permGFSixteen)

; initialize the index loop in r0
LDI r23, 0x0f            ; r16 = x
LDI r24, 0x10           ; lopp index
CLR r2                  ; to deal with carry propagation

; BEGIN compute permIndices(x)    = G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) for very x
;           and permIndicesBis(x) = G(G(G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3)^m1)^m2)^m3) for very x
permIndicesLoop:
; for permIndices
MOV r22,r23
EOR r22,r16                             ; r22 = x + m0
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(x + m0)
EOR r22,r17                             ; r22 = G(x + m0) ^ m1 
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(G(x + m0) ^ m1)
EOR r22,r18                             ; r22 = G(G(x + m0) ^ m1) ^ m2
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(G(G(x + m0) ^ m1) ^ m2)
EOR r22,r19                             ; r22 = G(G(G(x + m0) ^ m1) ^ m2) ^ m3
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3)
ST X+,r22                               ; X <- G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) and X++

; for permIndicesBis
EOR r22,r17                             ; r22 = G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1 
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1)
EOR r22,r18                             ; r22 = G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1) ^ m2
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1) ^ m2)
EOR r22,r19                             ; r22 = G(G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1) ^ m2) ^ m3
MOVW r30,r20                            ; Z = #G
ADD r30,r22
ADC r31,r2                              ; Z = #(G(r22))
LPM r22,Z                               ; r22 = G(G(G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1) ^ m2) ^ m3)
ST Y+,r22                               ; Y <- G(G(G(G(G(G(G(x + m0) ^ m1) ^ m2) ^ m3) ^ m1) ^ m2) ^ m3) and Y++

DEC r23                                 ; decrement loop index
DEC r24
BRNE permIndicesLoop                    ; loop until r16 = 0

LDI  r24, lo8(t_shiftRows)
LDI  r25, hi8(t_shiftRows)              ; r25||r24 = #t_shiftRows
LDI  r26,lo8(permIndices)               ; X        = #permIndices
LDI  r27,hi8(permIndices)
LDI  r28,lo8(permIndicesSR)             ; Y        = #permIndicesSR
LDI  r29,hi8(permIndicesSR)

LDI  r16, 16                            ; loop index = i
ADIW r26, 16
ADIW r28, 16
; X = #permIndices   + 16
; Y = #permIndicesSR + 16
loop_buildpermIndicesSR:
LD   r18, -X         ; r18 = permIndices(x) = random index
MOVW r30, r24        ; Z = #t_shiftRows
ADD  r30, r18
ADC  r31, r0
LPM  r18, Z          ; r18 = t_shiftRows(permIndices(x))
ST   -Y, r18         ; state(t_shiftRows(permIndices(x))) = t_permShiftRows(permIndices(x))
DEC  r16
BRNE loop_buildpermIndicesSR
; permIndicesSR(x) = t_shiftRows(permIndices(x))

CLR  r16
CLR  r17

; BEGIN SECURITY section (erase registers)
MOVW r18, r16
MOVW r20, r18
MOVW r22, r20
MOVW r24, r22
MOVW r26, r24
MOVW r30, r26
; END SECURITY section (erase registers)

RET


;----------------------------------------------------------------------------------------------------
;------------------------------   buildMultiplicativeMask  ------------------------------------------
;----------------------------------------------------------------------------------------------------
buildMultiplicativeMask:
; build a multiplicative mask 
; NOTE: permIndices and permIndicesBis must have been built prior to calling this function
; construction of multiplicative mask a: 
;           - a = permIndices[2] || permIndicesBis[2]
;           - if a == 0 then
;               a = permIndices[3] || permIndicesBis[3]       
;
; NOTE: Y and Z are modified, r1,r2,r16 and r17 are modified 
; COMPLEXITY: 41 cycles
LDI  r28,lo8(permIndices)           ; Y = #permIndices
LDI  r29,hi8(permIndices)
LDD  r16, Y+2                       ; r16 = random in [0..15]
LDD  r17, Y+3                       ; r17 = random in [0..15]
SWAP r16
SWAP r17
LDI  r28,lo8(permIndicesBis)        ; Y = #permIndicesBis
LDI  r29,hi8(permIndicesBis)
LDD  r1, Y+2                        ; r1 = random in [0..15]
LDD  r2, Y+3                        ; r2 = random in [0..15]
EOR  r17, r2                        ; r17 = random in [0..255]
EOR  r16, r1                        ; r16 = random in [0..255]
BRBC 1,notnull                        
MOV  r16,r17                        ; r16 = random in [1..255]
                                    
notnull:                            
CLR  r2                             ; used for carry propagation

MOV  mask_multiplicative, r16

; compute the inverse 1/a in GF256

LDI  r30,lo8(LogTable)              ; Z = #Logtable
LDI  r31,hi8(LogTable)              
ADD  r30, r16                       
ADC  r31, r2                        
LPM  r16, Z                         ; r16 = Log(r16)
                                    
LDI    r17, 255                     
SUB r17, r16                        ; r17 = 255 - Log(r16) 
                                    
LDI  r30,lo8(ALogTable)             ; Z = #ALogtable
LDI  r31,hi8(ALogTable)             
ADD  r30, r17                                 
ADC  r31, r2                        
LPM  r17, Z                         ; r17 = Inverse (r16)

MOV  mask_multiplicative_inverse, r17

RET


;----------------------------------------------------------------------------------------------------
;--------------------          computeAndStoreMaskedSbox            ---------------------------------
;----------------------------------------------------------------------------------------------------
computeAndStoreMaskedSbox:
; compute S( (x + sbox_mask_input)*mask_multiplicative_inverse )*mask_multiplicative + sbox_mask_output 
; for every x and store it at address #maskedSbox
; SECURITY: the table recomputation is done in a regular increasing order starting from a random value.
; REQUIRE: r18 = #masks
; NOTE: X, Y and Z are modified, r2 and r16 to r23 are modified 
; SECURITY: processing done in random order
; COMPLEXITY: 39000 cycles

; get the masks sbox_mask_input and sbox_mask_output corresponding to masks[16] and masks[17]
; also get a random index (in mask[15]) for the processing.
LDI r30,lo8(mask)                   ; Z = #masks
LDI r31,hi8(mask)
ADIW r30,15                         ; Z = #masks + 15
LD r19,Z+                           ; r19 = random index for mask processing
LD r20,Z+                           ; r20 = sbox_mask_input
LD r21,Z                            ; r21 = sbox_mask_output

; load RAM address of sbox in registers r23:r22
LDI r22,lo8(sbox)
LDI r23,hi8(sbox)

; load RAM address of maskedSbox in r25:r24 
LDI r24,lo8(maskedSbox)
LDI r25,hi8(maskedSbox)

; clear r2 and r16 (for carry purpose)
CLR r2
CLR r16

; initialize the sbox index loop in r26
LDI r18,0x00                        ; r18 = 00

; BEGIN compute MaskedSbox(x) = Sbox(x+r20)+r21 for every x starting from r19 to r19-1 (mod 256)
sboxLoop:
MOV   r16,r19                        ; r16 = r19 = x
EOR   r16,r20                        ; r16 = x + sbox_mask_input
MOV   r17, mask_multiplicative_inverse
RCALL GF256_mult                     ; r16 = (x + sbox_mask_input) * mask_multiplicative_inverse
MOVW  r30,r22                        ;   Z = #sbox
ADD   r30,r16
ADC   r31,r2                         ;   Z = #(sbox + r16)
LPM   r16,Z                          ; r16 = sbox((x + sbox_mask_input) * mask_multiplicative_inverse)
MOV   r17, mask_multiplicative
RCALL GF256_mult                     ; r16 = mask_multiplicative * sbox(x * mask_multiplicative_inverse + sbox_mask_input)
EOR   r16,r21                        ; r16 = mask_multiplicative * sbox(x * mask_multiplicative_inverse + sbox_mask_input) + sbox_mask_output 
MOVW  r26, r24
ADD   r26, r19
ADC   r27, r2                        ; X = #maskedSBox(r19)
ST    X,r16                          ; X  <- mask_multiplicative * sbox((x+ sbox_mask_input) * mask_multiplicative_inverse) + sbox_mask_output
INC   r19                            ; increment sbox index
INC   r18                            ; increment loop index
BRNE  sboxLoop                       ; loop until r18 = 0
; END compute MaskedSbox(x) = Sbox((x+r20)*r14)*r13+r21 for every x

CLR r20
CLR r21
CLR r22
CLR r23

RET


;----------------------------------------------------------------------------------------------------
;-------------------------          loadMasks          ----------------------------------------------
;----------------------------------------------------------------------------------------------------
loadMasks:
; load the 18 mask bytes from r19||r18 (pointer given at input of the AES function) to #masksState
; REQUIRE: r19||r18 must equal the masks input pointer given at input of the AES function
; NOTE: X, Y, r20, r0 are modified
; COMPLEXITY: xxx cycles

; load RAM address of masksState in r30:r31 (register Z)
LDI r30,lo8(masksState)
LDI r31,hi8(masksState)

; load RAM address of input masks in r26:r27 (register X)
LDI r26,lo8(mask)                       ; X = #masks
LDI r27,hi8(mask)

LDI r20, 16                             ; loop index
loop_loadMasks:
LD r21,X+
ST Z+, r21
DEC r20
BRNE loop_loadMasks

CLR r21

RET


;----------------------------------------------------------------------------------------------------
;-----------------------------     loadAndMaskInput     ---------------------------------------------
;----------------------------------------------------------------------------------------------------
loadAndMaskInput:
; load 16 bytes of the AES input from RAM 
; then multiply each byte with mask_multiplicative  
; and  xor each byte with the respective mask values (stored in masksState) 
; the masked bytes are stored in maskedState
; SECURITY: access are done in random order (specified in permIndices)
; REQUIRE: X must contain the AES input address and loadMasks must have been runned prior this call
;          also buildMultiplicativeMasks must have been called prior to the call 
;           also buildIndicesPermutation must have been called prior to the call
; NOTE: X,Y r0, r1, r16 to r23 and r26 to r29 are modified
; RECALL: #maskedState = #input
; COMPLEXITY: xxx cycles

LDI  r20, lo8(input)            ; r21||r20 = #input
LDI  r21, hi8(input)
LDI  r22, lo8(masksState)       ; r23||r22 = #masksState
LDI  r23, hi8(masksState)

CLR  r0                         ; to deal with carry propagation
MOV  r17, mask_multiplicative

LDI  r19, 0x0F                  ; loop index = i

loop_loadAndMaskInput:
LDI  r26, lo8(permIndices)
LDI  r27, hi8(permIndices)
ADD  r26, r19                    
ADC  r27, r0                    ;  X = #permIndices (i) 
LD   r1, X                      ; r1 = permIndices (i) = random index

MOVW r26, r20                   ;  X = #input
ADD  r26, r1
ADC  r27, r0                    ; X = # (input + i)
LD   r16, X                     ; r16 = input[i]
RCALL GF256_mult                ; r16 = input[i]*mask_multiplicative

MOVW r28, r22                   ; Y = #masksState
ADD  r28, r1
ADC  r29, r0                    ; Y = # (masksState + i)
LD   r18, Y                     ; r18 = masksState[i]

EOR  r16, r18                   ; r16 = input[i]*mask_multiplicative + masksState[i]

ST   X, r16                     ; maskedState[i] = input[i]*mask_multiplicative + masksState[i];

DEC  r19
BRNE loop_loadAndMaskInput

; case r19 = 0
LDI  r26, lo8(permIndices)
LDI  r27, hi8(permIndices)
ADD  r26, r19                   ; 
ADC  r27, r0
LD   r1, X                      ; r1 = random index

MOVW r26, r20
ADD  r26, r1
ADC  r27, r0                    ; X = # (input + i)
LD   r16, X                     ; r16 = input[i]

RCALL GF256_mult                ; r16 = input[i]*mask_multiplicative

MOVW r28, r22
ADD  r28, r1
ADC  r29, r0                    ; Y = # (masksState + i)
LD   r18, Y                     ; r17 = masksState[i]

EOR  r16, r18                   ; r16 = input[i]*mask_multiplicative + masksState[i]

ST   X, r16                     ; maskedState[i] = input[i]*mask_multiplicative + masksState[i];

CLR r16
CLR r17

RET

;----------------------------------------------------------------------------------------------------
;-----------------------------     loadAndMaskKey       ---------------------------------------------
;----------------------------------------------------------------------------------------------------
loadAndMaskKey:
; load 16 bytes of the AES key from RAM (address contained in X register)
; and multiply each byte with the multiplicative mask value 
; the masked key is stored in keyState 
; SECURITY: access are done in random order (specified in permIndices)
; REQUIRE: X must contain the AES input address 
;          also buildMultiplicativeMasks must have been called prior to the call 
;           also buildIndicesPermutation must have been called prior to the call
; NOTE: X,Y,Z, r0, r16, r17, r18, r20-r24 are modified, r25 is used and re-stored

LDI  r20, lo8(secret)            ; X = #input
LDI  r21, hi8(secret)
LDI  r24, lo8(keyState)          ; Z = #keyState
LDI  r25, hi8(keyState)

CLR  r0                          ; to deal with carry propagation
MOV  r17, mask_multiplicative



LDI  r19, 0x0F                  ; 
loop_loadAndMaskKey:

LDI  r26, lo8(permIndices)
LDI  r27, hi8(permIndices)
ADD  r26, r19                   ; 
ADC  r27, r0
LD   r1, X                      ; r1 = random index

MOVW r26, r20
ADD  r26, r1
ADC  r27, r0                    ; X = # (secret + i)

LD   r16, X                     ; r16 = secret[i]
RCALL GF256_mult                ; r16 = secret[i]*mask_multiplicative

MOVW r30, r24
ADD  r30, r1
ADC  r31, r0                    ; Z = # (keyState + i)
ST   Z, r16                     ; maskedState[i] = secret[i]*mask_multiplicative 

DEC  r19
BRNE loop_loadAndMaskKey

; case r19 = 0
LDI  r26, lo8(permIndices)
LDI  r27, hi8(permIndices)
ADD  r26, r19                   ; 
ADC  r27, r0
LD   r1, X                      ; r1 = random index

MOVW r26, r20
ADD  r26, r1
ADC  r27, r0                    ; X = # (secret + i)

LD   r16, X                     ; r16 = secret[i]
RCALL GF256_mult                ; r16 = secret[i]*mask_multiplicative

MOVW r30, r24
ADD  r30, r1
ADC  r31, r0                    ; Z = # (keyState + i)
ST   Z, r16                     ; maskedState[i] = secret[i]*mask_multiplicative 


CLR r16
CLR r17

RET

;----------------------------------------------------------------------------------------------------
;-------------------------         orderFromOneToTwo             ------------------------------------
;----------------------------------------------------------------------------------------------------
orderFromOneToTwo:
; INPUT: none
; GOAL : compute  maskedState [i] = maskedState [i] ^ masksState [(i + 4) % 16] in random order
;        this allows to artificially create a second order masking scheme for the Mix-Columns
;        operation.
; COMPLEXITY: ...

PUSH r24
PUSH r25
LDI r20, lo8 (maskedState)
LDI r21, hi8 (maskedState)
LDI r28, lo8(permIndices)
LDI r29, hi8(permIndices)
LDI r24, lo8 (masksState)
LDI r25, hi8 (masksState)
CLR r19
LDI r17, 16
LDI r16, 4

loop_orderOneToTwo:
LD     r18, Y+                 ; r18 = rand
MOVW   r26, r20
ADD    r26, r18
ADC    r27, r19                ; X = # maskedState [rand]        
MOVW   r30, r24
ADD    r18, r16
ANDI   r18, 15                 ; r18 = (rand + 4) % 16
ADD    r30, r18
ADC    r31, r19                ; Z = # masksState [(rand + 4) % 16]
LD     r18, X
LD     r15, Z                     
EOR    r18, r15                ; r18 =  maskedState [rand] ^ masksState [(rand + 4) % 16]
ST     X, r18                  ; maskedState [rand] = maskedState [rand] ^ masksState [(rand + 4) % 16]
DEC    r17
BRNE   loop_orderOneToTwo

POP    r25
POP    r24
RET

;****************************************************************************************************
;*******************************            AES ENCRYPTION        ***********************************
;****************************************************************************************************
asm_maskedAES128enc:
; main function asm_maskedAES128enc
; INPUT: 3 arguments stored in global variables "input", "key" and "masks" respectively
; OUTPUT: output is returned in "input" (which is therefore erased)
; NOTE: all arrays are 16 bytes long except masks which contains 18 bytes
; NOTE: the key is not overwritten but not the input
; COMPLEXITY: 82 437 cycles (current version)
; 

;--------------------------------------------------
;save context (68 cycles)
;call macro saveContext (64 cycles)
saveContext

;--------------------------------------------------
; Pre-Compute a random permutation over GF(16)
RCALL buildIndicesPermutation

;--------------------------------------------------
; Generate the multiplicative masks mask_multiplicative and mask_multiplicative_inverse
RCALL buildMultiplicativeMask

;--------------------------------------------------
; Pre-Compute the masked sbox and store the new sbox in maskedSbox (3852 cycles)
;restore address of masks from stack
RCALL computeAndStoreMaskedSbox

;--------------------------------------------------
; Load mask values and plaintext bytes, mask the plaintext 
; and store them in masksState and maskedState respectively
RCALL loadMasks
RCALL loadAndMaskInput
RCALL loadAndMaskKey
PUSH  mask_multiplicative
PUSH  mask_multiplicative_inverse

;--------------------------------------------------
; First AddRoundKey
; initialize the AES round counter with 11, from now on, r25 should never be manipulated!
LDI registerRoundCounter,0x0B
RCALL addRoundKey


;--------------------------------------------------
; BEGIN loop over the 10 AES rounds 
;--------------------------------------------------
; -- maskedSubBytes
; -- ShiftRows
; -- MixColumns (except for the last round)
; -- AddRoundKey
; NOTE: ShiftRows and MixColumns are performed for 
;       the maskedState and the masksState in random
;       order.
; NOTE: loop index has been previously stored in 
;       registerRoundCounter
DEC registerRoundCounter
loopAESRounds:
;--------------------------------------------------
; masked SubBytes
; -- Security:
; -- -- masked SubByte (order 1)
; -- -- processing in random order
RCALL maskedSubBytes


;--------------------------------------------------
; ShiftRows
; -- for the masked state
; -- load RAM address of maskedState in r20:r21
; -- load RAM address of permIndices in Y = r28:r29
; -- Security:
; -- -- processing in random order one different permutation for each of the two calls
LDI r20, lo8 (maskedState)
LDI r21, hi8 (maskedState)
LDI r28, lo8(permIndices)
LDI r29, hi8(permIndices)
RCALL shiftRows
; -- for the masks state
; -- load RAM address of masksState in r20:r21
; -- load RAM address of permIndices in Y = r28:r29
LDI r20, lo8 (masksState)
LDI r21, hi8 (masksState)
LDI r28, lo8(permIndicesBis)
LDI r29, hi8(permIndicesBis)
RCALL shiftRows

;test if this is the last round and performs MixColumns otherwise
MOV  r20,registerRoundCounter
DEC  r20
BREQ noMixColumns

;--------------------------------------------------
; MixColumns
; -- for the masked state
; -- load RAM address of maskedState in Y = r28:r29
; -- Security:
; -- -- processing in random order one different permutation for each of the two calls
; -- -- 2nd order masking
; BEGIN First order masking to 2nd order masking
RCALL    orderFromOneToTwo
; END First order masking to 2nd order masking
LDI r28, lo8 (maskedState)
LDI r29, hi8 (maskedState)
LDI r26, lo8(permIndices)
LDI r27, hi8(permIndices)
RCALL mixColumns
; -- for the masks state
; -- load RAM address of masksState in Y = r28:r29
LDI r28, lo8 (masksState)
LDI r29, hi8 (masksState)
LDI r26, lo8(permIndicesBis)
LDI r27, hi8(permIndicesBis)
RCALL mixColumns
; BEGIN First order masking to 2nd order masking
RCALL    orderFromOneToTwo
; END First order masking to 2nd order masking

noMixColumns:
RCALL keyExpansion

;--------------------------------------------------
; AddRoundKey
RCALL addRoundKey


;--------------------------------------------------
; Unmasking of maskedState and loading into #ciphertext (address in the stack
POP  mask_multiplicative_inverse
POP  mask_multiplicative
PUSH mask_multiplicative
PUSH mask_multiplicative_inverse

DEC registerRoundCounter                       ; decrement round counter
BRNE loopAESRounds                             ; and continue if registerRoundCounter != 0
;--------------------------------------------------
; END loop over the 10 AES rounds
;--------------------------------------------------

;--------------------------------------------------
; Unmasking of maskedState and loading into #ciphertext (address in the stack)
; RECALL: #maskedState = #input = #output
LDI r26,lo8(input)
LDI r27,hi8(input)
LDI r28,lo8(masksState)
LDI r29,hi8(masksState)

POP  mask_multiplicative_inverse
POP  mask_multiplicative

MOV    r17, mask_multiplicative_inverse

LDI r20, 16                 ; loop index = i
loop_final_unmasking:
LD    r16, Y+               ; r16 = masksState[i]
LD    r18, X                ; r18 = maskedState[i]
EOR   r16, r18              ; r16 = masksState[i] ^ masksState[i] = output[i]*mask_multiplicative
RCALL GF256_mult            ; process r16*r17 = output[i]
ST    X+, r16               ;  X <- output[i] 
DEC   r20
BRNE  loop_final_unmasking

;call macro loadContext (64 cycles)
loadContext

RET

;--------------------------------------------------
;-------------- END OF FILE    -----------------------
;--------------------------------------------------
