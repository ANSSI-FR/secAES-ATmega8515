;*                                                                           
;*****************************************************************************
;*                                                                          
;*                  MODULE : AES128-ENC PRIMITIVE                         
;*                                                                          
;*****************************************************************************
;*****************************************************************************
;*                                                                            
;* File : maskedAES128enc.s                                                   
;*                                                                            
;* Project :  Test Vehicule                                                   
;*                                                                            
;* Description: AES encryption function with the following security features  
;*           -->  linear steps protected with first-order masking
;*                (one mask per state byte)
;*           -->  sbox processing protected with the table-recomputation method
;*                (see [Koc99]) 
;*           -->  shuffling of sbox processing and linear processing
;            -->  --> ShiftRows is performed in random order on each byte of the state 
;            -->  --> --> entropy = 1 among 16
;            -->  --> MixColumns is performed in random order on each column index
;            -->  --> --> entropy = 1 among 4
;*           -->  the key-scheduling is unprotected.
;*                                                   
;* Bibliography: [Koc99], [RPD09], [CJRR99]
;*                                                                           
;*---------------------------------------------------------------------------
;* Author(s): V. LOMNE, E. PROUFF, T. ROCHE                                  
;*                                                                           
;*---------------------------------------------------------------------------
;* the inputs "message", "key" and "mask" are assumed to be stored in global 
;*            variables, "input", "key" and "mask" respectively.
;* the output is directly stored in the global variable "input"             
;*
;* arrays are defined in "aesTables.h" for temporary storing of intermediate 
;* data:
;*    - unsigned char secret           [16];
;*    - unsigned char input            [16];
;*    - unsigned char mask             [18];
;*                                                     
;*    - unsigned char masksState       [16];
;*    - unsigned char keyState         [16];
;*      
;*    - unsigned char zeroValue        [37];   //needed for storing the 
;*                                             //maskedSbox Table at an 
;*                                             //address with lsb null.
;*    - unsigned char maskedSbox       [256];  //recomputed s-box
;*    - unsigned char permIndices      [16];   //shuffling array
;*    - unsigned char t_permShiftRows  [16];   //temporary array
;*
;* do not erase these registers:
;*    - Rcon[0] stored in r24
;*    - round counter stored in r25
;*----------------------------------------------------------------------------
;* Perfs: 38037 cycles
;*----------------------------------------------------------------------------
;* Historic                                                                   
;*----------------------------------------------------------------------------
;* V 1.00 | 16/03/14 | First  version (DPA book implementation)     
;* V 2.00 | 23/03/14 | Second version (18 masks instead of 6)       
;* V 2.01 | 18/05/14 | Improved to avoid BUS leakage during SubBytes    
;* V 3.00 | 28/11/14 | Operations Shuffling    
;* V 3.01 | 17/02/15 | keyExpansion on the fly    
;* V 3.02 | 20/05/15 | Code Cleaning    
;*****************************************************************************

.global asm_maskedAES128enc

#define registerRcon r24
#define registerRoundCounter r25



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

;****************************************************************************************************
;*******************************            MACROS                ***********************************
;****************************************************************************************************

;----------------------------------------------------------------------------------------------------
;------------------------------  MACRO saveContext         ------------------------------------------
;----------------------------------------------------------------------------------------------------
.MACRO saveContext
; save all register values into the stack 
; COMPLEXITY: 64 cycles
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
;------------------------------  MACRO loadContext         ------------------------------------------
;----------------------------------------------------------------------------------------------------
.MACRO loadContext
; load all register values from the stack 
; COMPLEXITY: 64 cycles
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


;----------------------------------------------------------------------------------------------------
;------------------------------  MACRO loadData         ------------------------------------------
;----------------------------------------------------------------------------------------------------
.MACRO loadData
; load 16 bytes of data from RAM (address contained in X register) into r0 to r15
; REQUIRE: X must contain the source address
; NOTE: registers r0 to r15 and X are modified
; COMPLEXITY: 32 cycles
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
LD r13,X+
LD r14,X+
LD r15,X+
.ENDM

;----------------------------------------------------------------------------------------------------
;------------------------------  MACRO storeData           ------------------------------------------
;----------------------------------------------------------------------------------------------------
.MACRO storeData
; save 16 bytes of data into RAM (address contained in X register) from r0 to r15
; REQUIRE: X must contain the source address
; NOTE: registers r0 to r15 and X are modified
; COMPLEXITY: 32 cycles
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
.ENDM

;****************************************************************************************************
;*******************************            AES PRIMITIVES        ***********************************
;****************************************************************************************************

;----------------------------------------------------------------------------------------------------
;------------------------------  Key expansion subroutine  ------------------------------------------
;----------------------------------------------------------------------------------------------------
keyExpansion:
; performs the AES keyExpansion corresponding to the ith round and updates the register registerRcon 
; REQUIRE: the previous round key bytes must be in r0-r15, register registerRcon must contain the AES round constant
; NOTE: registers r0-r15, r16, r17, r18, r19, Z are modified
; COMPLEXITY: 124 cycles

;compute the round key
MOV r18,registerRoundCounter
LDI r19,0x0B
SUB r19,r18                                 ; r19 = 11 - registerRoundCounter
LDI r30,lo8(Rcon)
LDI r31,hi8(Rcon)
CLR r1                                      ; to deal with the carry propagation during the following process
ADD r30, r19
ADC r31, r1
LPM registerRcon, Z                         ; registerRcon = AES round constant of index r19

;load keyState in r0 to r15 (33 cycles)
LDI r26,lo8(keyState)
LDI r27,hi8(keyState)
loadData

; BEGIN Process the transformation (r0,r1,r2,r3) <-- (sbox(r13)^Rcon[i],sbox(r14),sbox(r15),sbox(r12))
LDI r16,lo8(sbox)
LDI r17,hi8(sbox)
CLR r18                                      ; to deal with the carry propagation during the following process
CLR r19                                      ; SECURITY: to prevent Hamming distance leakage

; 1st element
MOVW r30,r16                                 ; Z = #sbox
ADD  r30,r13
ADC  r31,r18                                 ; Z -> Key[13]
LPM  r19,Z                                   ; r19 = Key[13]
EOR  r0,registerRcon
EOR  r0,r19                                  ; r0  = Key[13] xor Rcon[i]

; 2nd element
MOVW r30,r16                                 ; Z = #sbox
ADD  r30,r14
ADC  r31,r18                                 ; Z -> Key[14]
LPM  r19,Z                                   ; r19 = Key[14]
EOR  r1,r19                                  ; r1  = Key[14]

; 3rd element
MOVW r30,r16                                 ; Z = #sbox
ADD  r30,r15
ADC  r31,r18                                 ; Z -> Key[14]
LPM  r19,Z                                   ; r19 = Key[14]
EOR  r2,r19                                  ; r1  = Key[14]

; 4th element
MOVW r30,r16                                 ; Z = #sbox
ADD  r30,r12
ADC  r31,r18                                 ; Z -> Key[14]
LPM  r19,Z                                   ; r19 = Key[14]
EOR  r3,r19                                  ; r1  = Key[14]
; END Process the transformation of the 4th column of the AES keyState

; BEGIN Process the transformation of the 3 other columns
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
;store the content of r0 - r15 in "keyState" (32 cycles)
storeData

RET

;----------------------------------------------------------------------------------------------------
;-------------------------       maskedSubBytes         ---------------------------------------------
;----------------------------------------------------------------------------------------------------
maskedSubBytes:
; perform masked SubBytes
; NOTE: X, r16-r24, r0-r5 are modified
; COMPLEXITY: 674 cycles


;load RAM address of maskedSbox in r16:r17
LDI   r16,lo8 (maskedSbox)
LDI   r17,hi8 (maskedSbox)
LDI   r18,lo8 (masksState)
LDI   r19,hi8 (masksState)
LDI   r20,lo8 (input)
LDI   r21,hi8 (input)
; init Y with the address of permIndices
LDI   r28,lo8 (permIndices)            ; Y = #permIndices
LDI   r29,hi8 (permIndices)

CLR    r0                              ; FOR SECURITY ONLY: clear rO
CLR    r1                              ; FOR SECURITY ONLY: clear r1
CLR    r2                              ; FOR SECURITY ONLY: clear r2 
CLR    r3                              ; FOR SECURITY ONLY: clear r3 
CLR    r5                              ; clear r5  (for adding carry)

; load RAM address of masksState in X = r26:r27
LDI   r26,lo8(mask)                    ; X = #masks
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

MOV   r27,r17
MOV   r26,r24                          ; FOR SECURITY ONLY:  X  = #maskedSbox
LD     r0,  X                          ; FOR SECURITY ONLY:  r0 = sbox (0)  + sbox_output_mask

MOV   r26,r22                          ; X  = #maskedSbox
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

//INC    r4
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
; performs shiftRows on a 16-bytes array whose adress has been stored in Y register
; REQUIRE: Y must equal the address of the shiftRows input
; NOTE: registers r0, -r16-r31 are modified, r25 is re-stored
; COMPLEXITY: 725 cycles

PUSH r25            ; r25 contains the AES round counter

MOVW r20, r28       ; address of the state on which to apply ShiftRows
LDI  r22, lo8(t_permShiftRows)
LDI  r23, hi8(t_permShiftRows)
LDI  r24, lo8(permIndices)
LDI  r25, hi8(permIndices)

CLR r0               ; to deal with carry propagation
LDI r16, 16          ; loop index = i
LDI r17, 15          ; loop index to address tables = x
loop_shiftRows:
MOVW r26, r24       ; X = #permIndices
ADD  r26, r17
ADC  r27, r0
LD   r18, X         ; r18 = permIndices(x) = random index
MOVW r26, r20
ADD  r26, r18
ADC  r27, r0
LD   r19, X         ; r19 = state(permIndices(x))
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
ST   X, r19         ; t_permShiftRows(permIndices(x)) = state(permIndices(x))
DEC  r17
DEC  r16
BRNE loop_shiftRows

LDI r20, lo8(t_shiftRows)
LDI r21, hi8(t_shiftRows)

LDI r16, 16          ; loop index = i
LDI r17, 15          ; loop index to address tables = x
loop_shiftRowsBis:
MOVW r26, r24        ; X = #permIndices
ADD  r26, r17
ADC  r27, r0
LD   r18, X          ; r18 = permIndices(x) = random index
MOVW r26, r22
ADD  r26, r18
ADC  r27, r0
LD   r19, X          ; r19 = t_permShiftRows(permIndices(x))
MOVW r30, r20        ; Z = #t_shiftRows
ADD  r30, r18
ADC  r31, r0
LPM  r18, Z          ; r18 = t_shiftRows(permIndices(x))
MOVW r26, r28        ; address of the state on whic to apply ShiftRows
ADD  r26, r18
ADC  r27, r0
ST   X, r19          ; state(t_shiftRows(permIndices(x))) = t_permShiftRows(permIndices(x))
DEC  r17
DEC  r16
BRNE loop_shiftRowsBis

POP r25              ; r25 contains the AES round counter
RET

;----------------------------------------------------------------------------------------------------
;-------------------------         mixColumns             -------------------------------------------
;----------------------------------------------------------------------------------------------------
mixColumns:
; perform mixColumns operation on a state matrix whose address has been stored in Y
; REQUIRE: Y must equal the address of the shiftRows input
; NOTE: r0, r1, r2, r3, r4, r5, r16-r22 are modified. Z and Y are manipulated
; COMPLEXITY: 383 cycles

; BEGIN SECURITY pre_treatment
; erase contents of registers r0-r3 (to prevent HD leakages)
CLR r0
CLR r1
CLR r2
CLR r3
CLR r4                                   ; will be used to add carries
CLR r5                                   ; will be used to propagate carry
CLR r30
CLR r31
; END SECURITY pre_treatment

LDI r16,lo8(xtime)                       ; save the adress of xtime table into r17||r16
LDI r17,hi8(xtime)
LDI  r26, lo8(mask)
LDI  r27, hi8(mask)
ADIW r26, 0x10                           ; X = #mask + 16
LD   r22, X
ANDI r22, 0x03                           ; r22 random value in [0..3] = rand
LSL  r22
LSL  r22                                 ; r22 equals the first coordinate of a random column (of index rand)
MOVW r20, r28                            ; r21||r20 = #input_state

; BEGIN processing of the column of index rand (=r22)
MOV  r19, r22                            ; r19 = 4*rand
MOVW r28, r20                            ; Y = #input_state
ADD  r28, r19
ADC  r29, r4                             ; Y = # of the column of input_state to process
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
LPM  r0, Z                                 ; r0  = 0                                        -> r0 = xtime (Y[0] + Y[1])
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
; END processing of the column of index rand (=r22)

; BEGIN processing of the column of index rand^1 (=r22^1)
MOV  r19, r22                            ; r19 = 4*rand
MOVW r28, r20                            ; Y = #input_state
LDI  r18, 4
EOR  r19, r18
ADD  r28, r19
ADC  r29, r4                             ; Y = # of the column of input_state to process
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
LPM  r0, Z                                 ; r0  = 0                                        -> r0 = xtime (Y[0] + Y[1])
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
; END processing of the column of index rand^1 (=r22^1)

; BEGIN processing of the column of index rand^2 (=r22^2)
MOV  r19, r22                            ; r19 = 4*rand
MOVW r28, r20                            ; Y = #input_state
LDI  r18, 8
EOR  r19, r18
ADD  r28, r19
ADC  r29, r4                             ; Y = # of the column of input_state to process
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
LPM  r0, Z                                 ; r0  = 0                                        -> r0 = xtime (Y[0] + Y[1])
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
; END processing of the column of index rand^2 (=r22^2)

; BEGIN processing of the column of index rand^3 (=r22^3)
MOV  r19, r22                            ; r19 = rand
MOVW r28, r20                            ; Y = #input_state
LDI  r18, 12
EOR  r19, r18
ADD  r28, r19
ADC  r29, r4                             ; Y = # of the column of input_state to process
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
LPM  r0, Z                                 ; r0  = 0                                        -> r0 = xtime (Y[0] + Y[1])
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
; END processing of the column of index rand^3 (=r22^3)


; BEGIN SECURITY post-treatment
; erase the contents of r0-r3 and Y
CLR r0
CLR r1
CLR r2
CLR r3
CLR r19
; END SECURITY post-treatment

RET

;----------------------------------------------------------------------------------------------------
;-----------------------------     addRoundKey subroutine    ----------------------------------------
;----------------------------------------------------------------------------------------------------
addRoundKey:
; add the AES round key in a random order specified by permIndices
; REQUIRE: sub-functions roundKeysDerivation and buildIndicesPermutation must have been runned prior this call
; X, Y, Z, r16, r17, r18, , r19, r20, r21, r22, r23, r24 are modified
; perf: 302 cycles

;add the offset to address of "arrayTempKeys"
LDI r22,lo8(keyState)
LDI r23,hi8(keyState)

LDI r20, lo8(input)
LDI r21, hi8(input)

LDI r30, lo8(permIndices)
LDI r31, hi8(permIndices)

CLR r19                                     ; to deal with mask propagation
LDI r24, 16                                 ; loop index
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


;****************************************************************************************************
;*******************************   SECURITY PRE-PROCESSING PRIMITIVES            ********************
;****************************************************************************************************

;----------------------------------------------------------------------------------------------------
;------------------------------   buildIndicesPermutation  ------------------------------------------
;----------------------------------------------------------------------------------------------------
buildIndicesPermutation:
; build a random permutation permIndices over GF(16) from the fixed permutation permGFSixteen and the two first masks of table mask
; Let F = permIndices, G = permGFSixteen, m1||m0 = mask[0] and m3||m2 = mask[1]
; F(x) = G(G(G(G(x^m0)^m1)^m2)^m3) 
; NOTE: r16, r17, r18, r19, r20, r21, r22, , r23, r26, r27, r30, r31
; COMPLEXITY: 604 cycles
LDI  r26,lo8(mask)
LDI  r27,hi8(mask)
LD   r16, X+
MOV  r17, r16
ANDI r16, 0x0F
SWAP r17
ANDI r17, 0x0F  
LD   r18, X
MOV  r19,r18
ANDI r18, 0x0F
SWAP r19
ANDI r19, 0x0F
LDI  r26,lo8(permIndices)              ; X = #permIndices
LDI  r27,hi8(permIndices)
LDI  r30,lo8(permGFSixteen)            ; Z = #permGFSixteen
LDI  r31,hi8(permGFSixteen)
MOVW r20,r30                           ; r21||r20 = #permGFSixteen

; initialize the index loop in r24
LDI r23, 0x0f			; r23 = x
LDI r24, 0x10           ; loop index
CLR r2                  ; to deal with carry propagation

; BEGIN compute MaskedSbox(x) = Sbox(x+r0)+r1 for very x
permIndicesLoop:
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
DEC r23                                 ; decrement x
DEC r24                                 ; decrement loop index
BRNE permIndicesLoop                    ; loop until r24 = 0

CLR  r16
CLR  r17
MOVW r18, r16
MOVW r20, r18
MOVW r22, r20
MOVW r24, r22
MOVW r26, r24
MOVW r30, r26

RET

;----------------------------------------------------------------------------------------------------
;--------------------          computeAndStoreMaskedSbox            ---------------------------------
;----------------------------------------------------------------------------------------------------
computeAndStoreMaskedSbox:
; compute S( x + sbox_mask_input) + sbox_mask_output for every x and store it at address #maskedSbox
; NOTE: registers 18-2, X, and Z are modified
; REQUIRE: the least significant byte of the address maskedSbox must be 0!
; COMPLEXITY: 3608 cycles

; get the masks sbox_mask_input and sbox_mask_output corresponding to masks[16] and masks[17]
LDI r30,lo8(mask)                         ; Z = #masks
LDI r31,hi8(mask)
ADIW r30,16                               ; Z = #masks + 16
LD r20,Z+                                 ; r20 = sbox_mask_input
LD r21,Z                                  ; r21 = sbox_mask_output

; load RAM address of sbox in registers r18:r19
LDI r18,lo8(sbox)
LDI r19,hi8(sbox)

; load RAM address of maskedSbox in X = r26:r27 
LDI r26,lo8(maskedSbox)
LDI r27,hi8(maskedSbox)

; clear r2 (for carry purpose)
CLR r2
; clear r22 (for security purpose)
CLR r22

; initialize the sbox index loop in r16
LDI r26,0x00                     ; r16 = x

; BEGIN compute MaskedSbox(x) = Sbox(x+r0)+r1 for every x
sboxLoop:
MOV  r22,r26
EOR  r22,r20                     ; r3 = x + r0
MOVW r30,r18                     ; Z = #sbox
ADD  r30,r22
ADC  r31,r2                      ; Z = #(sbox + r3)
LPM  r22,Z                       ; r3 = sbox(x + r0)
EOR  r22,r21                     ; r3 = sbox(x + r0) + r1 
ST   X,r22                       ; Y <- sbox(x + r0) + r1 and Y++
INC  r26                         ; increment sbox index
BRNE sboxLoop                    ; loop until r26 = 0
; END compute MaskedSbox(x) = Sbox(x+r0)+r1 for every x
CLR r20
CLR r21
CLR r22

RET


;----------------------------------------------------------------------------------------------------
;-------------------------          loadMasks          ----------------------------------------------
;----------------------------------------------------------------------------------------------------
loadMasks:
; load the 18 mask bytes from #mask to #masksState
; REQUIRE: r19||r18 must equal the masks input pointer given at input of the AES function
; NOTE: X, Y, r20, r21 are modified
; COMPLEXITY: 124 cycles

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
; load 16 bytes of the AES input from RAM ("input" global variable)
; and xor each byte with the respective mask values (in masksState)
; the masked bytes are stored in maskedState
; REQUIRE: loadMasks must have been runned prior this call 
; NOTE: X,Y,Z, r0, r16, r17, r18, r20-r24 are modified
; COMPLEXITY: 383 cycles

LDI  r20, lo8(input)            ; X = #input --> #maskedState
LDI  r21, hi8(input)
LDI  r22, lo8(masksState)       ; Y = #masksState
LDI  r23, hi8(masksState)

CLR  r0                         ; to deal with carry propagation

LDI  r18, 16                    ; loop counter i
LDI  r19, 0x0F                  ; 
loop_loadAndMaskInput:
LDI  r26, lo8(permIndices)
LDI  r27, hi8(permIndices)
ADD  r26, r19                   ; 
ADC  r27, r0
LD   r1, X                      ; r1 = random index
MOVW r26, r20
ADD  r26, r1
ADC  r27, r0
MOVW r28, r22
ADD  r28, r1
ADC  r29, r0
LD   r16, X                     ; r16 = input[i]
LD   r17, Y                     ; r17 = masksState[i]
EOR  r16, r17                   ; r16 = input[i] + masksState[i]
ST   X, r16                     ; maskedState[i] = input[i] + masksState[i]
DEC  r19
DEC  r18                        ; i--
BRNE loop_loadAndMaskInput

CLR r16
CLR r17

RET

;****************************************************************************************************
;*******************************            AES ENCRYPTION        ***********************************
;****************************************************************************************************
asm_maskedAES128enc:
; main function asm_maskedAES128enc
; INPUT: 3 arguments stored in global variables "input", "key", "masks"
; OUTPUT: the ciphertext is stored in "input"
; NOTE: all arrays are 16 bytes long except masks which contains 18 bytes
; NOTE: the key is not overwritten, the input is.
; COMPLEXITY: 38 037 cycles

;--------------------------------------------------
;save context (64 cycles)
saveContext
;--------------------------------------------------

;load master key in r0 to r15 (32 cycles)
LDI r26,lo8(secret)
LDI r27,hi8(secret)
loadData

;load address of "keyState"
LDI r26,lo8(keyState)
LDI r27,hi8(keyState)
;store first round key in "keyState" (32 cycles)
storeData

;--------------------------------------------------
; Pre-Compute a random permutation over GF(16) (604 cycles)
RCALL buildIndicesPermutation

;--------------------------------------------------
; Pre-Compute the masked sbox and store the new sbox 
; into maskedSbox (3608 cycles)
; restore address of masks from stack
RCALL computeAndStoreMaskedSbox

;--------------------------------------------------
; Load mask values (124 cycles) and plaintext bytes, 
; then mask the plaintext and store them in masksState 
; and maskedState (383 cycles) respectively
RCALL loadMasks
RCALL loadAndMaskInput

;--------------------------------------------------
; First AddRoundKey
; initialize the AES round counter with 11, from 
; now on, r25 should never be manipulated!
LDI registerRoundCounter,0x0B
RCALL addRoundKey

;--------------------------------------------------
; BEGIN loop over the 10 AES rounds 
;--------------------------------------------------
; -- maskedSubBytes                                  --> 674 cycles
; -- ShiftRows                                       --> 725 cycles each call
; -- MixColumns (except for the last round)          --> 383 cycles each call
; -- AddRoundKey                                     --> 302 cycles
; NOTE: ShiftRows and MixColumns are performed for the maskedState and the masksState
; NOTE: AES round index has been previously stored in registerRoundCounter
DEC registerRoundCounter

loopAESRounds:
;--------------------------------------------------
; masked SubBytes
RCALL maskedSubBytes

;--------------------------------------------------
; ShiftRows
; -- for the masked state
; -- load RAM address of masksState in Y = r28:r29
LDI r28, lo8 (input)
LDI r29, hi8 (input)
RCALL shiftRows
; -- for the masks state
; -- load RAM address of masksState in Y = r28:r29
LDI r28, lo8 (masksState)
LDI r29, hi8 (masksState)
RCALL shiftRows

;test if this is the last round and performs MixColumns otherwise
MOV  r20,registerRoundCounter
DEC  r20
BREQ noMixColumns

;--------------------------------------------------
; MixColumns
; -- for the masked state
; -- load RAM address of maskedState in Y = r28:r29
LDI r28, lo8 (input)
LDI r29, hi8 (input)
RCALL mixColumns
; -- for the masks state
; -- load RAM address of masksState in Y = r28:r29
LDI r28, lo8 (masksState)
LDI r29, hi8 (masksState)
RCALL mixColumns

;--------------------------------------------------
; AddRoundKey
noMixColumns:
RCALL keyExpansion
RCALL addRoundKey

DEC registerRoundCounter                       ; decrement round counter
BRNE loopAESRounds                             ; and continue if registerRoundCounter != 0
;--------------------------------------------------
; END loop over the 10 AES rounds
;--------------------------------------------------

;--------------------------------------------------
; Unmasking of maskedState and loading into #ciphertext (address in the stack)
LDI r28,lo8(masksState)
LDI r29,hi8(masksState)
LDI r30,lo8(input)
LDI r31,hi8(input)

LDI r20, 16
loop_final_unmasking:
LD  r16, Y+
LD  r17, Z
EOR r16, r17
ST  Z+, r16
DEC r20
BRNE loop_final_unmasking

;call macro loadContext (64 cycles)
loadContext

RET

;--------------------------------------------------
;-------------- END OF FILE	-----------------------
;--------------------------------------------------
