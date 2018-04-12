#include <config.h>

;       .arch   at90s8515
        .arch   atmega16
; TRIG PIN is PB5
TRIG_PIN=5
PINB=0x16
DDRB=0x17
PORTB=0x18
        .text
        .global trig_high, trig_low

trig_low:
        ; Set OUT direction
        sbi             DDRB, TRIG_PIN
	; Signal low
	cbi             PORTB, TRIG_PIN
	ret

trig_high:
        ; Set OUT direction
        sbi             DDRB, TRIG_PIN
	; Signal low
	sbi             PORTB, TRIG_PIN
	ret
