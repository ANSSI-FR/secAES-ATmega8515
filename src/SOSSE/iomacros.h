/*
   Copyright (C) 1999 Marek Michalkiewicz <marekm@linux.org.pl>

   Permission to use, copy, modify, and distribute this software and
   its documentation for any purpose and without fee is hereby granted,
   without any conditions or restrictions.  This software is provided
   "as is" without express or implied warranty.
 */

#ifndef _IOMACROS_H_
#define _IOMACROS_H_

#include <inttypes.h>

#ifndef BV
  #define BV(x) (1 << (x))
#endif

/* Memory mapped I/O - use for non-constant I/O space addresses.  */

#define __mmio(port) (*((volatile uint8_t *)((uint8_t)(port) + 0x20)))

/* Macros for access to 8-bit I/O registers with constant address.  */

#define __inb(port) ({				\
	uint8_t t;				\
	asm volatile (				\
		"in %0, %1"			\
		: "=r" (t)			\
		: "I" ((uint8_t)(port))		\
	);					\
	t;					\
 })

/* XXX - order of parameters is confusing, but it is probably too late
   to change now, should be (port, val) - destination on the left side,
   as in memset and C assignment operators.  */

#define __outb(val, port)			\
	asm volatile (				\
		"out %1, %0"			\
		: /* no outputs */		\
		: "r" ((uint8_t)(val)),		\
		  "I" ((uint8_t)(port))		\
	)

#define __outb_zero(port)			\
	asm volatile (				\
		"out %0, __zero_reg__"		\
		: /* no outputs */		\
		: "I" ((uint8_t)(port))		\
	)

/* Macros for access to 8-bit I/O registers (auto detect const address).  */

#define inp(port) (__builtin_constant_p((port)) ? __inb((port)) : __mmio((port)))

/*TR ADD: replace outp by __outp to avoid double definition */
#define __outp(val, port) do {				\
	if (__builtin_constant_p((port))) {		\
		if (__builtin_constant_p((val)) && ((val) == 0)) \
			__outb_zero((port));		\
		else					\
			__outb((val), (port));		\
	} else						\
		__mmio((port)) = (val);			\
 } while (0)

/* Macros for access to 16-bit I/O registers (ADC, ICR1, OCR1, TCNT1) -
   read low byte first, then high byte (from the TEMP register),
   write high byte first (to the TEMP register), then low byte.
   If used from interrupts as well as from the main program, disable
   interrupts first, or use the *_atomic versions (avoid interrupts
   in the middle of operation - there is only one TEMP register).  */

#define __inw(port) ({					\
	uint16_t t;					\
	asm volatile (					\
		"in %A0, %1" "\n\t"			\
		"in %B0, (%1)+1"			\
		: "=r" (t)				\
		: "I" ((uint8_t)(port))			\
	);						\
	t;						\
 })

#define __inw_atomic(port) ({				\
	uint16_t t;					\
	asm volatile (					\
		"in __tmp_reg__, __SREG__" "\n\t"	\
		"cli" "\n\t"				\
		"in %A0, %1" "\n\t"			\
		"in %B0, (%1)+1" "\n\t"			\
		"out __SREG__, __tmp_reg__"		\
		: "=r" (t)				\
		: "I" ((uint8_t)(port))			\
	);						\
	t;						\
 })

#define __outw(val, port)				\
	asm volatile (					\
		"out (%1)+1, %B0" "\n\t"		\
		"out %1, %A0"				\
		: /* no outputs */			\
		: "r" ((uint16_t)(val)),		\
		  "I" ((uint8_t)(port))			\
	)

#define __outw_atomic(val, port)			\
	asm volatile (					\
		"in __tmp_reg__, __SREG__" "\n\t"	\
		"cli" "\n\t"				\
		"out (%1)+1, %B0" "\n\t"		\
		"out %1, %A0" "\n\t"			\
		"out __SREG__, __tmp_reg__"		\
		: /* no outputs */			\
		: "r" ((uint16_t)(val)),		\
		  "I" ((uint8_t)(port))			\
	)

/* __cbi / __sbi require constant port < 0x20 and constant bit */

#define __cbi(port, bit)				\
	asm volatile (					\
		"cbi %0, %1"				\
		: /* no outputs */			\
		: "I" ((uint8_t)(port)),		\
		  "I" ((uint8_t)(bit))			\
	)

#define __sbi(port, bit)				\
	asm volatile (					\
		"sbi %0, %1"				\
		: /* no outputs */			\
		: "I" ((uint8_t)(port)),		\
		  "I" ((uint8_t)(bit))			\
	)

/* __port_and / __port_or work with any constant port */

#define __port_and(port, val)				\
	asm volatile (					\
		"in __tmp_reg__, %0" "\n\t"		\
		"and __tmp_reg__, %1" "\n\t"		\
		"out %0, __tmp_reg__"			\
		: /* no outputs */			\
		: "I" ((uint8_t)(port)),		\
		  "r" ((uint8_t)(val))			\
	)

#define __port_or(port, val)				\
	asm volatile (					\
		"in __tmp_reg__, %0" "\n\t"		\
		"or __tmp_reg__, %1" "\n\t"		\
		"out %0, __tmp_reg__"			\
		: /* no outputs */			\
		: "I" ((uint8_t)(port)),		\
		  "r" ((uint8_t)(val))			\
	)

/* __cbi_const_port / __sbi_const_port work with const or non-const bit */

#define __cbi_const_port(port, bit) do {		\
	if (((port) < 0x20) && __builtin_constant_p((bit))) \
		__cbi((port), (bit));			\
	else						\
		__port_and((port), ~BV((bit)));		\
 } while (0)

#define __sbi_const_port(port, bit) do {		\
	if (((port) < 0x20) && __builtin_constant_p((bit))) \
		__sbi((port), (bit));			\
	else						\
		__port_or((port), BV((bit)));		\
 } while (0)

/* General cbi / sbi macros - work with any (const or non-const) data.  */

#define cbi(port, bit) do {				\
	if (__builtin_constant_p((port)))		\
		__cbi_const_port((port), (bit));	\
	else						\
		__mmio((port)) &= ~BV((bit));		\
 } while (0)

#define sbi(port, bit) do {				\
	if (__builtin_constant_p((port)))		\
		__sbi_const_port((port), (bit));	\
	else						\
		__mmio((port)) |= BV((bit));		\
 } while (0)

#endif /* _IOMACROS_H_ */

