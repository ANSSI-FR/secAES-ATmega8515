/*
	Simple Operating System for Smartcard Education
	Copyright (C) 2002  Matthias Bruestle <m@mbsks.franken.de>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*! @file
	\brief Configuration settings.

	$Id: config.h,v 1.27 2003/03/30 12:42:21 m Exp $
*/

#ifndef SOSSE_CONFIG_H
#define SOSSE_CONFIG_H

/* Configuration defines */

/*! \brief En-/disables true random generator. <B>Highly experimental!</B>

	If set to 1, a true random number generator is included. This is
	currently only for test purposes and highly experimental!
*/
#define CONF_WITH_TRNG			0

/*! \brief En-/disables test commands.

	If set to 1, commands READ EEPROM and WRITE EEPROM are included.
*/
#define CONF_WITH_TESTCMDS		1

/* EEPROM addresses */

/*! \brief EEPROM address of the state of the card.

	This is currently unused.

	<EM>Warning: When using interrupts on the AVR, this byte may accidentally
	be changed. See errata sheets of AVR.</EM>
*/
#define CARD_STATE_ADDR		0x0000

//! EEPROM address of the ATR length.
#define ATR_LEN_ADDR		(CARD_STATE_ADDR+1)
//! Max. length of the ATR
#define ATR_MAXLEN			28
//! EEPROM address of the ATR.
#define ATR_ADDR			(ATR_LEN_ADDR+1)

//! EEPROM address of the serial number of the card.
#define SERNUM_ADDR			(ATR_ADDR+ATR_MAXLEN)
//! Length of the serial number.
#define SERNUM_LEN			8

//! EEPROM address of the state of the PRNG.
#define RAND_STATE_ADDR		(SERNUM_ADDR+SERNUM_LEN)
//! Length of the state of the PRNG. (Counter[8], State[8], Key[16])
#define RAND_STATE_LEN		8+8+16

//! Dummy address to handle the ifdefs here.
#define DATA_END_1			(RAND_STATE_ADDR+RAND_STATE_LEN)

#if defined(__AVR_ATmega163__)
//! This is a little endian architecture.
#define ENDIAN_LITTLE
//! Size of the internal EEPROM
#define EEPROM_SIZE                     0x200
//! Size of the RAM.
#define RAM_SIZE                        0x400
//! Chip ID.
#define CHIP                            0x02 // FIXME - assign new chip ID
//! External EEPROM ID.
#define ESIZ                            0x03
//! AVR architecture. Needed for assembler.
#define ARCH                            avr5

#elif defined(__AVR_ATmega8515__)
//! This is a little endian architecture.
#define ENDIAN_LITTLE
//! Size of the internal EEPROM
#define EEPROM_SIZE                     0x200
//! Size of the RAM.
#define RAM_SIZE                        0x400
//! Chip ID.
#define CHIP                            0x02 // FIXME - assign new chip ID
//! External EEPROM ID.
#define ESIZ                            0x03
//! AVR architecture. Needed for assembler.
#define ARCH                            avr4

#else
#error Unknown destination platform.

#endif

#endif /* SOSSE_CONFIG_H */

