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

/* $Id: main.c,v 1.31 2002/12/24 13:33:11 m Exp $ */

/*! @file
	\brief main() function with command loop.
*/

#include <config.h>
#include <commands.h>
#include <sw.h>
#include <hal.h>
#include <t0.h>

/*! \brief Main function containing command interpreter loop.

	At the end of the loop, sw is sent as the status word.

	This function does never return.
*/
int main( void )
{
	iu8 i, len, b;

	/* TODO: On error? */
	hal_init();

	/* Send ATR */
	/* TODO: Possible from EEPROM? */
	hal_io_sendByteT0( 0x3B );

#if CONF_WITH_LOGGING==1
	log_init();
#endif

	resplen = 0;

	if( !(hal_eeprom_read( &len, ATR_LEN_ADDR, 1 ) &&
		(len<=ATR_MAXLEN)) )
		for(;;) {}

	for( i=1; i<len; i++ ) {
		if( !hal_eeprom_read( &b, ATR_ADDR+i, 1 ) ) for(;;) {}
		hal_io_sendByteT0( b );
	}

	/* Command loop */
	for(;;) {
		for( i=0; i<5; i++ ) {
			header[i] = hal_io_recByteT0();
		}

#if CONF_WITH_TRNG==1
		hal_rnd_addEntropy();
#endif

		if( (header[0]&0xFC)==CLA_PROP ) {
			switch( header[1]&0xFE ) {
#if CONF_WITH_TESTCMDS==1
			case INS_WRITE:
				cmd_write();
				break;
			case INS_READ:
				cmd_read();
				break;
#endif /* CONF_WITH_TESTCMDS==1 */
			case INS_SET_KEY:
				cmd_set_key();
				break;
			case INS_GET_KEY:
				cmd_get_key();
				break;
			case INS_SET_INPUT:
				cmd_set_input();
				break;
			case INS_GET_INPUT:
				cmd_get_input();
				break;
			case INS_SET_MASK:
				cmd_set_mask();
				break;
			case INS_GET_MASK:
				cmd_get_mask();
				break;
			case INS_AES128_ENC:
				cmd_aes128_enc();
				break;
			case INS_GET_OUTPUT:
				cmd_get_output();
				break;
			default:
				t0_sendWord( SW_WRONG_INS );
			}
		} else {
			t0_sendWord( SW_WRONG_CLA );
		}

#if CONF_WITH_TRNG==1
		hal_rnd_addEntropy();
#endif

		/* Return the SW in sw */
		t0_sendSw();
	}
}

