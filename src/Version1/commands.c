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
	\brief Commands.

	The documentation of the commands is on the main page of the doxygen
	documentation.

	$Id: commands.c,v 1.27 2003/03/30 12:42:21 m Exp $
*/

#include <hal.h>
#include <commands.h>
#include <config.h>
#include <log.h>
#include <stddef.h>
#include <string.h>
#include <sw.h>
#include <t0.h>
#include <tools.h>
#include <aesTables.h>
#include <maskedAES128enc.h>

#ifdef __AVR__
#include <avr/io.h>
#endif /* __AVR__ */

/*! \brief Valid data in response array. Invalid if zero. */
iu8 resplen;
/*! \brief Data returned by Get Response command.

	The size of this array is the max. of sizeof(S_FINFO) and CRYPT_BLOCK_LEN.
*/
iu8 response[8];

#if CONF_WITH_TESTCMDS==1
void cmd_write( void )
{
	iu8 b, i;

	if( t0_testP3( 0x00 ) ) {
		sw_set( SW_WRONG_LEN );
		return;
	}

	/* TODO: check for eeprom range */
	/* ACK */
	t0_sendAck();


	/* Receive */
	for( i=0; i<header[4]; i++ ) {
		///* ~ACK */
		//t0_sendCAck();

		/* Data */
		b = hal_io_recByteT0();

		if( !hal_eeprom_write( ((iu16)header[2]<<8)+header[3]+i, &b, 1 ) ) return;
	}

	sw_set( SW_OK );
}
#endif /* CONF_WITH_TESTCMDS==1 */

#if CONF_WITH_TESTCMDS==1
void cmd_read( void )
{
	iu16 i, max=header[4];
	iu8 b;

	/* TODO: check for eeprom range */

	/* ACK */
	t0_sendAck();

	if( !max ) max=256;
	for( i=0; i<max; i++ ) {
		if( !hal_eeprom_read( &b, (header[2]<<8)+header[3]+i, 1 ) ) return;

		/* Data */
		hal_io_sendByteT0( b );
	}

	/* SW */
	sw_set( SW_OK );
}
#endif /* CONF_WITH_TESTCMDS==1 */


/*! \brief Set the secret key in RAM.
*/
void cmd_set_key( void )
{
	
	if( t0_testP3( 0x00 ) ) {
		sw_set( SW_WRONG_LEN );
		return;
	}

	iu8 length=header[4];
	
	if(length>AESKeySize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}
	
	iu8 i, b;
	/* ACK */
	t0_sendAck();
	
	/* Receive */
	for( i=0; i<length; i++ ) {
		
		/* ~ACK */
		//t0_sendCAck();

		/* Data */
		b = hal_io_recByteT0();

		secret[i] = b;
	}
	
	/* ACK */
	//t0_sendAck();
	
	/* SW */
	sw_set( SW_OK );
}

/*! \brief Get the secret key stored in RAM.
*/
void cmd_get_key( void )
{
	iu16 i, length=header[4];
	iu8 b;
	
	/* ACK */
	t0_sendAck();
	
	if(length>AESKeySize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}

	for( i=0; i<length; i++ ) {
		b = secret[i];

		/* Data */
		hal_io_sendByteT0( b );
	}

	/* SW */
	sw_set( SW_OK );
}

/*! \brief Set the cipher input in RAM.
*/
void cmd_set_input( void )
{
	if( t0_testP3( 0x00 ) ) {
		sw_set( SW_WRONG_LEN );
		return;
	}

	iu8 length=header[4];
	
	if(length>AESInputSize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}
	
	iu8 i, b;
	/* ACK */
	t0_sendAck();
	
	/* Receive */
	for( i=0; i<length; i++ ) {
		
		/* ~ACK */
		//t0_sendCAck();

		/* Data */
		b = hal_io_recByteT0();

		input[i] = b;
	}
	
	/* ACK */
	//t0_sendAck();
	
	/* SW */
	sw_set( SW_OK );
}

/*! \brief Get the cipher input stored in RAM.
*/
void cmd_get_input( void )
{
	iu16 i, length=header[4];
	iu8 b;
	
	/* ACK */
	t0_sendAck();

	if(length>AESInputSize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}

	for( i=0; i<length; i++ ) {
		b = input[i];

		/* Data */
		hal_io_sendByteT0( b );
	}

	/* SW */
	sw_set( SW_OK );
}

/*! \brief Set the masks values in RAM.
*/
void cmd_set_mask( void )
{
	
	if( t0_testP3( 0x00 ) ) {
		sw_set( SW_WRONG_LEN );
		return;
	}

	iu8 length=header[4];
	
	if(length>AESMaskSize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}
	
	iu8 i, b;
	/* ACK */
	t0_sendAck();
	
	/* Receive */
	for( i=0; i<length; i++ ) {
		
		/* ~ACK */
		//t0_sendCAck();

		/* Data */
		b = hal_io_recByteT0();

		mask[i] = b;
	}
	
	/* ACK */
	//t0_sendAck();
	
	/* SW */
	sw_set( SW_OK );
}

/*! \brief Get the mask values stored in RAM.
*/
void cmd_get_mask( void )
{
	iu16 i, length=header[4];
	iu8 b;
	
	if(length>AESMaskSize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}
	/* ACK */
	t0_sendAck();

	for( i=0; i<length; i++ ) {
		b = mask[i];

		/* Data */
		hal_io_sendByteT0( b );
	}

	/* SW */
	sw_set( SW_OK );
}


/*! \brief Launch AES-128 encryption.
*/
void cmd_aes128_enc( void )
{
        
	iu16 length=header[4];
	
	if(length!=0){ 
		sw_set( SW_WRONG_LEN );
		return;
	}
	asm_maskedAES128enc();

	/* ACK */
	//t0_sendAck();
	
	/* SW */
	sw_set( SW_OK );
}

/*! \brief Get the cipher output stored in RAM.
*/
void cmd_get_output( void )
{
	iu16 i, length=header[4];
	iu8 b;
	
	/* ACK */
	t0_sendAck();

	if(length>AESOutputSize){ 
		sw_set( SW_WRONG_LEN );
		return;
	}
	for( i=0; i<length; i++ ) {
		b = input[i];

		/* Data */
		hal_io_sendByteT0( b );
	}

	/* SW */
	sw_set( SW_OK );
}

void cmd_getResponse( void )
{
	iu8 i;

	if( resplen==0 ) {
		sw_set( SW_WRONG_CONDITION );
		return;
	}

	if( !t0_testP3( resplen ) ) {
		if( (header[4]>resplen) || (!header[4]) ) {
			sw_set( SW_WRONG_LE|resplen );
			return;
		}
		/* User want's not all data */
		resplen=header[4];
	}

	if( !t0_testP1P2( 0x0000 ) ) return;

	/* ACK */
	t0_sendAck();

	/* Data */
	for( i=0; i<resplen; i++ ) {
		hal_io_sendByteT0( response[i] );
	}

	sw_set( SW_OK );
}
