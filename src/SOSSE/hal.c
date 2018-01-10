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
	\brief HAL (Hardware Abstraction Layer).

	$Id: hal.c,v 1.22 2003/03/30 12:42:21 m Exp $
*/


/* Neue Makros wegen neuem avr-gcc */
#define outb(val, sfr) (_SFR_BYTE(sfr) = (val)) 
#define outp(val, sfr) outb(val, sfr) 
#define eeprom_rb(addr) eeprom_read_byte ((uint8_t *)(addr)) 
#define eeprom_wb(addr,val) eeprom_write_byte ((uint8_t *)(addr), (uint8_t)(val))  

#include <config.h>
#include <hal.h>
#include <avr/eeprom.h>
#include <avr/io.h>
#include <string.h>
#include <tools.h>
#include <types.h>
#include <iomacros.h>


#if CONF_WITH_TRNG==1
/* Random number gathering */
union {
	iu8 c[8];
	iu32 l[2];
} randdata;
iu8 randbytes;
#endif

void hal_init( void )
{

    
      ACSR  = 0x80;        // = 0x80;
      DDRA  = 0x00;        // = 0xFF;
      DDRB  = 0b00000000;  // = 0xFF;
      DDRC  = 0x00;        // = 0xFF;
      DDRD  = 0x00;        // = 0xFF;
      PORTA = 0xFF;        // = 0xFF;
      PORTB = 0b11111111;  // = 0xFF;
      PORTC = 0xFF;        // = 0xFF;
      PORTD = 0xFF;        // = 0xFF;
      /*                   
  
  outb(0x80,ACSR);
  outb(0xFF,DDRA);
  outb(0xFF,DDRB);
  outb(0xFF,DDRC);
  outb(0xFF,DDRD);
  outb(0xFF,PORTA);
  outb(0xFF,PORTB);
  outb(0xFF,PORTC);
  outb(0xFF,PORTD);
      */

#if CONF_WITH_TRNG==1
  /* Random number gathering */
  randbytes=0;
  TIMSK = 0;	//outp( 0, TIMSK );	/* Disable timer interrupts */
  TCNT0 = 0;	//outp( 0, TCNT0 );	/* Set timer 0 value */
  TCCR0 = 1;	//outp( 1, TCCR0 );	/* Start timer 0 */
#endif

  return;
}

/*	addr: r25:r24
	ret: r25(=0):r24
*/
extern iu8 xeread( iu16 addr );
/*	addr: r25:r24
	b: r22
*/
extern void xewrt( iu16 addr, iu8 b );

bool hal_eeprom_read( iu8 *dst, iu16 src, iu8 len )
{
	while( len-- ) {
		if( src<EEPROM_SIZE ) {
			/* Internal EEPROM */
			while( !eeprom_is_ready() ) {}

			*dst++ = eeprom_rb( src++ ); 
		       
			/**dst++ = eeprom_read_byte( src++ ); */
		       
#if CONF_WITH_I2CEEPROM==1
		} else {
			/* External I2C EEPROM */
			/* Subtract the size of the internal EEPROM to get the
			   location in external EEPROM.
			*/
			*dst++ = xeread( src-EEPROM_SIZE );
			src++;
#endif /* CONF_WITH_I2CEEPROM==1 */
		}
	}

	return TRUE;
}

/* TODO: Compare written data? Return 6581 on error. */
bool hal_eeprom_write( iu16 dst, iu8 *src, iu8 len )
{
	while( len-- ) {
		if( dst<EEPROM_SIZE ) {
			/* Internal EEPROM */
			while( !eeprom_is_ready() ) {}

				eeprom_wb( dst++, *src++ ); 
				/*eeprom_write_byte( dst++, *src++ );*/
#if CONF_WITH_I2CEEPROM==1
		} else {
			/* External I2C EEPROM */
			/* Subtract the size of the internal EEPROM to get the
			   location in external EEPROM.
			*/
			xewrt( dst-EEPROM_SIZE, *src++ );
			dst++;
#endif /* CONF_WITH_I2CEEPROM==1 */
		}
	}

	return TRUE;
}

/*	b: r25(=0):r24
*/
extern void sendbytet0( iu8 b );
/*	ret: r25(=0):r24
*/
extern iu8 recbytet0( void );

void hal_io_sendByteT0( iu8 b )
{
	sendbytet0( b );
	return;
}

iu8 hal_io_recByteT0( void )
{
	return recbytet0();
}

#if 1
bool hal_rnd_addEntropy( void )
{
	return 1;
}
#else
#if CONF_WITH_TRNG==1
bool hal_rnd_addEntropy( void )
{
	randdata.c[(randbytes++)&0x07] = inp( TCNT0 );	/* Read timer 0 */

	if( randbytes>7 ) {
		struct {
			iu32 state[2];
			iu32 key[4];
		} x917;

		randbytes=0;

		log_add( LOG_TAG_RANDOM, randdata.c, sizeof(randdata.c) );

		if( !hal_eeprom_read( (iu8*)x917.state, RAND_STATE_ADDR+8,
			sizeof(x917) ) )
			return FALSE;

		x917.state[0]=randdata.l[0]; 
		x917.state[1]=randdata.l[1];

		crypt_enc( x917.state, x917.key );

		if( !hal_eeprom_write( RAND_STATE_ADDR, (iu8*)x917.state,
			sizeof(x917.state) ) )
			return FALSE;
	}

	return TRUE;
}
#endif

//#if 0
/* This is left here in case more stringend memory limitations are present. */
/* We don't need to swap here bytes, because we just need random data. */
bool hal_rnd_getBlock( iu8 *dst )
{
	iu32 block[2], key[4];

	if( !( hal_eeprom_read( (iu8*)block, SERNUM_ADDR, SERNUM_LEN ) &&
		hal_eeprom_read( (iu8*)key, RAND_STATE_ADDR, sizeof(key) ) ) )
		return FALSE;

	key[2]=key[1];
	key[3]=key[0];

	crypt_enc( block, key );

	if( !hal_eeprom_write( RAND_STATE_ADDR, (iu8*)block, RAND_STATE_LEN ) )
		return FALSE;

	crypt_enc( block, key );

	memcpy( dst, block, sizeof(block) );

	return TRUE;
}
//#endif
#endif
