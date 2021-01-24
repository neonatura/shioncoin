/*
 *  Copyright 2013 Neo Natura 
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __SHCRC_H__
#define __SHCRC_H__

/*
 *  @addtogroup libshare
 *  @{
 */

/**
 * Converts a memory segment into a checksum 64bit number hash code.
 * @param data The location of the data in physical memory.
 * @param len The length of the data in bytes.
 * @returns The hash code generated from the data content.
 */
uint64_t shcrc(void *data, size_t data_len);

/**
 * Convert a memory segment into a hexadecimal 64bit number hash code.
 */
char *shcrc_hex(void *data, size_t data_len);

/**
 * Converts a memory segment into a 32bit checksum.
 */
#define shcrc32(_data, _data_len) \
  (uint32_t)(shcrc((_data), (_data_len)) & 0xFFFFFFFF)

/**
 * Converts a memory segment into a 16bit checksum.
 */
#define shcrc16(_data, _data_len) \
  (uint16_t)(shcrc((_data), (_data_len)) & 0xFFFF)

/* Generates 16-bit endian-safe checksum number. */
uint16_t shcrc_htons(void *data, size_t data_len);

/**
 * Prints the checksum in a custom 56bit ascii code.
 */
char *shcrcstr(uint64_t crc);

/**
 * Generate a checksum from a shcrcstr() 56bit ascii code.
 */
uint64_t shcrcgen(char *str);



/**
 * @}
 */

#endif /* ndef __SHCRC_H__ */


