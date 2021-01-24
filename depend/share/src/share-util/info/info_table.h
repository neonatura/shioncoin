

/*
 *  Copyright 2014 Neo Natura
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
 */  

#ifndef __SHARETOOL__INFO_TABLE_H__
#define __SHARETOOL__INFO_TABLE_H__


#define MAX_TABLE_COLUMNS 64


typedef struct info_table_row_t {
  char *col[MAX_TABLE_COLUMNS];
  struct info_table_row_t *next;
} info_table_row_t;

typedef struct info_table_t {
  info_table_row_t *row;
  info_table_row_t *row_head;
  char *label[MAX_TABLE_COLUMNS];
} info_table_t;


info_table_t *info_table_init(void);
void info_table_print(info_table_t *table, FILE *fout);


#endif /* ndef__SHARETOOL__INFO_TABLE_H__ */
