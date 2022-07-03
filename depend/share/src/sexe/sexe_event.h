


/*
 * @copyright
 *
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
 *
 *  @endcopyright
 */

#ifndef __SEXE__SEXE_EVENT_H__
#define __SEXE__SEXE_EVENT_H__



/**
 * Trigger a event to be handled with the object provided.
 */
int sexe_event_handle(lua_State *L, const char *e_name, shjson_t *json);

shkey_t *sexe_event_key(char *e_name);

unsigned int sexe_event_next_id(void);


#endif /* ndef __SEXE__SEXE_EVENT_H__ */

