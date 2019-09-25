
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
 *
 *  This file is part of ShionCoin.
 *  (https://github.com/neonatura/shioncoin)
 *        
 *  ShionCoin is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  ShionCoin is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ShionCoin.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#define __PROTO__PROTOCOL_C__

#include "shcoind.h"
#include "stratum/stratum.h"
#include "coin_proto.h"
#include "rpc/rpc_proto.h"

typedef int (*stratum_command_f)(CIface *, user_t *, shjson_t *, shjson_t **);

typedef struct stratum_command_t
{
	const char *method;
	stratum_command_f func;
} stratum_command_t;

static stratum_command_t stratum_command_table[] =
{
	{ "mining.capabilities", NULL },
	{ "mining.extranonce.subscribe", stratum_miner_extranonce_subscribe },
	{ "mining.get_transactions", stratum_miner_get_transactions },
	{ "mining.suggest_difficulty", NULL },
	{ "mining.suggest_target", NULL },

	{ NULL, NULL } /* terminator */
};

int stratum_command_api(int ifaceIndex, user_t *user, const char *method, shjson_t *param)
{
	CIface *iface;
	int i;
	
	iface = GetCoinByIndex(ifaceIndex);
	if (!iface || !iface->enabled)
		return (1);

	for (i = 0; stratum_command_table[i].method; i++) {
		if (0 == strcasecmp(stratum_command_table[i].method, method))
			break;
	}
	if (!stratum_command_table[i].method)
		return (1);

	int err = 0;
	{
		stratum_command_t *t = &stratum_command_table[i];
		shjson_t *reply = NULL;

		if (t->func != NULL) {
			err = (*t->func)(iface, user, param, &reply); 
		} 
		if (err) {
			reply = shjson_init(NULL);
			set_stratum_error(reply, err, sherrstr(err));
			shjson_null_add(reply, "result");
		} else if (!reply) {
			static char *json_data = "{\"result\":true,\"error\":null}";
			reply = shjson_init(json_data);
		}
		stratum_send_message(user, reply);
		shjson_free(&reply);
	}

	return (err);
}


