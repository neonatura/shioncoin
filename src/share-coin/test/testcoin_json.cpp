
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

#include "test_shcoind.h"
#include <string>
#include <vector>
#include "wallet.h"
#include "test/test_pool.h"
#include "test/test_block.h"
#include "test/test_txidx.h"

#include "offer.h"
#include "asset.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace std;
using namespace json_spirit;

extern void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out);





#ifdef __cplusplus
extern "C" {
#endif


_TEST(jsonencap)
{

  /* generate JSON string. */
  CScript script;
  uint160 hash("0x1");
  script << OP_EXT_NEW << CScript::EncodeOP_N(0) << OP_HASH160 << hash << OP_2DROP << OP_RETURN;

  Object obj;
//  ScriptPubKeyToJSON(script, obj);
  obj.push_back(Pair("test", "value"));

  string strJson = write_string(Value(obj), false);
//              if (!read_string(strRequest, valRequest))
//fprintf(stderr, "DEBUG: jsonencap: strJson: %s\n", strJson.c_str());
  _TRUE(strJson.size() != 0);

}




#ifdef __cplusplus
}
#endif
