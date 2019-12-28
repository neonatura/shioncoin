
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
 *
 *  This file is part of Shioncoin.
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

#ifndef __SHCOIND_LOG_H__
#define __SHCOIND_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif


#define SHERR_INFO -199


#define shcoind_log(_text) \
  (f_shcoind_log(0, "Info", _text, __FILE__, __LINE__))

#define shcoind_err(_err, _tag, _text) \
  (f_shcoind_log(_err, _tag, _text, __FILE__, __LINE__))

#define shcoind_info(_tag, _text) \
  (f_shcoind_log(SHERR_INFO, _tag, _text, __FILE__, __LINE__))

#define shcoind_netlog(_node, _cmd) \
	(f_shcoind_log_net(GetCoinByIndex( \
			(_node)->ifaceIndex)->name, (_node)->addr.ToString().c_str(), \
			(_cmd)->pchCommand, (_cmd)->nMessageSize, __FILE__, __LINE__))

void f_shcoind_log(int err_code, const char *tag, const char *text, const char *src_fname, long src_line);

void f_shcoind_log_net(const char *iface, const char *addr, const char *tag, size_t size, const char *src_fname, long src_line);

void timing_init(char *tag, shtime_t *stamp_p);

void timing_term(int ifaceIndex, char *tag, shtime_t *stamp_p);


#ifdef __cplusplus
}
#endif

#endif /* ndef __SHCOIND_LOG_H__ */
