
/*
 * @copyright
 *
 *  Copyright 2014 Brian Burrell
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

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef __SERVER__PROTOCOL_H__
#define __SERVER__PROTOCOL_H__

#include "serialize.h"
#include "netbase.h"
#include <string>
//#include "../proto.h"
#include "uint256.h"

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
	public:

		CMessageHeader();
		CMessageHeader(int ifaceIndex, const char* pszCommand, unsigned int nMessageSizeIn);

		std::string GetCommand() const;
		bool IsValid(int ifaceIndex) const;

		IMPLEMENT_SERIALIZE
			(
			 READWRITE(FLATDATA(pchMessageStart));
			 READWRITE(FLATDATA(pchCommand));
			 READWRITE(nMessageSize);
			 READWRITE(nChecksum);
			)

		enum {
			MESSAGE_START_SIZE=4,
			COMMAND_SIZE=12,
			MESSAGE_SIZE_SIZE=sizeof(int),
			CHECKSUM_SIZE=sizeof(int),

			MESSAGE_SIZE_OFFSET=MESSAGE_START_SIZE+COMMAND_SIZE,
			CHECKSUM_OFFSET=MESSAGE_SIZE_OFFSET+MESSAGE_SIZE_SIZE
		};

		char pchMessageStart[MESSAGE_START_SIZE];
		char pchCommand[COMMAND_SIZE];
		unsigned int nMessageSize;
		unsigned int nChecksum;
};

/** nServices flags */
enum
{
	NODE_NETWORK = (1 << 0),
	NODE_GETUTXO = (1 << 1),
	NODE_BLOOM = (1 << 2),
	NODE_WITNESS = (1 << 3)
};

/** A CService with information about it as peer */
class CAddress : public CService
{
	public:
		uint64 nServices;

		// disk and network only
		unsigned int nTime;

		// memory only
		mutable int64 nLastTry;

		CAddress() : CService()
	{
		Init();
	}

		explicit CAddress(CService ipIn, uint64 nServicesIn = NODE_NETWORK) : CService(ipIn)
	{
		Init();
		nServices = nServicesIn;
	}

		void Init()
		{
			nServices = NODE_NETWORK;
			nTime = 100000000;
			nLastTry = 0;
		}

		IMPLEMENT_SERIALIZE
			(
			 CAddress* pthis = const_cast<CAddress*>(this);
			 CService* pip = (CService*)pthis;
			 if (fRead)
			 pthis->Init();
			 if (nType & SER_DISK)
			 READWRITE(nVersion);
			 if ((nType & SER_DISK) ||
				 (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
			 READWRITE(nTime);
			 READWRITE(nServices);
			 READWRITE(*pip);
			)

			void print() const;

};

/** inv message data */
class CInv
{
	public:
		int type;
		uint256 hash;
		mutable int ifaceIndex;

		CInv();
		CInv(int ifaceIndex, int typeIn, const uint256& hashIn);
		CInv(int ifaceIndex, const std::string& strType, const uint256& hashIn);

		IMPLEMENT_SERIALIZE
			(
			 READWRITE(type);
			 READWRITE(hash);
			)

			friend bool operator<(const CInv& a, const CInv& b);

		bool IsKnownType() const;
		std::string GetCommand() const;
		std::string ToString() const;
		void print() const;
};

#endif /* __SERVER__PROTOCOL_H__ */

