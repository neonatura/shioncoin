
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

#ifndef __EXT__ENTITY_H__
#define __EXT__ENTITY_H__


class CEntity : public CExtCore
{
	public:
		shgeo_t geo;
		cbuff vAddr;
		unsigned int nType;

		CEntity()
		{
			SetNull();
		}

		CEntity(const CEntity& ent)
		{
			SetNull();
			Init(ent);
		}

		CEntity(string labelIn)
		{
			SetNull();
			SetLabel(labelIn);
		}

		IMPLEMENT_SERIALIZE (
				READWRITE(*(CExtCore *)this);
				READWRITE(FLATDATA(geo));
				READWRITE(this->vAddr);
				READWRITE(this->nType);
		)

		friend bool operator==(const CEntity &a, const CEntity &b)
		{
			return (
					((CExtCore&) a) == ((CExtCore&) b) &&
					0 == memcmp(&a.geo, &b.geo, sizeof(shgeo_t)) &&
					a.nType == b.nType &&
					a.vAddr == b.vAddr
					);
		}

		CEntity operator=(const CEntity &b)
		{
			SetNull();
			Init(b);
			return *this;
		}

		void SetNull()
		{
			CExtCore::SetNull();
			memset(&geo, 0, sizeof(geo));
			vAddr.clear();
			nType = 0;
		}

		void Init(const CEntity& b)
		{
			CExtCore::Init(b);
			memcpy(&geo, &b.geo, sizeof(geo));
			vAddr = b.vAddr;
			nType = b.nType;
		}

		void SetType(int nTypeIn)
		{
			nType = nTypeIn;
		}

		unsigned int GetType()
		{
			return (nType);
		}

		bool IsLocalRegion();

		uint160 GetHash();

		std::string ToString();

		Object ToValue();

		// virtual time_t GetMinimumLifespan()
		// virtual GetMinimumVersion
		// GetMaximumVersion() { return iface.MAJOR_VERSION }
};

class CTxOut;


bool IsLocalEntity(CIface *iface, const CTxOut& txout);


#endif /* ndef __EXT__ENTITY_H__ */

