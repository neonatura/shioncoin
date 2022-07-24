
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

#ifndef __SERVER__LICENSE_H__
#define __SERVER__LICENSE_H__

/**
 * A license is a specific type of certification.
 * @note A license is not capable of having contextual data.
 */
class CLicense : public CCertCore
{

	public:

		CLicense()
		{
			SetNull();
		}

		CLicense(const CLicense& lic)
		{
			SetNull();
			Init(lic);
		}

		CLicense(const CCertCore& cert)
		{
			SetNull();
			CCertCore::Init(cert);
		}

		IMPLEMENT_SERIALIZE (
			READWRITE(*(CCertCore *)this);
		)

		void SetNull()
		{
			CCertCore::SetNull();
			nFlag |= SHCERT_CERT_LICENSE;
		}

		friend bool operator==(const CLicense &a, const CLicense &b) {
			return (
					((CCertCore&) a) == ((CCertCore&) b)
					);
		}

		CLicense operator=(const CLicense &b) 
		{
			SetNull();
			Init(b);
			return *this;
		}

		friend bool operator!=(const CLicense &a, const CLicense &b) {
			return !(a == b);
		}

		void Init(const CLicense& b)
		{
			CCertCore::Init(b);
		}

		void SetSerialNumber(cbuff vSerialIn)
		{
			vContext = vSerialIn;
		}

		/* a 128-bit binary context converted into a 160bit hexadecimal number. */
		std::string GetSerialNumber()
		{
			return (HexStr(vContext));
		}

		bool Sign(CCert *cert);

		bool Sign(int ifaceIndex);

		bool VerifySignature(int ifaceIndex, CCert *cert);

		bool VerifySignature(int ifaceIndex);

		int64 CalculateFee(CIface *iface);

		const uint160 GetHash()
		{
			uint256 hash = SerializeHash(*this);
			unsigned char *raw = (unsigned char *)&hash;
			cbuff rawbuf(raw, raw + sizeof(hash));
			return Hash160(rawbuf);
		}

		int VerifyTransaction();

//		void NotifySharenet(int ifaceIndex);

		std::string ToString();

		Object ToValue();

};


class CWalletTx;

int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, CWalletTx& wtx);

extern bool GetTxOfLicense(CIface *iface, const uint160& hash, CTransaction& tx);

cert_list *GetLicenseTable(int ifaceIndex);

bool IsLicenseTx(const CTransaction& tx);

bool CommitLicenseTx(CIface *iface, CTransaction& tx, int nHeight);

bool VerifyLicenseChain(CIface *iface, CTransaction& tx);

int64 GetLicenseOpFee(CIface *iface);

bool DecodeLicenseHash(const CScript& script, int& mode, uint160& hash);


#endif /* ndef __SERVER__LICENSE_H__ */

