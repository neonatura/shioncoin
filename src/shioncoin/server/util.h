
#ifndef __UTIL_H__
#define __UTIL_H__

#include "common.h"

#include "netbase.h" // for AddTimeData


void AddTimeData(const CNetAddr& ip, int64 nTime);

template<typename T>
uint256 SerializeHash(const T& obj, int nVersion = 1)
{
	int nType = SER_GETHASH;

	CHashWriter ss(nType, nVersion);
	ss << obj;
	return ss.GetHash();
}


#endif /* ndef __UTIL_H__ */

