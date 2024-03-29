
#include "shcoind.h"
#include "block.h"
#include "versionbits.h"
#include "algobits.h"
#include "sync.h"

static CCriticalSection cs_vcache;

static VersionBitsCache _version_bits_cache[MAX_COIN_IFACE];

const struct BIP9DeploymentInfo VersionBitsDeploymentInfo[MAX_VERSION_BITS_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
    },
    {
        /*.name =*/ "csv",
        /*.gbt_force =*/ true,
    },
    {
        /*.name =*/ "segwit",
        /*.gbt_force =*/ false,
    },
		{
			/* .name = */ "reserved_0",
			/* .gbt_force = */ false
		},
		{
			/* .name = */ "reserved_1",
			/* .gbt_force = */ false
		},
		{
			/* .name = */ "reserved_2",
			/* .gbt_force = */ false
		},
		{
			/* .name = */ "algo",
			/* .gbt_force = */ false
		},
		{
			/* .name = */ "param",
			/* .gbt_force = */ false
		},
		{
			/* .name = */ "bolo",
			/* .gbt_force = */ false
		}
};

VersionBitsCache *GetVersionBitsCache(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE) {
    return (NULL);
  }

  return (&_version_bits_cache[ifaceIndex]);
}

ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex *pindexPrev, CIface *params, DeploymentPos pos) const
{
	VersionBitsCache *vcache = GetVersionBitsCache(params);
	int ifaceIndex = GetCoinIndex(params);
  int nPeriod = Period(params);
  int nThreshold = Threshold(params);
  int64_t nTimeStart = BeginTime(params);
  int64_t nTimeTimeout = EndTime(params);
	ThresholdState state = THRESHOLD_DEFINED;

	if (!vcache) return state;
	{
		LOCK(cs_vcache);

		ThresholdConditionCache& cache = vcache->caches[pos];

		// A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
		if (pindexPrev != NULL) {
			pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
		}

		// Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
		std::vector<const CBlockIndex*> vToCompute;
		while (cache.count(pindexPrev) == 0) {
			if (pindexPrev == NULL) {
				// The genesis block is by definition defined.
				cache[pindexPrev] = THRESHOLD_DEFINED;
				break;
			}
			if (pindexPrev->GetMedianTimePast() < nTimeStart) {
				// Optimization: don't recompute down further, as we know every earlier block will be before the start time
				cache[pindexPrev] = THRESHOLD_DEFINED;
				break;
			}
			vToCompute.push_back(pindexPrev);
			pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
		}

		// At this point, cache[pindexPrev] is known
	//  assert(cache.count(pindexPrev));
		state = cache[pindexPrev];

		// Now walk forward and compute the state of descendants of pindexPrev
		while (!vToCompute.empty()) {
			ThresholdState stateNext = state;
			pindexPrev = vToCompute.back();
			vToCompute.pop_back();

			switch (state) {
				case THRESHOLD_DEFINED: 
					{
						if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
							stateNext = THRESHOLD_FAILED;
						} else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
							stateNext = THRESHOLD_STARTED;
						}
						break;
					}
				case THRESHOLD_STARTED: 
					{
						if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
							stateNext = THRESHOLD_FAILED;
							break;
						}
						bool fAlgo = false;
						if (ifaceIndex == TEST_COIN_IFACE ||
								ifaceIndex == TESTNET_COIN_IFACE ||
								ifaceIndex == SHC_COIN_IFACE ||
								ifaceIndex == COLOR_COIN_IFACE)
							fAlgo = true;
						// We need to count
						const CBlockIndex* pindexCount = pindexPrev;
						int count = 0;
						int idx = 0;
						while (pindexCount && idx < nPeriod) {
							if (!fAlgo || !IsAlgoBitsMask(pindexCount->nVersion)) {
								if (Condition(pindexCount, params)) {
									count++;
								}
								idx++;
							}
							pindexCount = pindexCount->pprev;
						}
						if (count >= nThreshold) {
							stateNext = THRESHOLD_LOCKED_IN;
						}
						break;
					}
				case THRESHOLD_LOCKED_IN: 
					{
						// Always progresses into ACTIVE.
						stateNext = THRESHOLD_ACTIVE;
						break;
					}
				case THRESHOLD_FAILED:
				case THRESHOLD_ACTIVE:
					{
						// Nothing happens, these are terminal states.
						break;
					}
			}
			cache[pindexPrev] = state = stateNext;
		}
	}

  return state;
}

namespace
{
  /**
   * Class to implement versionbits logic.
   */
  class VersionBitsConditionChecker : public AbstractThresholdConditionChecker {
    private:
      const DeploymentPos id;

    protected:
      int64_t BeginTime(CIface * params) const { return params->vDeployments[id].nStartTime; }
      int64_t EndTime(CIface * params) const { return params->vDeployments[id].nTimeout; }
      int Period(CIface * params) const { return params->nMinerConfirmationWindow; }
      int Threshold(CIface * params) const { return params->nRuleChangeActivationThreshold; }

      bool Condition(const CBlockIndex* pindex, CIface * params) const
      {
        return (((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & Mask(params)) != 0);
      }

    public:
      VersionBitsConditionChecker(DeploymentPos id_) : id(id_) {}
      uint32_t Mask(CIface * params) const { return ((uint32_t)1) << params->vDeployments[id].bit; }
  };

}

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, CIface * params, DeploymentPos pos)
{
  return VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, pos);
}

uint32_t VersionBitsMask(CIface * params, DeploymentPos pos)
{
  return VersionBitsConditionChecker(pos).Mask(params);
}

void VersionBitsCache::Clear()
{
  for (unsigned int d = 0; d < MAX_VERSION_BITS_DEPLOYMENTS; d++) {
    caches[d].clear();
  }
}


