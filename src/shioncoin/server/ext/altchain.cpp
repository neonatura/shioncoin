
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#include "shcoind.h"
#include "json_spirit_reader_template.h"
#include "json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

#include "block.h"
#include "wallet.h"
#include "chain.h"
#include "txcreator.h"
#include "certificate.h"
#include "versionbits.h"
#include "altchain.h"
#include "altchain_color.h"
#include "txsignature.h"
#include "color/color_pool.h"
#include "color/color_block.h"

extern std::string HexBits(unsigned int nBits);
extern void ScriptPubKeyToJSON(int ifaceIndex, const CScript& scriptPubKey, Object& out);
extern json_spirit::Value ValueFromAmount(int64 amount);


altchain_list *GetAltChainTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapColor);
}

bool DecodeAltChainHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/activate/update) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) { 
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type (altchain) */
  if (op != OP_ALTCHAIN) {
    return false;
  }

  vector<unsigned char> vch;
  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  if (opcode != OP_HASH160)
    return (false);

  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  hash = uint160(vch);
  return (true);
}

bool IsAltChainOp(int op) {
	return (op == OP_ALTCHAIN);
}

string altchainFromOp(int op) {
	switch (op) {
	case OP_EXT_ACTIVATE:
		return "altchainactivate";
	case OP_EXT_UPDATE:
		return "altchainupdate";
	case OP_EXT_TRANSFER:
		return "altchaintransfer";
	case OP_EXT_REMOVE:
		return "altchainremove";
	default:
		return "<unknown altchain op>";
	}
}

bool DecodeAltChainScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/activate/update) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (altchain) */
  if (op != OP_ALTCHAIN)
    return false;

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

#if 0
	if ((mode == OP_EXT_NEW && vvch.size() == 2) ||
			(mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() == 2) ||
      (mode == OP_EXT_TRANSFER && vvch.size() == 2) ||
      (mode == OP_EXT_PAY && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
#endif
	return (true);
}

bool DecodeAltChainScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAltChainScript(script, op, vvch, pc);
}

CScript RemoveAltChainScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAltChainScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveAltChainScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetAltChainOpFee(CIface *iface)
{
	return ((int64)MIN_TX_FEE(iface) * 10);
}

bool IsAltChainTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ALTCHAIN)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeAltChainHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

bool IsLocalAltChain(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalAltChain(CIface *iface, const CTransaction& tx)
{
  if (!IsAltChainTx(tx))
    return (false); /* not a altchain */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalAltChain(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an altchain transaction.
 */
bool VerifyAltChain(CTransaction& tx, int& mode)
{
  uint160 hashAltChain;
  int nOut;

  /* core verification */
  if (!IsAltChainTx(tx))
    return (error(SHERR_INVAL, "VerifyAltChain: not an altchain tx"));

  /* verify hash in pub-script matches altchain hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
    return (false); /* no extension output */
  }

  if (!DecodeAltChainHash(tx.vout[nOut].scriptPubKey, mode, hashAltChain)) {
    return (false); /* no altchain hash in output */
  }

  CAltChain *altchain = tx.GetAltChain();

  if (hashAltChain != altchain->GetHash()) {
    return error(SHERR_INVAL, "VerifyAltChain: transaction references invalid altchain hash.");
    return (false); /* altchain hash mismatch */
  }

	for (int i = 0; i < altchain->vtx.size(); i++) {
		const CAltTx& alt_tx = altchain->vtx[i];
		/* auxilliary payload for color-specific coin implementations. */
		if (alt_tx.vchAux.size() > 4096) {
			return error(SHERR_INVAL, "VerifyAltChain: auxillary payload exceeds 4096 bytes.");
		}

		if ((int64)alt_tx.nLockTime > altchain->block.nTime)
			return error(SHERR_INVAL, "VerifyAltChain: rejecting non-final transaction.");

		BOOST_FOREACH(const CTxIn& txin, alt_tx.vin) {
			if (!txin.IsFinal())
				return false;
		}
	}

	/* label is not [currently] used, but still restricted in size. */
  if (altchain->GetLabel().size() > 135)
    return error(SHERR_INVAL, "VerifyAltChain: label exceeds 135 characters.");

  return (true);
}

static void ReorganizeColorPoolMap(CIface *iface, const uint160& hColor, const uint256& hashBlock)
{
  CWallet *wallet = GetWallet(iface);
	vector<CTransaction> vTx;
	CTxMemPool *pool;
	uint256 hPrevBlock;

	pool = GetTxMemPool(iface);
	if (!pool)
		return;

	if (wallet->mapColorPool.count(hColor) != 0)
		wallet->mapColorPool.erase(hColor);

	/* scan for altchain-tx's */
	vTx = pool->GetActiveTx();
	hPrevBlock = hashBlock;
	bool bFound = false;
	int nIndex = -1;
	while (1) {
		int idx;
		for (idx = 0; idx < vTx.size(); idx++) {
			const CTransaction& tx = vTx[idx];
			if (!IsAltChainTx(tx))
				continue;

			CAltChain *t_alt = tx.GetAltChain();
			if (!t_alt) continue;

			if (t_alt->block.hashPrevBlock == hPrevBlock) {
				hPrevBlock = t_alt->block.GetHash();
				wallet->mapColorPool[hColor] = hPrevBlock;
				break;
			}
		}
		if (idx == vTx.size())
			break;
	}

}

bool ConnectAltChainTx(CIface *iface, const CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAltChain *alt = tx.GetAltChain();

	if (!alt)
		return (false);


	uint256 hashBlock; /* "best" block in chain. */
	if (wallet->mapColor.count(alt->hColor) == 0) {

		/* un-established block-chain */
		if (alt->block.hashPrevBlock != 0)
			return (error(SHERR_INVAL, "ConnectAltChainTx: non-genesis block supplied for non-established alt-chain.")); 

		const uint256& hBlock = alt->block.GetHash();

		color_opt opt;
		ParseColorOptScript(opt, alt->vtx[0].vout[0].scriptPubKey); 	
		SetChainColorOpt(alt->hColor, opt);
		wallet->mapColorHead[hBlock] = alt->hColor;
	} else {
		hashBlock = wallet->mapColor[alt->hColor];
		bool bOrphan = false;
		/* already established block-chain */
		if (alt->block.hashPrevBlock != hashBlock) {
			if (wallet->mapColorPool.count(alt->hColor) == 0) {
				bOrphan = true;
			} else {
				const uint256& hashPoolBlock = wallet->mapColor[alt->hColor];
				if (alt->block.hashPrevBlock != hashPoolBlock) {
					bOrphan = true;
				}
			}
		}
		if (bOrphan) {
			return (false); /* orphan */
		}
	}

	wallet->mapColor[alt->hColor] = alt->block.GetHash();

	ReorganizeColorPoolMap(iface, alt->hColor, hashBlock);

//	Debug("(%s) ConnectAltChainTx: hashBlock \"%s\" (color: %s)", iface->name, hashBlock.GetHex().c_str(), alt->hColor.GetHex().c_str());

  return (true);
}

bool DisconnectAltChainTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAltChain *altchain = tx.GetAltChain();
	CBlockIndex *pindex;
	uint256 hashBlock;
	
	if (!altchain)
		return (false);

	/* get last block */
	if (wallet->mapColor.count(altchain->hColor) == 0)
		return (false); /* nothing to disconnect */

	hashBlock = wallet->mapColor[altchain->hColor];
	pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, hashBlock);
	if (!pindex)
		return (false);

	if (pindex->pprev) {
		wallet->mapColor[altchain->hColor] = pindex->pprev->GetBlockHash();
	} else {
		wallet->mapColor.erase(altchain->hColor);
	}

	return (true);
}

#if 0
bool RemoveAltChainTx(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAltChain *altchain = (CAltChain *)&tx.altchain;
  string strTitle = altchain->GetLabel();

  if (wallet->mapAltChain.count(strTitle) == 0)
    return (false);

  /* transition current into archive */
  const uint256& cur_tx = wallet->mapAltChain[strTitle];
  wallet->mapAltChainArch[cur_tx] = strTitle;

  /* erase current */
  uint256 blank_hash;
  wallet->mapAltChain[strTitle] = blank_hash;

  return (true);
}
#endif

#if 0
/**
 * Verify that the preceding input is the currently established altchain tx.
 */
bool VerifyAltChainChain(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CAltChain *altchain = &tx.altchain;
  string strLabel = altchain->GetLabel();
  CTransaction in_tx;

  if (wallet->mapAltChain.count(strLabel) == 0)
    return (false);

  const uint256& prev_hash = wallet->mapAltChain[strLabel];
  BOOST_FOREACH(const CTxIn& in, tx.vin) {
    const uint256& in_hash = in.prevout.hash;

    if (in_hash == prev_hash)
      return (true);

#if 0
    if (!GetTransaction(iface, in_hash, in_tx))
      return (false);

    if (!IsAltChainTx(in_tx))
      return (false);

    int nOut = IndexOfExtOutput(in_tx);
    if (nOut == -1)
      return (false);

    CAltChain *in_altchain = &in_tx.altchain;
    if (in_altchain->GetLabel() != altchain->GetLabel())
      return (false);
#endif

  }

  return (false);
}
#endif

static bool CommitNewAltChainTx(CIface *iface, CTransaction& tx, CNode *pfrom, bool fUpdate)
{
	CAltChain *alt;
	CBlock *block;
	int mode;

	if (!VerifyAltChain(tx, mode))
		return error(SHERR_INVAL, "CommitNewAltChainTx: error verifying altchain chain on tx '%s'.", tx.GetHash().GetHex().c_str());

	if (mode != OP_EXT_NEW && mode != OP_EXT_UPDATE)
		return (true); /* unsupported - soft error */

	alt = tx.GetAltChain();
	if (!alt)
		return (error(SHERR_INVAL, "CommitNewAltChainTx: transaction is not altchain-tx"));

	{
		CWallet *wallet = GetWallet(iface);

		/* dissolve pool references as we commit to disk block-chain. */
		if (wallet->mapColorPool.count(alt->hColor) != 0)
			wallet->mapColorPool.erase(alt->hColor);
	}

	if (!fUpdate) { /* run-time */
		CBlockIndex *pindexBest;

		pindexBest = GetBestColorBlockIndex(iface, alt->hColor);
		if (pindexBest) {
			if (alt->block.hashPrevBlock == 0) {
				/* already established a genesis block. */
				return (error(SHERR_INVAL, "CommitAltChainTx: rejecting genesis block on already established chain (color \"%s\", tail \"%s\")", alt->hColor.GetHex().c_str(), pindexBest->GetBlockHash()));
			}
		} else /* !pindexBest */ {
			if (alt->block.hashPrevBlock != 0) {
				return (error(SHERR_INVAL, "CommitAltChainTx: rejecting non-genesis block on non-established chain (color \"%s\")", alt->hColor.GetHex().c_str()));
			}
		}

		if (pindexBest) {
			CIface *alt_iface = GetCoinByIndex(COLOR_COIN_IFACE);
			const uint256& hashBlock = alt->block.GetHash();
			if (pindexBest->GetBlockHash() != hashBlock && /* not dup */
					pindexBest->GetBlockHash() != alt->block.hashPrevBlock) {


				/* The order of the alt-chain tx's received on the main service dictate the order of the color alt-chain. */
#if 0
				CBlockIndex *pindexPrev = GetBlockIndexByHash(COLOR_COIN_IFACE, alt->block.hashPrevBlock);
				/* check whether chain-work is higher. */
				if (pindexPrev && pindexPrev->pnext) {
					CBlockIndex *pindex = pindexPrev->pnext;

					if (HasBlockHash(alt_iface, pindex->GetBlockHash())) {
						/* already commited. */
						return (CommitAltChainOrphanTx(iface, tx));
					}

					CBigNum bnTarget;
					bnTarget.SetCompact(alt->block.nBits);
					if (bnTarget <= 0 ||
							(CBigNum(1)<<256) / (bnTarget+1) <= pindex->GetBlockWork()) {
						/* new block chain-work is less than old one. */
						return (CommitAltChainOrphanTx(iface, tx));
					}
				}
#endif


				return (CommitAltChainOrphanTx(iface, tx));
			}
		}

		/* new block */
		block = alt->GetBlock();
		if (!ProcessBlock(pfrom, block)) {
			error(SHERR_INVAL, "CommitAltChainTx: error processing block \"%s\": %s", alt->block.GetHash().GetHex().c_str(), block->ToString().c_str());
			delete block;
			return (false);
		}

		delete block;
	} else { /* loading block-chain (startup) */
		/* perform similar check to the normal run-time block submission without accessing the block index. */
		block = alt->GetBlock();
		if (!block->CheckBlock()) {
			delete block;
			return error(SHERR_INVAL, "CommitAltChainTx: error validating block integrity (%s).", alt->block.GetHash().GetHex().c_str());
		}

		/* presuming coin iface txdb is accessible on shc txidx init. */
		if (!block->CheckTransactionInputs(COLOR_COIN_IFACE)) {
			delete block;
			return (error(SHERR_INVAL, "CommitAltChainTx: error validating block transactions (%s).", alt->block.GetHash().GetHex().c_str()));
		}
		delete block;

		/* verify that block is stored in disk block-chain. */
		CIface *clr_iface = GetCoinByIndex(COLOR_COIN_IFACE);
		if (!HasBlockHash(clr_iface, alt->block.GetHash())) {
			Debug("CommitAltChainTx: warning: non-commited block \"%s\"; skip.", alt->block.GetHash().GetHex().c_str());
			return (false);
		}
	}

	if (!ConnectAltChainTx(iface, tx))
		return error(SHERR_INVAL, "CommitAltChainTx: error updating altchain on tx '%s'.", tx.GetHash().GetHex().c_str());

	if (!fUpdate)
		Debug("CommitNewAltChainTx: alt-block \"%s\"",
				alt->block.GetHash().GetHex().c_str());

	return (true);
}

bool CommitAltChainTx(CIface *iface, CTransaction& tx, CNode *pfrom, bool fUpdate)
{
	int mode;

	if (!CommitNewAltChainTx(iface, tx, pfrom, fUpdate))
		return (false);

  return (true);
}

/* called when altchain-tx is added to SHC service pool */
bool CommitAltChainPoolTx(CIface *iface, CTransaction& tx, bool fPool)
{
  CWallet *wallet = GetWallet(iface);
  CAltChain *alt;
	CBlock *block;
	int mode;

	if (VerifyAltChain(tx, mode) == false) {
		return (error(SHERR_INVAL, "CommitAltChainPoolTx: error verifying alt-chain tx."));
	}

	alt = tx.GetAltChain();
	if (!alt)
		return (error(SHERR_INVAL, "CommitAltChainPool: !tx.GetAltChain"));

	CBlockIndex *pindexBest = GetBestColorBlockIndex(iface, alt->hColor);

	if (!pindexBest && mode != OP_EXT_NEW)
		return (false); /* genesis is always created via EXT_NEW mode */
	if (mode != OP_EXT_NEW && mode != OP_EXT_UPDATE)
		return (true); /* nonstandard - soft error */

	if ( (!pindexBest && alt->block.hashPrevBlock != 0) ||
			 (pindexBest && alt->block.hashPrevBlock != pindexBest->GetBlockHash()) ) {
		/* if two blocks are present in a pool with the same prev-hash than the one that has the higher chain-work becomes valid virtue of the priority applied to it in the mempool [and redudantly this check here]. */
		bool bFound = false;
		CTxMemPool *pool = GetTxMemPool(iface);
		vector<CTransaction> vTx = pool->GetActiveTx();
		for (int i = 0; i < vTx.size(); i++) {
			const CTransaction& tx = vTx[i];
			CAltChain *p_alt = tx.GetAltChain();
			if (!p_alt) continue;

			if (p_alt->block.hashPrevBlock == alt->block.hashPrevBlock) {
				/* we are siblings.. */
				uint256 thash1, thash2;
				scrypt_1024_1_1_256(BEGIN(alt->block.nFlag), BEGIN(thash1));
				scrypt_1024_1_1_256(BEGIN(p_alt->block.nFlag), BEGIN(thash2));
				if (thash1 > thash2) {
					/* new block is better than old block. */
					bFound = true;
				}
			}
		}
		if (!bFound) {
			return (error(SHERR_INVAL, "CommitAltChainPool: invalid hashPrevBlock \"%s\".", alt->block.hashPrevBlock.GetHex().c_str()));
		}
	}

	block = alt->GetBlock();
	if (!block) {
		return (error(SHERR_INVAL, "CommitAltChainPool: !alt->GetBlock"));
	}

	if (!block->CheckBlock()) {
		delete block;
		return (error(SHERR_INVAL, "CommitAltChainPool: !CheckBlock"));
	}
	
	if (!block->AddToBlockIndex()) {
		delete block;
		return (error(SHERR_INVAL, "CommitAltChainPool: !AddToBlockIndex"));
	}

	const uint256& hBlock = block->GetHash();

	wallet->mapColorPool[alt->hColor] = hBlock;

	if (!pindexBest) {
		/* genesis */
		color_opt opt;
		ParseColorOptScript(opt, block->vtx[0].vout[0].scriptPubKey); 	
		SetChainColorOpt(alt->hColor, opt);
		wallet->mapColorHead[hBlock] = alt->hColor;
	}

	delete block;

	return (true);
}

/* called when altchain-tx contains out-of-order colored alt-block */
bool CommitAltChainOrphanTx(CIface *iface /* not used */, const CTransaction& tx)
{
	CIface *clr_iface = GetCoinByIndex(COLOR_COIN_IFACE);
  CWallet *wallet;
  CAltChain *alt;
	CBlock *block;

	wallet = GetWallet(clr_iface);
	if (!wallet)
		return (false);

	alt = tx.GetAltChain();
	if (!alt)
		return (false);

	block = alt->GetBlock();
	if (!block)
		return (false);

	if (!block->CheckBlock()) {
		/* block is not valid */
		delete block;
		return (false);
	}

  BOOST_FOREACH(const CTransaction& tx, block->vtx) {
		if (tx.IsCoinBase())
			continue;

		CWalletTx wtx(wallet, tx);
		wtx.SetColor(alt->hColor);
		/* add to pool / save to wallet */
		wallet->CommitTransaction(wtx);
	}

	delete block;
	return (true);
}

uint160 GetAltColorHash(CIface *iface, string strTitle, string& strColorRet)
{
	char label[256];
	char abrev[256];
	uint32_t r, g, b, a;
	uint160 hash;
	unsigned char *raw;

	hash = 0;
	if (!iface)
		return (0);

	if (strTitle.length() == 0)
		return (0);

	color_gen((char *)strTitle.c_str(), &r, &g, &b, &a, label, abrev);

	/* perturb using first character of iface name. */
	abrev[3] = (abrev[0] + iface->name[0]) % 26;
	abrev[3] += 'A';

	/* -> network byte order (big endian) */
	r = htonl(r);
	g = htonl(g);
	b = htonl(b);
	a = htonl(a);

	raw = (unsigned char *)&hash;
	memcpy(raw, abrev, 4);
	memcpy(raw + 4, &a, sizeof(uint32_t));
	memcpy(raw + 8, &b, sizeof(uint32_t));
	memcpy(raw + 12, &g, sizeof(uint32_t));
	memcpy(raw + 16, &r, sizeof(uint32_t));
	
	strColorRet = string(label);

	return (hash);
}

string GetAltColorHashAbrev(uint160 hash)
{
	char buf[32];
	memset(buf, 0, sizeof(buf));
	memcpy(buf, (char *)&hash, 4);
	return (string(buf));
}

void GetAltColorCode(uint160 hash, uint32_t *r_p, uint32_t *g_p, uint32_t *b_p, uint32_t *a_p)
{
	unsigned char *raw;
	
	raw = (unsigned char *)&hash;
	memcpy(a_p, raw + 4, sizeof(uint32_t));
	memcpy(b_p, raw + 8, sizeof(uint32_t));
	memcpy(g_p, raw + 12, sizeof(uint32_t));
	memcpy(r_p, raw + 16, sizeof(uint32_t));

	/* host byte order */
	*r_p = ntohl(*r_p);
	*g_p = ntohl(*g_p);
	*b_p = ntohl(*b_p);
	*a_p = ntohl(*a_p);
}

static int FillAltChainBlock(string strAccount, CBlock *block, CTransaction *tx, uint160 hColor)
{
	CIface *alt_iface = GetCoinByIndex(COLOR_COIN_IFACE);
	CWallet *alt_wallet = GetWallet(COLOR_COIN_IFACE);
	set<pair<const CWalletTx*,unsigned int> > setCoins;
	vector<COutput> vCoins;
	int64 nCredit = 0;

	int64 nDebit = 0;
	for (int j = 0; j < tx->vout.size(); j++) {
		const CTxOut& out = tx->vout[j];
		nDebit += out.nValue;
	}

	/* select local tx outputs available for color and account name. */
	if (!alt_wallet->SelectAccountCoins(
				strAccount, nDebit, setCoins, nCredit, hColor)) {
		return (ERR_FEE);
	}

	nCredit = 0;
	tx->vin.clear();
	BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins) {
		const CWalletTx *wtxIn = coin.first;
		const CTxOut& out = wtxIn->vout[coin.second];

		nCredit += out.nValue;
		tx->vin.push_back(CTxIn(wtxIn->GetHash(), coin.second));
	}

	/* sign inputs */
	unsigned int nIn = 0;
	BOOST_FOREACH(const PAIRTYPE(const CWalletTx*, unsigned int)& coin, setCoins) {
		CSignature sig(COLOR_COIN_IFACE, tx, nIn);
		if (!sig.SignSignature(*coin.first)) {
			return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
		}
		nIn++;
	}

	int64 nChange = (nCredit - nDebit);

	CWalletTx wtx(alt_wallet, *tx);
	wtx.SetColor(hColor);
	int64 nTxFee = alt_wallet->CalculateFee(wtx, 0);

	nChange = (nChange > nTxFee) ? (nChange - nTxFee) : 0;
	if (nChange > MIN_TX_FEE(alt_iface)) {
		CScript scriptPubKey;
		const CCoinAddr& changeAddr = alt_wallet->GetRecvAddr(strAccount);
		scriptPubKey.SetDestination(changeAddr.Get());
		vector<CTxOut>::iterator position = tx->vout.begin()+GetRandInt(tx->vout.size());
		tx->vout.insert(position, CTxOut(nChange, scriptPubKey));
	}

	return (0);
}

bool GenerateAltChainGenesisBlock(CIface *iface, CAltChain *altchain, uint160 hColor, color_opt& opt, const CPubKey& pubkey, CBlock **pBlockRet)
{
	CBlock *block;
	int err;

	/* create new block. */
	vector<CTransaction> vTx;
	block = (CBlock *)color_GenerateNewBlock(iface, pubkey, hColor, vTx, opt);
	if (!block)
		return (false);

	/* assign color */
	altchain->hColor = hColor;

	/* generate hash of transactions. */
	block->hashMerkleRoot = block->BuildMerkleTree();

	/* cpu-mine for a new block nonce. */
	color_GenerateNewBlockNonce(iface, block);

	/* redundantly verify generated block. */
	if (!block->CheckBlock()) {
		delete block;
		return (error(SHERR_INVAL, "GenerateAltChainBlock: error validating block \"%s\" integrity.", block->GetHash().GetHex().c_str()));
	}

	/* fill block into altchain tx */
	altchain->block = block->GetAltBlockHeader();

	/* fill block tx's into altchain tx */
	altchain->vtx.clear();
	{
		const CTransaction& tx = block->vtx[0];

		CAltTx atx;
		atx.nFlag = tx.nFlag;
		atx.vin = tx.vin;
		atx.vout = tx.vout;
		atx.nLockTime = tx.nLockTime;
		altchain->vtx.insert(altchain->vtx.end(), atx);
	}

	if (pBlockRet) {
		/* return allocated block */
		*pBlockRet = block;
	} else {
		/* free block */
		delete block;
	}

	return (true);
}

bool GenerateAltChainBlock(CIface *iface, string strAccount, CAltChain *altchain, uint160 hColor, vector<CTransaction> vTx, const CPubKey& pubkey, CBlock **pBlockRet)
{
	CBlock *block;
	int err;

	/* create new block. */
	block = (CBlock *)color_GenerateNewBlock(iface, pubkey, hColor, vTx);
	if (!block)
		return (false);

	/* assign color */
	altchain->hColor = hColor;

	for (int i = 0; i < block->vtx.size(); i++) {
		if (block->vtx[i].IsCoinBase())
			continue;

		err = FillAltChainBlock(strAccount, block, &block->vtx[i], hColor);
		if (err) {
			delete block;
			return (error(err, "GenerateAltChainBlock: FillAltChainBlock"));
		}
	}

	/* generate hash of transactions. */
	block->hashMerkleRoot = block->BuildMerkleTree();

	/* cpu-mine for a new block nonce. */
	color_GenerateNewBlockNonce(iface, block);

	/* redundantly verify generated block. */
	if (!block->CheckBlock()) {
		delete block;
		return (error(SHERR_INVAL, "GenerateAltChainBlock: error validating block \"%s\" integrity.", block->GetHash().GetHex().c_str()));
	}

	/* fill block into altchain tx */
	altchain->block = block->GetAltBlockHeader();

	/* fill block tx's into altchain tx */
	altchain->vtx.clear();
	for (int i = 0; i < block->vtx.size(); i++) {
		const CTransaction& tx = block->vtx[i];

		CAltTx atx;
		atx.nFlag = tx.nFlag;
		atx.vin = tx.vin;
		atx.vout = tx.vout;
		atx.nLockTime = tx.nLockTime;
		altchain->vtx.insert(altchain->vtx.end(), atx);
	}

	if (pBlockRet) {
		/* return allocated block */
		*pBlockRet = block;
	} else {
		/* free block */
		delete block;
	}

	return (true);
}

const CPubKey& GetAltChainAddr(uint160 hColor, string strAccount, bool bForceNew)
{
	static CPubKey pubkey;
	CWallet *wallet = GetWallet(COLOR_COIN_IFACE);
	wallet->GetMergedPubKey(strAccount, hColor.GetHex().c_str(), pubkey);
	return (pubkey);
}

CBlock *CAltChain::GetBlock()
{
	COLORBlock *b;

	auto_ptr<COLORBlock> pblock(new COLORBlock(block, hColor));
	if (!pblock.get())
		return NULL;

	/* fill block from altchain tx */
	pblock->vtx.clear();
	for (int i = 0; i < vtx.size(); i++) {
		pblock->vtx.insert(pblock->vtx.end(), CTransaction(vtx[i]));
	}

	return ((COLORBlock *)pblock.release());
}




static inline string ToValue_date_format(time_t t)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));
  strftime(buf, sizeof(buf)-1, "%x %T", localtime(&t));

  return (string(buf));
}

Object CAltChain::ToValue()
{
	Object block_obj;
  Object obj;
	Array ar;

	/* block */
	block_obj = block.ToValue();
	/* vtx */
	for (int i = 0; i < vtx.size(); i++) {
		ar.push_back(vtx[i].ToValue());
	}
	block_obj.push_back(Pair("vtx", ar));

	/* alt-chain block */
	obj.push_back(Pair("block", block_obj));
	obj.push_back(Pair("colorhash", hColor.GetHex()));
	obj.push_back(Pair("symbol", GetAltColorHashAbrev(hColor)));
	obj.push_back(Pair("version", (int)GetVersion())); /* CExtCore */

  return (obj);
}

const uint160 CAltChain::GetHash()
{
	uint256 hashOut = SerializeHash(*this);
	unsigned char *raw = (unsigned char *)&hashOut;
	cbuff rawbuf(raw, raw + sizeof(hashOut));
	return Hash160(rawbuf);
}

const uint256 CAltTx::GetHash()
{
	return (SerializeHash(*this));
}

std::string CAltChain::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CAltBlock::ToValue()
{
	CIface *iface = GetCoinByIndex(COLOR_COIN_IFACE);
  CBlockIndex *pindex;
  Object obj;
  uint256 hash = GetHash();

  obj.push_back(Pair("blockhash", hash.GetHex()));
  obj.push_back(Pair("version", (boost::uint64_t)nFlag));
  obj.push_back(Pair("merkleroot", hashMerkleRoot.GetHex()));
  obj.push_back(Pair("time", (boost::int64_t)GetBlockTime()));
  obj.push_back(Pair("stamp", ToValue_date_format((time_t)GetBlockTime())));
  obj.push_back(Pair("nonce", (boost::uint64_t)nNonce));
  obj.push_back(Pair("bits", HexBits(nBits)));

  obj.push_back(Pair("previousblockhash", hashPrevBlock.GetHex().c_str()));

  pindex = GetBlockIndexByHash(COLOR_COIN_IFACE, hash);
  if (pindex) {
		unsigned int nHeight;
		if (GetColorBlockHeight(hash, nHeight))
			obj.push_back(Pair("height", (boost::uint64_t)nHeight));
		obj.push_back(Pair("difficulty", GetDifficulty(nBits, nFlag)));
    obj.push_back(Pair("chainwork", pindex->bnChainWork.ToString()));
		if (pindex->pnext)
			obj.push_back(Pair("nextblockhash",
						pindex->pnext->GetBlockHash().GetHex()));
  }

  return obj;
} 

std::string CAltBlock::ToString()
{
	  return (write_string(Value(ToValue()), false));
}

bool CAltTx::IsCoinBase() const
{
	return (vin.size() == 1 && vin[0].prevout.IsNull());
}

Object CAltTx::ToValue()
{
  Object obj;

  /* primary identification */
  obj.push_back(Pair("txid", GetHash().GetHex()));
  obj.push_back(Pair("version", (int)nFlag));

  Array obj_vin;
  unsigned int n = 0;
  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    Object in;
    if (IsCoinBase()) {
      in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    } else {
      in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
      in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
      in.push_back(Pair("scriptSig", txin.scriptSig.ToString()));
    }   

    in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));

    obj_vin.push_back(in);
    n++;
  }
  obj.push_back(Pair("vin", obj_vin));

  Array obj_vout;
  for (unsigned int i = 0; i < vout.size(); i++)
  {     
    const CTxOut& txout = vout[i];
    Object out;
    out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
    out.push_back(Pair("n", (boost::int64_t)i));
    out.push_back(Pair("scriptpubkey", txout.scriptPubKey.ToString().c_str()));
    ScriptPubKeyToJSON(COLOR_COIN_IFACE, txout.scriptPubKey, out);

    obj_vout.push_back(out);
  } 
  obj.push_back(Pair("vout", obj_vout));

	if (nLockTime != 0) {
		if ((int64)nLockTime < (int64)LOCKTIME_THRESHOLD) {
			obj.push_back(Pair("lock-height", (int)nLockTime));
		} else {
			obj.push_back(Pair("lock-time", (uint64_t)nLockTime));
			obj.push_back(Pair("lock-stamp", ToValue_date_format((time_t)nLockTime)));
		}
	}

	if (vchAux.size() != 0) {
		obj.push_back(Pair("aux-size", (int)vchAux.size()));
	}

  return (obj);
}

std::string CAltTx::ToString()
{
	  return (write_string(Value(ToValue()), false));
}


int init_altchain_tx(CIface *iface, string strAccount, uint160 hColor, color_opt& opt, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

	if (!wallet)
		return (ERR_INVAL);
	if (wallet->mapColor.count(hColor) != 0)
		return (ERR_EXIST);

  int64 nFee = GetAltChainOpFee(iface);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

  CTxCreator s_wtx(wallet, strAccount);

  CAltChain *altchain = s_wtx.CreateAltChain();
  if (!altchain) {
		error(SHERR_INVAL, "init_altchain_tx: !CreateAltChain");
		return (SHERR_INVAL);
	}

	/* fill in altchain ext tx */
	vector<CTransaction> vAltTx;
	const CPubKey& pubkey = GetAltChainAddr(hColor, strAccount, false); 
	if (!GenerateAltChainGenesisBlock(iface, altchain, hColor, opt, pubkey, NULL)) {
		error(SHERR_INVAL, "init_altchain_tx: !GenerateAltChainBlock");
		return (SHERR_INVAL);
	}

  CScript scriptPubKey;
  uint160 altchainHash = altchain->GetHash();
	scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_ALTCHAIN) << OP_HASH160 << altchainHash << OP_2DROP << OP_RETURN << OP_0;
  if (!s_wtx.AddOutput(scriptPubKey, nFee)) {
		error(SHERR_INVAL, "init_altchain_tx: s_wtx.AddOutput: %s", s_wtx.GetError().c_str());
    return (SHERR_INVAL);
	}

	/* commit transaction to pool. */
  if (!s_wtx.Send()) {
    return (SHERR_CANCELED);
	}

  wtx = s_wtx;

	Debug("(%s) init_altchain_tx: color(%s) altchainhash(%s) tx(%s)", 
			iface->name, hColor.GetHex().c_str(), 
			altchain->GetHash().GetHex().c_str(), 
			s_wtx.GetHash().GetHex().c_str());

  return (0);
}

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, vector<CTransaction> vAltTx, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

	if (!wallet)
		return (ERR_INVAL);
	if (wallet->mapColor.count(hColor) == 0)
		return (ERR_NOENT);

	if (!color_IsSupported(hColor))
		return (ERR_OPNOTSUPP);

  int64 nFee = GetAltChainOpFee(iface);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (ERR_FEE);
  }

  CTxCreator s_wtx(wallet, strAccount);
  CAltChain *altchain = s_wtx.CreateAltChain();
  if (!altchain) {
		error(SHERR_INVAL, "update_altchain_tx: !CreateAltChain");
		return (SHERR_INVAL);
	}

	/* fill in altchain ext tx */
	const CPubKey& pubkey = GetAltChainAddr(hColor, strAccount, false); 
	if (!GenerateAltChainBlock(iface, strAccount, altchain, hColor, vAltTx, pubkey, NULL)) {
		error(SHERR_INVAL, "update_altchain_tx: !GenerateAltChainBlock");
		return (SHERR_INVAL);
	}

  CScript scriptPubKey;
  uint160 altchainHash = altchain->GetHash();
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ALTCHAIN) << OP_HASH160 << altchainHash << OP_2DROP << OP_RETURN << OP_0;
  if (!s_wtx.AddOutput(scriptPubKey, nFee)) {
		error(SHERR_INVAL, "update_altchain_tx: s_wtx.AddOutput: %s", s_wtx.GetError().c_str());
    return (SHERR_INVAL);
	}

	/* commit transaction to pool. */
  if (!s_wtx.Send()) {
    return (SHERR_CANCELED);
	}

  wtx = s_wtx;

	Debug("(%s) update_altchain_tx: color(%s) altchainhash(%s) tx(%s)", 
			iface->name, hColor.GetHex().c_str(), 
			altchain->GetHash().GetHex().c_str(), 
			s_wtx.GetHash().GetHex().c_str());

  return (0);
}

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, const CScript& addrTo, int64 nValueTo, CWalletTx& wtx)
{
	vector<CTransaction> vTx;

	CTransaction tx;
	tx.vout.resize(1);
	tx.vout[0] = CTxOut(nValueTo, addrTo); 
	vTx.insert(vTx.end(), tx);

	return (update_altchain_tx(iface, strAccount, hColor, vTx, wtx));
}

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, const CPubKey& addrTo, int64 nValueTo, CWalletTx& wtx)
{
	CScript scriptPubKey;
	scriptPubKey.SetDestination(addrTo.GetID());
	return (update_altchain_tx(iface, strAccount,
				hColor, scriptPubKey, nValueTo, wtx));
}

int update_altchain_tx(CIface *iface, string strAccount, uint160 hColor, const CCoinAddr& addrTo, int64 nValueTo, CWalletTx& wtx)
{
	CScript scriptPubKey;
  scriptPubKey.SetDestination(addrTo.Get());
	return (update_altchain_tx(iface, strAccount,
				hColor, scriptPubKey, nValueTo, wtx));
}


