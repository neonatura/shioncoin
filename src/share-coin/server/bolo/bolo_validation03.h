
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
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

#ifndef __BOLO_VALIDATION03_H__
#define __BOLO_VALIDATION03_H__

#ifdef __cplusplus
extern "C" {
#endif


/* the minimum number of inputs to create a notary tx on the master chain. */
#define BOLO_MINRATIFY 11

/* the elapsed time (in blocks) that a notary tx has before expiring. */
#define BOLO_LOCKTIME_DEPTH 20

/* the intermediate period (in blocks) between notary tx submissions. */
#define BOLO_BLOCK_MERKLE_DEPTH 1000

#define BOLO_ASSETCHAIN_MINLEN 85
#define BOLO_ASSETCHAIN_MAXLEN 153

/* slave chain - block to notorize. */
extern int64 bolo_CHECKPOINT_HEIGHT;
extern int64 bolo_CHECKPOINT_TIME;
extern uint256 bolo_CHECKPOINT_HASH;
extern uint256 bolo_CHECKPOINT_TXID;

/* slave chain - proposed block to notorize. */
extern int bolo_PROPOSED_HEIGHT;
extern uint256 bolo_PROPOSED_BLOCK;
extern int bolo_HWM_HEIGHT;

/* establish the master and slave coin services. */
int32_t bolo_init(int slaveIface, int masterIface);

/* propose a notary tx on the master chain referencing the specified block and height on the slave chain. */
bool bolo_ProposeMasterTx(const uint256& hBlock, int nHeight, CCoinAddr *addr = NULL);

/* sign the final notary tx on the master chain. */
bool bolo_SignMasterNotarySignature(CTransaction& tx, int nIn);

bool bolo_VerifyMasterNotarySignature(CTransaction& tx, int nIn);

bool bolo_CreateMasterNotaryTx(CTransaction& tx);

/* verify that all inputs reference a known notary poposal tx commited on master chain. */
bool bolo_IsNotaryTx(const CTransaction& tx);

bool bolo_UpdateMasterNotaryTx(CTransaction& tx);

/**
 * A notarized validation matrix tx will have a single coinbase input (the validation matrix) and a single output of OP_RETURN (0x6A) OP_0 (0x0).
 */
void bolo_connectblock_slave(CBlockIndex *pindex, CBlock& block);

void bolo_disconnectblock_master(CBlockIndex *pindex, CBlock *block);

void bolo_disconnectblock_slave(CBlockIndex *pindex, CBlock *block);

/**
 * A notarized master transaction will have a eleven or more inputs of 0.00001 coins and a single zero-value output of "OP_RETURN << OP_11 << OP_1 << OP_HASH160 << <block hash: 32 bytes> << <height: 4 bytes> << OP_0" where OP_HASH160 is a uint160 hash of the coin interface's symbol.
 */
void bolo_connectblock_master(CBlockIndex *pindex, CBlock& block);

/* handles management of ongoing final notary tx on master chain while it remains in the memory pool */
bool bolo_updatetx_master(CTransaction& tx);

/* calculate a merkle tree hash from a chain of blocks. */
uint256 bolo_GetSlaveMerkle(int32_t height,int32_t MoMdepth);

bool bolo_IsSlaveIface(CIface *iface);


#ifdef __cplusplus
}
#endif

#endif /* ndef __BOLO_VALIDATION03_H__ */

