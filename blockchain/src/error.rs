//! Blockchain Errors.

//
// Copyright (c) 2018 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::output::OutputError;
use crate::timestamp::Timestamp;
use crate::view_changes::ViewChangeProof;
use failure::Fail;
use rocksdb;
use std::str::Utf8Error;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::PublicKey;
use stegos_crypto::CryptoError;

pub type StorageError = rocksdb::Error;

#[derive(Debug, Fail)]
pub enum BlockchainError {
    #[fail(
        display = "Found incompatible genesis: application={}, database={}",
        _0, _1
    )]
    IncompatibleGenesis(Hash, Hash),
    #[fail(
        display = "Expected a macro block, got micro block: epoch={}, offset={}, block={}",
        _0, _1, _2
    )]
    ExpectedMacroBlock(u64, u32, Hash),
    #[fail(
        display = "Expected a micro block, got macro block: epoch={}, offset={}, block={}",
        _0, _1, _2
    )]
    ExpectedMicroBlock(u64, u32, Hash),
    #[fail(
        display = "Have micro blocks on attempt to apply a macro block: epoch={}, offset={}, block={}",
        _0, _1, _2
    )]
    HaveMicroBlocks(u64, u32, Hash),
    #[fail(
        display = "TXOUTs with different account key: account_key_before:{},\
                   account_key_after={},  utxo={}",
        _0, _1, _2
    )]
    StakeOutputWithDifferentAccountKey(PublicKey, PublicKey, Hash),
    #[fail(
        display = "Stake is locked: validator={}, expected_balance={}, minimum_balance={}",
        _0, _1, _2
    )]
    StakeIsLocked(pbc::PublicKey, i64, i64),
    #[fail(display = "Storage I/O error={}", _0)]
    StorageError(StorageError),
    #[fail(display = "Transaction error={}", _0)]
    TransactionError(TransactionError),
    #[fail(display = "Block error={}", _0)]
    BlockError(BlockError),
    #[fail(display = "Output error={}", _0)]
    OutputError(OutputError),
    #[fail(display = "Crypto error={}", _0)]
    CryptoError(CryptoError),
    #[fail(display = "Cannot convert utf8 string = {}", _0)]
    UtfError(Utf8Error),
    #[fail(display = "Other error={}", _0)]
    FailureError(failure::Error),
}

/// Transaction errors.
#[derive(Debug, Fail)]
pub enum TransactionError {
    #[fail(display = "Invalid signature: tx={}", _0)]
    InvalidSignature(Hash),
    #[fail(display = "Invalid monetary balance: tx={}", _0)]
    InvalidMonetaryBalance(Hash),
    #[fail(display = "Negative fee: tx={}", _0)]
    NegativeFee(Hash),
    #[fail(display = "Negative reward: tx={}", _0)]
    NegativeReward(Hash),
    #[fail(display = "No inputs: tx={}", _0)]
    NoInputs(Hash),
    #[fail(display = "Missing transaction input: tx={}, utxo={}", _0, _1)]
    MissingInput(Hash, Hash),
    #[fail(display = "Duplicate input: tx={}, utxo={}", _0, _1)]
    DuplicateInput(Hash, Hash),
    #[fail(display = "Duplicate output: tx={}, utxo={}", _0, _1)]
    DuplicateOutput(Hash, Hash),
    #[fail(display = "Output hash collision: tx={}, utxo={}", _0, _1)]
    OutputHashCollision(Hash, Hash),
    #[fail(
        display = "Received transaction from network, with invalid type: type={}",
        _0
    )]
    ReceivedInvalidTransaction(&'static str),

    #[fail(
        display = "CoinbaseTransaction must contain only PaymentUTXOs: tx={}, utxo={}",
        _0, _1
    )]
    NonPaymentOutputInCoinbase(Hash, Hash),

    #[fail(display = "Non-StakeUTXO found in TXINs: tx = {}. utxo={}", _0, _1)]
    InvalidRestakingInput(Hash, Hash),

    #[fail(display = "TXINs with mixed validator keys: tx = {}, utxo={}", _0, _1)]
    RestakingValidatorKeyMismatch(Hash, Hash),

    #[fail(
        display = "StakeUTXOs with mixed recipient keys: tx = {}, utxo={}",
        _0, _1
    )]
    MixedRestakingOwners(Hash, Hash),

    #[fail(display = "No TXINs: tx={}", _0)]
    NoRestakingTxins(Hash),

    #[fail(display = "Non-StakeUTXO found in TXOUTs: tx={}, utxo={}", _0, _1)]
    InvalidRestakingOutput(Hash, Hash),

    #[fail(display = "TXOUTs with mixed validator keys: tx={}, utxo={}", _0, _1)]
    MixedTxoutValidators(Hash, Hash),

    #[fail(display = "Unexpected transaction type in MicroBlock.")]
    UnexpectedTxType,

    #[fail(display = "TXIN amount .ne. TXOUT amount: tx={}", _0)]
    ImbalancedRestaking(Hash),

    #[fail(display = "Slashing error ={}", _0)]
    SlashingError(SlashingError),
}

#[derive(Debug, Fail)]
pub enum MultisignatureError {
    #[fail(
        display = "Signature bitmap too big: len={}, validators_len={} ",
        _0, _1
    )]
    TooBigBitmap(usize, usize),
    #[fail(
        display = "Not enough votes in signature: votes={}, needed_votes={} ",
        _0, _1
    )]
    NotEnoughtVotes(i64, i64),
    #[fail(display = "Signature is not valid: hash={} ", _0)]
    InvalidSignature(Hash),
}

#[derive(Debug, Fail)]
pub enum BlockError {
    #[fail(
        display = "Previous hash mismatch: epoch={}, offset={}, block={}, block_previous={}, our_previous={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockPreviousHash(u64, u32, Hash, Hash, Hash),
    #[fail(
        display = "Previous hash mismatch: epoch={}, block={}, block_previous={}, our_previous={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockPreviousHash(u64, Hash, Hash, Hash),
    #[fail(
        display = "Micro block hash collision: epoch={}, offset={}, block={}",
        _0, _1, _2
    )]
    MicroBlockHashCollision(u64, u32, Hash),
    #[fail(display = "Macro block hash collision: epoch={}, block={}", _0, _1)]
    MacroBlockHashCollision(u64, Hash),
    #[fail(
        display = "Out of order macro block: block={}, block_epoch={}, our_epoch={}",
        _0, _1, _2
    )]
    OutOfOrderMacroBlock(Hash, u64, u64),
    #[fail(
        display = "Out of order micro block: block={}, block_epoch={}, block_offset={}, our_epoch={}, our_offset={}",
        _0, _1, _2, _3, _4
    )]
    OutOfOrderMicroBlock(Hash, u64, u32, u64, u32),
    #[fail(
        display = "Invalid micro block fee: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockFee(u64, u32, Hash, i64, i64),
    #[fail(
        display = "Unexpected macro block fee: epoch={}, block={}, got={}, expected={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockFee(u64, Hash, i64, i64),
    #[fail(
        display = "Coinbase transaction must be first in the block: block={}",
        _0
    )]
    CoinbaseMustBeFirst(Hash),
    #[fail(
        display = "Found that service award random produce winner, but no tx found: block={}",
        _0
    )]
    NoServiceAwardTx(Hash),
    #[fail(
        display = "Found that service award with more than one winner: block={}, winner_count={}",
        _0, _1
    )]
    AwardMoreThanOneWinner(Hash, usize),
    #[fail(
        display = "Found that service award produce different winner: block={}, \
                   actual_winner={}, award_winner={}",
        _0, _1, _2
    )]
    AwardDifferentWinner(Hash, PublicKey, PublicKey),
    #[fail(display = "Found service award tx with different output: block={}", _0)]
    AwardDifferentOutputType(Hash),
    #[fail(
        display = "Found that service award produce different reward: block={}, \
                   actual_reward={}, award_reward={}",
        _0, _1, _2
    )]
    AwardDifferentReward(Hash, i64, i64),
    #[fail(display = "Invalid block monetary balance: epoch={}, block={}", _0, _1)]
    InvalidBlockBalance(u64, Hash),
    #[fail(
        display = "Invalid inputs_range_hash in a macro block: epoch={}, block={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockInputsHash(u64, Hash, Hash, Hash),
    #[fail(
        display = "Invalid outputs_range_hash in a macro block: epoch={}, block={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockOutputsHash(u64, Hash, Hash, Hash),
    #[fail(
        display = "Invalid canaries_range_hash in a macro block: epoch={}, block={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockCanariesHash(u64, Hash, Hash, Hash),
    #[fail(
        display = "Invalid inputs_len in a macro block: epoch={}, block={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockInputsLen(u64, Hash, usize, usize),
    #[fail(
        display = "Invalid outputs_len in a macro block: epoch={}, block={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockOutputsLen(u64, Hash, usize, usize),
    #[fail(
        display = "Invalid transactions_range_hash in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockTransactionsHash(u64, u32, Hash, Hash, Hash),
    #[fail(
        display = "Invalid inputs_range_hash in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockInputsHash(u64, u32, Hash, Hash, Hash),
    #[fail(
        display = "Invalid outputs_range_hash in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockOutputsHash(u64, u32, Hash, Hash, Hash),
    #[fail(
        display = "Invalid canaries_range_hash in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockCanariesHash(u64, u32, Hash, Hash, Hash),
    #[fail(
        display = "Invalid transactions_len in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockTransactionsLen(u64, u32, Hash, usize, usize),
    #[fail(
        display = "Invalid inputs_len in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockInputsLen(u64, u32, Hash, usize, usize),
    #[fail(
        display = "Invalid outputs_len in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockOutputsLen(u64, u32, Hash, usize, usize),
    #[fail(
        display = "Invalid canaries_len in a micro block: epoch={}, offset={}, block={}, expected={}, got={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockCanariesLen(u64, u32, Hash, usize, usize),
    #[fail(
        display = "Missing block input: epoch={}, block={}, utxo={}",
        _0, _1, _2
    )]
    MissingBlockInput(u64, Hash, Hash),
    #[fail(
        display = "Duplicate block input: epoch={}, block={}, utxo={}",
        _0, _1, _2
    )]
    DuplicateBlockInput(u64, Hash, Hash),
    #[fail(
        display = "Duplicate block output: epoch={}, block={}, utxo={}",
        _0, _1, _2
    )]
    DuplicateBlockOutput(u64, Hash, Hash),
    #[fail(
        display = "Output hash collision: epoch={}, block={}, utxo={}",
        _0, _1, _2
    )]
    OutputHashCollision(u64, Hash, Hash),
    #[fail(display = "The leader must be validator: epoch={}, block={}", _0, _1)]
    LeaderIsNotValidator(u64, Hash),
    #[fail(
        display = "Found propose with more than one signature: epoch={}, block={}",
        _0, _1
    )]
    MoreThanOneSignatureAtPropose(u64, Hash),
    #[fail(
        display = "Different leader found in received block: elected={}, sender={}",
        _0, _1
    )]
    DifferentPublicKey(pbc::PublicKey, pbc::PublicKey),
    #[fail(display = "Invalid leader signature found: epoch={}, block={}", _0, _1)]
    InvalidLeaderSignature(u64, Hash),
    #[fail(
        display = "Invalid block BLS multisignature: epoch={}, block={}, error={}",
        _1, _2, _0
    )]
    InvalidBlockSignature(MultisignatureError, u64, Hash),
    #[fail(
        display = "Invalid block version: epoch={}, block={}, block_version={}, our_version={}",
        _0, _1, _2, _3
    )]
    InvalidBlockVersion(u64, Hash, u64, u64),
    #[fail(
        display = "Received block with invalid random: epoch={}, block={}",
        _0, _1
    )]
    IncorrectRandom(u64, Hash),
    #[fail(
        display = "Received block with incorrect VDF solution: epoch={}, block={}",
        _0, _1
    )]
    InvalidVDFProof(u64, Hash),
    #[fail(
        display = "Received block with unexpected VDF complexity: epoch={}, block={}, expected={}, got={}",
        _0, _1, _2, _3
    )]
    UnexpectedVDFComplexity(u64, Hash, u64, u64),
    #[fail(
        display = "Received block with wrong view_change: epoch={}, block={}, block_view_change={}, our_view_change={}",
        _0, _1, _2, _3
    )]
    InvalidViewChange(u64, Hash, u32, u32),
    #[fail(
        display = "Invalid view change proof: epoch={}, proof={:?}, error={}",
        _0, _1, _2
    )]
    InvalidViewChangeProof(u64, ViewChangeProof, failure::Error),
    #[fail(
        display = "No proof of view change found for out of order block: epoch={}, offset={}, block={}, block_view_change={}, our_view_change={}",
        _0, _1, _2, _3, _4
    )]
    NoProofWasFound(u64, u32, Hash, u32, u32),
    #[fail(
        display = "Election result could be taken only current epoch: \
                   election_epoch={}, last_key_block={}",
        _0, _1
    )]
    ElectionResultForPastEpoch(u64, u64),
    #[fail(
        display = "No election result are known for future blocks: election_epoch={}, blockchain_epoch={}",
        _0, _1
    )]
    ElectionResultForFutureBlock(u64, u64),
    #[fail(
        display = "Unexpected macro block reward: epoch={}, block={}, got={}, expected={}",
        _0, _1, _2, _3
    )]
    InvalidMacroBlockReward(u64, Hash, i64, i64),
    #[fail(
        display = "Unexpected micro block reward: epoch={}, offset={}, block={}, got={}, expected={}",
        _0, _1, _2, _3, _4
    )]
    InvalidMicroBlockReward(u64, u32, Hash, i64, i64),
    #[fail(
        display = "Activity bitmap too big: len={}, validators_len={} ",
        _0, _1
    )]
    TooBigActivitymap(usize, usize),
    #[fail(
        display = "Found a outdated block proposal: epoch={}, block={}, block_time={} last_block_time={}.",
        _0, _1, _2, _3
    )]
    OutdatedBlock(u64, Hash, Timestamp, Timestamp),
    #[fail(
        display = "Timestamp is out of sync: epoch={}, block={}, block_time={}, our_time={}",
        _0, _1, _2, _3
    )]
    OutOfSyncTimestamp(u64, Hash, Timestamp, Timestamp),
    #[fail(
        display = "Invalid block proposal: epoch={}, expected={}, got={}",
        _0, _1, _2
    )]
    InvalidBlockProposal(u64, Hash, Hash),
    #[fail(
        display = "Invalid block epoch found: block_epoch={}, chain_epoch={}",
        _0, _1
    )]
    InvalidBlockEpoch(u64, u64),
    #[fail(
        display = "Proposed view_change different from ours: epoch={}, block={}, block_viewchange={}, our_viewchange={}",
        _0, _1, _2, _3
    )]
    OutOfSyncViewChange(u64, Hash, u32, u32),
}

#[derive(Debug, Fail)]
pub enum SlashingError {
    #[fail(
        display = "Found a block from future epoch : proof_epoch={}, blockchain_epoch={}",
        _0, _1
    )]
    InvalidProofHeight(u64, u64),
    #[fail(
        display = "Found block with past epoch : proof_epoch={}, last_key_block_epoch={}",
        _0, _1
    )]
    InvalidProofEpoch(u64, u64),
    #[fail(
        display = "Other leader found at same epoch: view_change={}, blockchain_view_change={}",
        _0, _1
    )]
    DifferentLeader(u32, u32),
    #[fail(
        display = "Found same block that already was committed : epoch={}, offset={}, block={}",
        _0, _1, _2
    )]
    BlockWithoutConflicts(u64, u32, Hash),
    #[fail(
        display = "Found incorrect leader: leader_in_proof={}, actual_leader={}",
        _0, _1
    )]
    WrongLeader(pbc::PublicKey, pbc::PublicKey),
    #[fail(
        display = "No active validators found after punishing cheater: validator = {}",
        _0
    )]
    LastValidator(pbc::PublicKey),
    #[fail(display = "Cheater was not validator: validator = {}", _0)]
    NotValidator(pbc::PublicKey),
    #[fail(
        display = "Different parents was found for blocks in proofs: \
                   block1_parent = {}, block2_parent = {}",
        _0, _1
    )]
    DifferentHistory(Hash, Hash),

    #[fail(
        display = "Different epoch was found for blocks in proofs: \
                   block1_epoch = {}, block2_epoch = {}",
        _0, _1
    )]
    DifferentEpoch(u64, u64),
    #[fail(
        display = "Different offset was found for blocks in proofs: \
                   block1_offset = {}, block2_offset= {}",
        _0, _1
    )]
    DifferentOffset(u32, u32),
    #[fail(
        display = "Found slashing transaction, with incorrect inputs, tx_hash = {}",
        _0
    )]
    IncorrectTxins(Hash),
    #[fail(
        display = "Found slashing transaction, with incorrect outputs, tx_hash = {}",
        _0
    )]
    IncorrectTxouts(Hash),
}

impl From<rocksdb::Error> for BlockchainError {
    fn from(error: rocksdb::Error) -> BlockchainError {
        BlockchainError::StorageError(error)
    }
}

impl From<TransactionError> for BlockchainError {
    fn from(error: TransactionError) -> BlockchainError {
        BlockchainError::TransactionError(error)
    }
}

impl From<BlockError> for BlockchainError {
    fn from(error: BlockError) -> BlockchainError {
        BlockchainError::BlockError(error)
    }
}

impl From<OutputError> for BlockchainError {
    fn from(error: OutputError) -> BlockchainError {
        BlockchainError::OutputError(error)
    }
}

impl From<CryptoError> for BlockchainError {
    fn from(error: CryptoError) -> BlockchainError {
        BlockchainError::CryptoError(error)
    }
}
impl From<failure::Error> for BlockchainError {
    fn from(error: failure::Error) -> BlockchainError {
        BlockchainError::FailureError(error)
    }
}

impl From<SlashingError> for BlockchainError {
    fn from(error: SlashingError) -> BlockchainError {
        BlockchainError::TransactionError(TransactionError::SlashingError(error))
    }
}

impl From<Utf8Error> for BlockchainError {
    fn from(error: Utf8Error) -> BlockchainError {
        BlockchainError::UtfError(error)
    }
}
