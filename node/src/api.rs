//! Node - API.

//
// Copyright (c) 2019 Stegos AG
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
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use stegos_blockchain::{
    ElectionInfo, EscrowInfo, Output, Timestamp, Transaction, WalletRecoveryState,
};
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};

///
/// RPC requests.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request")]
#[serde(rename_all = "snake_case")]
pub enum NodeRequest {
    ElectionInfo {},
    EscrowInfo {},
    PopBlock {},
    #[serde(skip)]
    RecoverWallet {
        /// Wallet Secret Key.
        wallet_skey: scc::SecretKey,
        /// Wallet Public Key.
        wallet_pkey: scc::PublicKey,
    },
}

///
/// RPC responses.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response")]
#[serde(rename_all = "snake_case")]
pub enum NodeResponse {
    ElectionInfo(ElectionInfo),
    EscrowInfo(EscrowInfo),
    BlockPopped,
    #[serde(skip)]
    WalletRecovered(WalletRecoveryState),
    Error {
        error: String,
    },
}

/// Send when synchronization status has been changed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncChanged {
    pub is_synchronized: bool,
    pub epoch: u64,
    pub offset: u32,
    pub view_change: u32,
    pub last_block_hash: Hash,
    pub last_macro_block_hash: Hash,
    pub last_macro_block_timestamp: Timestamp,
    pub local_timestamp: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewMacroBlock {
    pub epoch: u64,
    pub last_macro_block_timestamp: Timestamp,
    pub facilitator: pbc::PublicKey,
    pub validators: Vec<(pbc::PublicKey, i64)>,
    #[serde(skip)]
    pub inputs: Vec<Output>,
    #[serde(skip)]
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackMicroBlock {
    pub epoch: u64,
    pub offset: u32,
    #[serde(skip)]
    pub recovered_transaction: HashMap<Hash, Transaction>,
    pub statuses: HashMap<Hash, TransactionStatus>,
    #[serde(skip)]
    pub inputs: Vec<Output>,
    #[serde(skip)]
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewMicroBlock {
    pub epoch: u64,
    pub offset: u32,
    #[serde(skip)]
    pub transactions: HashMap<Hash, Transaction>,
    pub statuses: HashMap<Hash, TransactionStatus>,
    #[serde(skip)]
    pub inputs: Vec<Output>,
    #[serde(skip)]
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "notification")]
#[serde(rename_all = "snake_case")]
pub enum NodeNotification {
    NewMicroBlock(NewMicroBlock),
    NewMacroBlock(NewMacroBlock),
    RollbackMicroBlock(RollbackMicroBlock),
    SyncChanged(SyncChanged),
}

impl From<SyncChanged> for NodeNotification {
    fn from(sync: SyncChanged) -> NodeNotification {
        NodeNotification::SyncChanged(sync)
    }
}

impl From<NewMacroBlock> for NodeNotification {
    fn from(block: NewMacroBlock) -> NodeNotification {
        NodeNotification::NewMacroBlock(block)
    }
}

impl From<NewMicroBlock> for NodeNotification {
    fn from(block: NewMicroBlock) -> NodeNotification {
        NodeNotification::NewMicroBlock(block)
    }
}

impl From<RollbackMicroBlock> for NodeNotification {
    fn from(block: RollbackMicroBlock) -> NodeNotification {
        NodeNotification::RollbackMicroBlock(block)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionStatus {
    Created {},
    Accepted {},
    Rejected {
        error: String,
    },
    /// Transaction was included in microblock.
    Prepare {
        epoch: u64,
        offset: u32,
    },
    /// Transaction was reverted back to mempool.
    Rollback {
        epoch: u64,
        offset: u32,
    },
    /// Transaction was committed to macro block.
    Committed {
        epoch: u64,
    },
    /// Transaction was rejected, because other conflicted
    Conflicted {
        epoch: u64,
        conflict_tx: Option<Hash>,
    },
}
