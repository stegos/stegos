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
use super::replication::api::*;
use futures::sync::mpsc;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use stegos_blockchain::{
    ElectionInfo, EpochInfo, EscrowInfo, MacroBlock, MicroBlock, Output, PublicPaymentOutput,
    Timestamp, Transaction, ValidatorKeyInfo,
};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::scc;
use stegos_crypto::utils::{deserialize_protobuf_from_hex, serialize_protobuf_to_hex};

///
/// RPC requests.
///
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NodeRequest {
    ElectionInfo {},
    EscrowInfo {},
    ReplicationInfo {},
    PopMicroBlock {},
    ChainName {},
    BroadcastTransaction {
        #[serde(serialize_with = "serialize_protobuf_to_hex")]
        #[serde(deserialize_with = "deserialize_protobuf_from_hex")]
        data: Transaction,
    },
    PublicOutputs {
        pkey: scc::PublicKey,
    },
    ValidateCertificate {
        output_hash: Hash,
        spender: scc::PublicKey,
        recipient: scc::PublicKey,
        rvalue: scc::Fr,
    },
    EnableRestaking {},
    DisableRestaking {},
    ChangeUpstream {},
    StatusInfo {},
    ValidatorsInfo {},
    SubscribeStatus {},
    MacroBlockInfo {
        epoch: u64,
    },
    MicroBlockInfo {
        epoch: u64,
        offset: u32,
    },
    SubscribeChain {
        epoch: u64,
        offset: u32,
    },
}

///
/// RPC responses.
///
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NodeResponse {
    ElectionInfo(ElectionInfo),
    EscrowInfo(EscrowInfo),
    ReplicationInfo(ReplicationInfo),
    MicroBlockPopped,
    ChainName {
        name: String,
    },
    #[serde(skip)]
    BroadcastTransaction {
        hash: Hash,
        status: TransactionStatus,
    },
    PublicOutputs {
        epoch: u64,
        list: Vec<PublicPaymentOutput>,
    },
    CertificateValid {
        epoch: u64,
        block_hash: Hash,
        is_final: bool,
        timestamp: Timestamp,
        amount: i64,
    },
    RestakingEnabled,
    RestakingDisabled,
    UpstreamChanged,
    StatusInfo(StatusInfo),
    ValidatorsInfo {
        epoch: u64,
        offset: u32,
        view_change: u32,
        validators: Vec<ValidatorKeyInfo>,
    },
    SubscribedStatus {
        #[serde(flatten)]
        status: StatusInfo,
        #[serde(skip)]
        rx: Option<mpsc::Receiver<StatusNotification>>, // Option is needed for serde.
    },
    MacroBlockInfo(ExtendedMacroBlock),
    MicroBlockInfo(ExtendedMicroBlock),
    SubscribedChain {
        current_epoch: u64,
        current_offset: u32,
        #[serde(skip)]
        rx: Option<mpsc::Receiver<ChainNotification>>, // Option is needed for serde.
    },
    Error {
        error: String,
    },
}

/// Notification about synchronization status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub is_synchronized: bool,
    pub epoch: u64,
    pub offset: u32,
    pub view_change: u32,
    pub last_block_hash: Hash,
    pub last_macro_block_hash: Hash,
    pub last_macro_block_timestamp: Timestamp,
    pub local_timestamp: Timestamp,
}

/// Status notifications.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum StatusNotification {
    StatusChanged(StatusInfo),
}

impl From<StatusInfo> for StatusNotification {
    fn from(status: StatusInfo) -> StatusNotification {
        StatusNotification::StatusChanged(status)
    }
}

/// Blockchain notifications.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum ChainNotification {
    MicroBlockPrepared(ExtendedMicroBlock),
    MicroBlockReverted(RevertedMicroBlock),
    MacroBlockCommitted(ExtendedMacroBlock),
}

/// A macro block with extra information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedMacroBlock {
    /// Committed macro block.
    #[serde(flatten)]
    pub block: MacroBlock,
    /// Collected information about epoch.
    #[serde(flatten)]
    pub epoch_info: EpochInfo,
    // Transaction statuses.
    #[serde(skip)] // internal API for wallet.
    pub transaction_statuses: HashMap<Hash, TransactionStatus>,
}

impl ExtendedMacroBlock {
    pub fn inputs(&self) -> impl Iterator<Item = &Hash> {
        self.block.inputs.iter()
    }
    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.block.outputs.iter()
    }
}

/// Information about reverted micro block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevertedMicroBlock {
    #[serde(flatten)]
    pub block: MicroBlock,
    #[serde(skip)] // internal API for wallet
    pub transaction_statuses: HashMap<Hash, TransactionStatus>,
    #[serde(skip)] // internal API for wallet
    pub recovered_inputs: HashMap<Hash, Output>,
    #[serde(skip)] // internal API for wallet
    pub pruned_outputs: Vec<Hash>,
}

impl RevertedMicroBlock {
    pub fn pruned_outputs(&self) -> impl Iterator<Item = &Hash> {
        self.pruned_outputs.iter()
    }
    pub fn recovered_inputs(&self) -> impl Iterator<Item = &Output> {
        self.recovered_inputs.values()
    }
}

/// PA micro block with extra information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedMicroBlock {
    #[serde(flatten)]
    pub block: MicroBlock,
    #[serde(skip)] // internal API for wallet.
    pub transaction_statuses: HashMap<Hash, TransactionStatus>,
}

impl ExtendedMicroBlock {
    pub fn inputs(&self) -> impl Iterator<Item = &Hash> {
        self.block.transactions.iter().flat_map(|tx| tx.txins())
    }
    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.block.transactions.iter().flat_map(|tx| tx.txouts())
    }
}

impl From<ExtendedMacroBlock> for ChainNotification {
    fn from(block: ExtendedMacroBlock) -> ChainNotification {
        ChainNotification::MacroBlockCommitted(block)
    }
}

impl From<ExtendedMicroBlock> for ChainNotification {
    fn from(block: ExtendedMicroBlock) -> ChainNotification {
        ChainNotification::MicroBlockPrepared(block)
    }
}

impl From<RevertedMicroBlock> for ChainNotification {
    fn from(block: RevertedMicroBlock) -> ChainNotification {
        ChainNotification::MicroBlockReverted(block)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "status")]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Created {},
    Accepted {},
    Rejected {
        error: String,
    },
    /// Transaction was included in microblock.
    Prepared {
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
        offset: Option<u32>,
    },
}

impl Hashable for TransactionStatus {
    fn hash(&self, hasher: &mut Hasher) {
        match self {
            TransactionStatus::Created {} => "Created".hash(hasher),
            TransactionStatus::Accepted {} => "Accepted".hash(hasher),
            TransactionStatus::Rejected { error } => {
                "Rejected".hash(hasher);
                error.hash(hasher)
            }
            TransactionStatus::Prepared { epoch, offset } => {
                "Prepare".hash(hasher);
                epoch.hash(hasher);
                offset.hash(hasher);
            }
            TransactionStatus::Rollback { epoch, offset } => {
                "Rollback".hash(hasher);
                epoch.hash(hasher);
                offset.hash(hasher);
            }
            TransactionStatus::Committed { epoch } => {
                "Committed".hash(hasher);
                epoch.hash(hasher);
            }
            TransactionStatus::Conflicted { epoch, offset } => {
                "Conflicted".hash(hasher);

                epoch.hash(hasher);
                if let Some(offset) = offset {
                    "some".hash(hasher);
                    offset.hash(hasher);
                } else {
                    "none".hash(hasher);
                }
            }
        }
    }
}
