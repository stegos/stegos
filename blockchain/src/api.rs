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
use crate::block::{MacroBlock, MacroBlockHeader, MicroBlock, MicroBlockHeader};
use crate::output::{Output, PaymentOutput, PublicPaymentOutput, StakeOutput};
use crate::transaction::Transaction;
use bit_vec::BitVec;
use serde_derive::{Deserialize, Serialize};
use stegos_crypto::{hash::Hash, pbc, scc};

/// Macro Block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroBlockInfo {
    pub block_hash: Hash,
    /// Header.
    #[serde(flatten)]
    pub header: MacroBlockHeader,

    /// BLS (multi-)signature.
    pub multisig: pbc::Signature,

    /// Bitmap of signers in the multi-signature.
    #[serde(deserialize_with = "stegos_crypto::utils::deserialize_bitvec")]
    #[serde(serialize_with = "stegos_crypto::utils::serialize_bitvec")]
    pub multisigmap: BitVec,

    /// The list of transaction inputs in a Merkle Tree.
    pub inputs: Vec<Hash>,

    /// The list of transaction outputs in a Merkle Tree.
    pub outputs: Vec<Output>,
}

impl From<MacroBlock> for MacroBlockInfo {
    fn from(b: MacroBlock) -> MacroBlockInfo {
        MacroBlockInfo {
            block_hash: Hash::digest(&b),
            header: b.header,
            multisig: b.multisig,
            multisigmap: b.multisigmap,
            inputs: b.inputs,
            outputs: b.outputs,
        }
    }
}

impl From<MacroBlockInfo> for MacroBlock {
    fn from(b: MacroBlockInfo) -> MacroBlock {
        MacroBlock {
            header: b.header,
            multisig: b.multisig,
            multisigmap: b.multisigmap,
            inputs: b.inputs,
            outputs: b.outputs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroBlockInfo {
    pub block_hash: Hash,
    /// Header.
    #[serde(flatten)]
    pub header: MicroBlockHeader,

    /// BLS signature by leader.
    pub sig: pbc::Signature,

    /// Transactions.
    pub transactions: Vec<Transaction>,
}

impl From<MicroBlock> for MicroBlockInfo {
    fn from(b: MicroBlock) -> MicroBlockInfo {
        MicroBlockInfo {
            block_hash: Hash::digest(&b),
            header: b.header,
            sig: b.sig,
            transactions: b.transactions,
        }
    }
}

impl From<MicroBlockInfo> for MicroBlock {
    fn from(b: MicroBlockInfo) -> MicroBlock {
        MicroBlock {
            header: b.header,
            sig: b.sig,
            transactions: b.transactions,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum OriginalOutput {
    PaymentOutput(PaymentOutput),
    PublicPaymentOutput(PublicPaymentOutput),
    StakeOutput(StakeOutput),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputInfo {
    output_hash: Hash,
    #[serde(flatten)]
    output: OriginalOutput,
}

impl From<Output> for OriginalOutput {
    fn from(b: Output) -> OriginalOutput {
        match b {
            Output::PaymentOutput(p) => OriginalOutput::PaymentOutput(p),
            Output::PublicPaymentOutput(p) => OriginalOutput::PublicPaymentOutput(p),
            Output::StakeOutput(p) => OriginalOutput::StakeOutput(p),
        }
    }
}
impl From<OriginalOutput> for Output {
    fn from(b: OriginalOutput) -> Output {
        match b {
            OriginalOutput::PaymentOutput(p) => Output::PaymentOutput(p),
            OriginalOutput::PublicPaymentOutput(p) => Output::PublicPaymentOutput(p),
            OriginalOutput::StakeOutput(p) => Output::StakeOutput(p),
        }
    }
}

impl From<Output> for OutputInfo {
    fn from(b: Output) -> OutputInfo {
        OutputInfo {
            output_hash: Hash::digest(&b),
            output: b.into(),
        }
    }
}

impl From<OutputInfo> for Output {
    fn from(b: OutputInfo) -> Output {
        b.output.into()
    }
}

#[derive(Eq, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicOutputInfo {
    pub output_hash: Hash,
    pub amount: i64,
}

#[derive(Eq, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicOutputsInfo {
    pub epoch: u64,
    pub offset: u32,
    pub balance: i64,
    pub outputs: Vec<PublicOutputInfo>,
    pub pkey: scc::PublicKey,
}
