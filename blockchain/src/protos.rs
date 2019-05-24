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

use crate::transaction::PaymentTransaction;
use failure::{ensure, format_err, Error, Fail};
use stegos_serialization::traits::*;

use bitvector::BitVector;

use crate::view_changes::*;
use crate::*;
use stegos_crypto::bulletproofs::BulletProof;
use stegos_crypto::curve1174::{EncryptedPayload, Fr, Pt, PublicKey, SchnorrSig};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

#[derive(Debug, Fail)]
pub enum ProtoError {
    #[fail(display = "Missing field '{}' in packet '{}'.", _1, _0)]
    MissingField(String, String),
    #[fail(display = "Duplicate value in field '{}'.", _0)]
    DuplicateValue(String),
}

// link protobuf dependencies
use stegos_crypto::protos::*;
use stegos_crypto::CryptoError;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for PaymentOutput {
    type Proto = blockchain::PaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_cloaking_hint(self.cloaking_hint.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let cloaking_hint = Pt::from_proto(proto.get_cloaking_hint())?;
        let proof = BulletProof::from_proto(proto.get_proof())?;
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(PaymentOutput {
            recipient,
            cloaking_hint,
            proof,
            payload,
        })
    }
}

impl ProtoConvert for PublicPaymentOutput {
    type Proto = blockchain::PublicPaymentOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PublicPaymentOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_amount(self.amount);
        proto.set_serno(self.serno);
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let amount = proto.get_amount();
        let serno = proto.get_serno();
        Ok(PublicPaymentOutput {
            recipient,
            amount,
            serno,
        })
    }
}

impl ProtoConvert for StakeOutput {
    type Proto = blockchain::StakeOutput;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::StakeOutput::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_validator(self.validator.into_proto());
        proto.set_amount(self.amount);
        proto.set_serno(self.serno);
        proto.set_signature(self.signature.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let validator = pbc::PublicKey::from_proto(proto.get_validator())?;
        let amount = proto.get_amount();
        let serno = proto.get_serno();
        let signature = pbc::Signature::from_proto(proto.get_signature())?;
        Ok(StakeOutput {
            recipient,
            validator,
            amount,
            serno,
            signature,
        })
    }
}

impl ProtoConvert for Output {
    type Proto = blockchain::Output;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Output::new();
        match self {
            Output::PaymentOutput(output) => proto.set_payment_output(output.into_proto()),
            Output::PublicPaymentOutput(output) => {
                proto.set_public_payment_output(output.into_proto())
            }
            Output::StakeOutput(output) => proto.set_stake_output(output.into_proto()),
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        match proto.output {
            Some(blockchain::Output_oneof_output::payment_output(ref output)) => {
                let output = PaymentOutput::from_proto(output)?;
                Ok(Output::PaymentOutput(output))
            }
            Some(blockchain::Output_oneof_output::public_payment_output(ref output)) => {
                let output = PublicPaymentOutput::from_proto(output)?;
                Ok(Output::PublicPaymentOutput(output))
            }
            Some(blockchain::Output_oneof_output::stake_output(ref output)) => {
                let output = StakeOutput::from_proto(output)?;
                Ok(Output::StakeOutput(output))
            }
            None => {
                Err(ProtoError::MissingField("output".to_string(), "output".to_string()).into())
            }
        }
    }
}

impl ProtoConvert for CoinbaseTransaction {
    type Proto = blockchain::CoinbaseTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::CoinbaseTransaction::new();
        proto.set_block_reward(self.block_reward);
        proto.set_block_fee(self.block_fee);
        proto.set_gamma(self.gamma.into_proto());
        for output in &self.txouts {
            proto.txouts.push(output.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block_reward = proto.get_block_reward();
        let block_fee = proto.get_block_fee();
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for output in proto.txouts.iter() {
            txouts.push(Output::from_proto(output)?);
        }
        Ok(CoinbaseTransaction {
            block_reward,
            block_fee,
            gamma,
            txouts,
        })
    }
}

impl ProtoConvert for PaymentTransaction {
    type Proto = blockchain::PaymentTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::PaymentTransaction::new();

        for txin in &self.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_gamma(self.gamma.into_proto());
        proto.set_fee(self.fee);
        proto.set_sig(self.sig.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let fee = proto.get_fee();
        let sig = SchnorrSig::from_proto(proto.get_sig())?;

        Ok(PaymentTransaction {
            txins,
            txouts,
            gamma,
            fee,
            sig,
        })
    }
}

impl ProtoConvert for RestakeTransaction {
    type Proto = blockchain::RestakeTransaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::RestakeTransaction::new();

        for txin in &self.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_signature(self.sig.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }
        let sig = pbc::secure::Signature::from_proto(proto.get_signature())?;

        Ok(RestakeTransaction { txins, txouts, sig })
    }
}

impl ProtoConvert for Transaction {
    type Proto = blockchain::Transaction;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Transaction::new();
        match self {
            Transaction::CoinbaseTransaction(coinbase_transaction) => {
                proto.set_coinbase_transaction(coinbase_transaction.into_proto())
            }
            Transaction::PaymentTransaction(payment_transaction) => {
                proto.set_payment_transaction(payment_transaction.into_proto())
            }
            Transaction::RestakeTransaction(restake_transaction) => {
                proto.set_restake_transaction(restake_transaction.into_proto())
            }
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let transaction = match proto.transaction {
            Some(blockchain::Transaction_oneof_transaction::coinbase_transaction(
                ref coinbase_transaction,
            )) => {
                let coinbase_transaction = CoinbaseTransaction::from_proto(coinbase_transaction)?;
                Transaction::CoinbaseTransaction(coinbase_transaction)
            }
            Some(blockchain::Transaction_oneof_transaction::payment_transaction(
                ref payment_transaction,
            )) => {
                let payment_transaction = PaymentTransaction::from_proto(payment_transaction)?;
                Transaction::PaymentTransaction(payment_transaction)
            }
            Some(blockchain::Transaction_oneof_transaction::restake_transaction(
                ref restake_transaction,
            )) => {
                let restake_transaction = RestakeTransaction::from_proto(restake_transaction)?;
                Transaction::RestakeTransaction(restake_transaction)
            }
            None => {
                return Err(ProtoError::MissingField(
                    "transaction".to_string(),
                    "transaction".to_string(),
                )
                .into());
            }
        };
        Ok(transaction)
    }
}

impl ProtoConvert for BaseBlockHeader {
    type Proto = blockchain::BaseBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::BaseBlockHeader::new();
        proto.set_version(self.version);
        proto.set_previous(self.previous.into_proto());
        proto.set_height(self.height);
        proto.set_view_change(self.view_change);
        proto.set_random(self.random.into_proto());
        let since_the_epoch = self
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time is valid");
        let timestamp = since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_millis() as u64;
        proto.set_timestamp(timestamp);
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let version = proto.get_version();
        let previous = Hash::from_proto(proto.get_previous())?;
        let height = proto.get_height();
        let view_change = proto.get_view_change();
        let timestamp =
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(proto.get_timestamp());
        let random = pbc::VRF::from_proto(proto.get_random())?;
        Ok(BaseBlockHeader {
            version,
            previous,
            height,
            view_change,
            timestamp,
            random,
        })
    }
}

impl ProtoConvert for MicroBlock {
    type Proto = blockchain::MicroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MicroBlock::new();
        proto.set_base(self.base.into_proto());
        if let Some(view_change_proof) = &self.view_change_proof {
            proto.set_view_change_proof(view_change_proof.into_proto())
        }
        for transaction in &self.transactions {
            proto.transactions.push(transaction.into_proto());
        }
        proto.set_pkey(self.pkey.into_proto());
        proto.set_sig(self.sig.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let view_change_proof = if proto.has_view_change_proof() {
            Some(ViewChangeProof::from_proto(proto.get_view_change_proof())?)
        } else {
            None
        };
        let mut transactions = Vec::<Transaction>::with_capacity(proto.transactions.len());
        for transaction in proto.transactions.iter() {
            transactions.push(Transaction::from_proto(transaction)?);
        }
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;
        let sig = if proto.has_sig() {
            pbc::Signature::from_proto(proto.get_sig())?
        } else {
            pbc::Signature::zero()
        };
        Ok(MicroBlock {
            base,
            view_change_proof,
            transactions,
            pkey,
            sig,
        })
    }
}

impl ProtoConvert for SerializedNode<Box<Output>> {
    type Proto = blockchain::MerkleNode;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MerkleNode::new();
        proto.set_hash(self.hash.into_proto());
        if let Some(left) = self.left {
            proto.set_left(left as u64 + 1);
        } else {
            proto.set_left(0);
        }
        if let Some(right) = self.right {
            proto.set_right(right as u64 + 1);
        } else {
            proto.set_right(0);
        }
        if let Some(ref value) = self.value {
            proto.set_value(value.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let hash = Hash::from_proto(proto.get_hash())?;
        let left = if proto.get_left() > 0 {
            Some((proto.get_left() - 1) as usize)
        } else {
            None
        };
        let right = if proto.get_right() > 0 {
            Some((proto.get_right() - 1) as usize)
        } else {
            None
        };
        let value = if proto.has_value() {
            Some(Box::new(Output::from_proto(proto.get_value())?))
        } else {
            None
        };
        Ok(SerializedNode::<Box<Output>> {
            hash,
            left,
            right,
            value,
        })
    }
}

impl ProtoConvert for MacroBlockHeader {
    type Proto = blockchain::MacroBlockHeader;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MacroBlockHeader::new();
        proto.set_base(self.base.into_proto());
        proto.set_gamma(self.gamma.into_proto());
        proto.set_block_reward(self.block_reward);
        proto.set_inputs_range_hash(self.inputs_range_hash.into_proto());
        proto.set_outputs_range_hash(self.outputs_range_hash.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let base = BaseBlockHeader::from_proto(proto.get_base())?;
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let block_reward = proto.get_block_reward();
        let inputs_range_hash = Hash::from_proto(proto.get_inputs_range_hash())?;
        let outputs_range_hash = Hash::from_proto(proto.get_outputs_range_hash())?;

        Ok(MacroBlockHeader {
            base,
            gamma,
            block_reward,
            inputs_range_hash,
            outputs_range_hash,
        })
    }
}

impl ProtoConvert for MacroBlockBody {
    type Proto = blockchain::MacroBlockBody;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MacroBlockBody::new();
        proto.set_sig(self.multisig.into_proto());
        proto.set_pkey(self.pkey.into_proto());
        if !self.multisigmap.is_empty() {
            assert!(self.multisigmap.len() <= VALIDATORS_MAX);
            proto.sigmap.resize(VALIDATORS_MAX, false);
            for bit in self.multisigmap.iter() {
                proto.sigmap[bit] = true;
            }
        }

        for input in &self.inputs {
            proto.inputs.push(input.into_proto());
        }
        for output in self.outputs.serialize() {
            proto.outputs.push(output.into_proto());
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;
        let multisig = if proto.has_sig() {
            pbc::Signature::from_proto(proto.get_sig())?
        } else {
            pbc::Signature::zero()
        };
        if proto.sigmap.len() > VALIDATORS_MAX {
            return Err(
                CryptoError::InvalidBinaryLength(VALIDATORS_MAX, proto.sigmap.len()).into(),
            );
        }
        let mut multisigmap = BitVector::new(VALIDATORS_MAX);
        for (bit, val) in proto.sigmap.iter().enumerate() {
            if *val {
                multisigmap.insert(bit);
            }
        }

        let mut inputs = Vec::<Hash>::with_capacity(proto.inputs.len());
        for input in proto.inputs.iter() {
            inputs.push(Hash::from_proto(input)?);
        }

        let mut outputs = Vec::with_capacity(proto.outputs.len());
        for output in proto.outputs.iter() {
            outputs.push(SerializedNode::<Box<Output>>::from_proto(output)?);
        }
        let outputs = Merkle::deserialize(&outputs)?;

        Ok(MacroBlockBody {
            pkey,
            multisig,
            multisigmap,
            inputs,
            outputs,
        })
    }
}

impl ProtoConvert for MacroBlock {
    type Proto = blockchain::MacroBlock;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::MacroBlock::new();
        proto.set_header(self.header.into_proto());
        proto.set_body(self.body.into_proto());
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let header = MacroBlockHeader::from_proto(proto.get_header())?;
        let body = MacroBlockBody::from_proto(proto.get_body())?;
        Ok(MacroBlock { header, body })
    }
}

impl ProtoConvert for Block {
    type Proto = blockchain::Block;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = blockchain::Block::new();
        match self {
            Block::MacroBlock(macro_block) => proto.set_macro_block(macro_block.into_proto()),
            Block::MicroBlock(micro_block) => proto.set_micro_block(micro_block.into_proto()),
        }
        proto
    }

    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let block = match proto.block {
            Some(blockchain::Block_oneof_block::macro_block(ref macro_block)) => {
                let macro_block = MacroBlock::from_proto(macro_block)?;
                Block::MacroBlock(macro_block)
            }
            Some(blockchain::Block_oneof_block::micro_block(ref micro_block)) => {
                let micro_block = MicroBlock::from_proto(micro_block)?;
                Block::MicroBlock(micro_block)
            }
            None => {
                return Err(
                    ProtoError::MissingField("block".to_string(), "block".to_string()).into(),
                );
            }
        };
        Ok(block)
    }
}

impl ProtoConvert for ChainInfo {
    type Proto = view_changes::ChainInfo;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_changes::ChainInfo::new();
        proto.set_height(self.height);
        proto.set_last_block(self.last_block.into_proto());
        proto.set_view_change(self.view_change);
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let height = proto.get_height();
        let view_change = proto.get_view_change();
        let last_block = Hash::from_proto(proto.get_last_block())?;
        Ok(ChainInfo {
            height,
            view_change,
            last_block,
        })
    }
}

impl ProtoConvert for ViewChangeProof {
    type Proto = view_changes::ViewChangeProof;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = view_changes::ViewChangeProof::new();
        if !self.multisig.is_zero() {
            proto.set_multisig(self.multisig.into_proto());
        }
        if !self.multimap.is_empty() {
            assert!(self.multimap.len() <= VALIDATORS_MAX);
            proto.multimap.resize(VALIDATORS_MAX, false);
            for bit in self.multimap.iter() {
                proto.multimap[bit] = true;
            }
        }
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let multisig = if proto.has_multisig() {
            pbc::Signature::from_proto(proto.get_multisig())?
        } else {
            pbc::Signature::zero()
        };
        ensure!(
            proto.multimap.len() <= VALIDATORS_MAX,
            format_err!(
                "multimap greater than max count of max validators: map_len={}",
                proto.multimap.len()
            )
        );
        let mut multimap = BitVector::new(VALIDATORS_MAX);
        for (bit, val) in proto.multimap.iter().enumerate() {
            if *val {
                multimap.insert(bit);
            }
        }
        Ok(ViewChangeProof { multisig, multimap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use stegos_crypto::curve1174;
    use stegos_crypto::hash::{Hash, Hashable, Hasher};
    use stegos_crypto::pbc;

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn outputs() {
        let (_skey1, pkey1) = curve1174::make_random_keys();
        let (network_skey1, network_pkey1) = pbc::make_random_keys();

        let amount = 1_000_000;

        let (output, _gamma) = Output::new_payment(&pkey1, amount).expect("keys are valid");
        roundtrip(&output);

        let output = Output::new_stake(&pkey1, &network_skey1, &network_pkey1, amount)
            .expect("keys are valid");
        roundtrip(&output);

        let mut buf = output.into_buffer().unwrap();
        buf.pop();
        Output::from_buffer(&buf).expect_err("error");
    }

    fn mktransaction() -> PaymentTransaction {
        let (skey1, pkey1) = curve1174::make_random_keys();
        let (_skey2, pkey2) = curve1174::make_random_keys();

        let amount: i64 = 1_000_000;
        let fee: i64 = 0;

        // "genesis" output by 0
        let (output0, _delta0) = Output::new_payment(&pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output11, gamma11) = Output::new_payment(&pkey2, amount).expect("keys are valid");

        roundtrip(&output11);
        roundtrip(&gamma11);

        let outputs_gamma = gamma11;

        let tx = PaymentTransaction::new(&skey1, &inputs1, &[output11], &outputs_gamma, fee)
            .expect("keys are valid");
        tx.validate(&inputs1).unwrap();

        let tx2 = roundtrip(&tx);
        tx2.validate(&inputs1).unwrap();

        tx
    }

    #[test]
    fn coinbase_transaction() {
        let (_skey, pkey) = curve1174::make_random_keys();
        let (output, gamma) = Output::new_payment(&pkey, 100).expect("Invalid keys");
        let coinbase = CoinbaseTransaction {
            block_reward: 15,
            block_fee: 100,
            gamma: -gamma,
            txouts: vec![output],
        };
        roundtrip(&coinbase);
    }

    #[test]
    fn payment_transaction() {
        let tx = mktransaction();
        roundtrip(&tx);
        let tx: Transaction = tx.into();
        roundtrip(&tx);

        let mut buf = tx.into_buffer().unwrap();
        buf.pop();
        PaymentTransaction::from_buffer(&buf).expect_err("error");
    }

    #[test]
    fn micro_blocks() {
        let (skey, pkey) = curve1174::make_random_keys();
        let (skeypbc, pkeypbc) = pbc::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let previous = Hash::digest(&"test".to_string());
        let seed = mix(Hash::digest("random"), view_change);
        let random = pbc::make_VRF(&skeypbc, &seed);
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        roundtrip(&base);

        // View Changes Proof.
        let sig = pbc::sign_hash(&previous, &skeypbc);
        let signatures = vec![(1u32, &sig)];
        let view_change_proof = Some(ViewChangeProof::new(signatures.into_iter()));

        // Transactions.
        let (tx, _inputs, _outputs) =
            PaymentTransaction::new_test(&skey, &pkey, 300, 2, 100, 1, 100)
                .expect("Invalid transaction");
        let transactions: Vec<Transaction> = vec![tx.into()];

        let mut block = MicroBlock::new(base, view_change_proof, transactions, pkeypbc);
        block.sign(&skeypbc, &pkeypbc);
        let block2 = roundtrip(&block);
        assert_eq!(block2.pkey, block.pkey);
        assert_eq!(block2.sig, block.sig);
    }

    impl Hashable for MacroBlockBody {
        fn hash(&self, state: &mut Hasher) {
            "Monetary".hash(state);
            self.multisig.hash(state);
            // TODO: check mulitisigmap?
            let inputs_count: u64 = self.inputs.len() as u64;
            inputs_count.hash(state);
            for input in &self.inputs {
                input.hash(state);
            }
            self.outputs.roothash().hash(state)
        }
    }

    #[test]
    fn macro_blocks() {
        let (_skey1, pkey1) = curve1174::make_random_keys();
        let (_skey2, pkey2) = curve1174::make_random_keys();
        let (skeypbc, pkeypbc) = pbc::make_random_keys();

        let version: u64 = 1;
        let height: u64 = 0;
        let timestamp = SystemTime::now();
        let view_change = 0;
        let amount: i64 = 1_000_000;
        let previous = Hash::digest(&"test".to_string());

        // "genesis" output by 0
        let (output0, gamma0) = Output::new_payment(&pkey1, amount).unwrap();

        // Transaction from 1 to 2
        let inputs1 = [Hash::digest(&output0)];
        let (output1, gamma1) = Output::new_payment(&pkey2, amount).unwrap();
        let outputs1 = [output1];
        let gamma = gamma0 - gamma1;

        let seed = mix(Hash::digest("random"), view_change);
        let random = pbc::make_VRF(&skeypbc, &seed);
        let base = BaseBlockHeader::new(version, previous, height, view_change, timestamp, random);
        roundtrip(&base);

        let block = MacroBlock::new(base, gamma, 0, &inputs1, &outputs1, pkeypbc);
        roundtrip(&block.header);
        roundtrip(&block.body);
        roundtrip(&block);

        let block = Block::MacroBlock(block);
        roundtrip(&block);
    }
}
