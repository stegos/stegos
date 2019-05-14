//! Transaction output.

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

use failure::{Error, Fail};
use rand::random;
use serde_derive::Serialize;
use std::mem::transmute;
use stegos_crypto::bulletproofs::{fee_a, make_range_proof, validate_range_proof, BulletProof};
use stegos_crypto::curve1174::cpt::{
    aes_decrypt, aes_encrypt, EncryptedPayload, Pt, PublicKey, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::{Fq, Fr};
use stegos_crypto::curve1174::{G, UNIQ};
use stegos_crypto::hash::{Hash, Hashable, Hasher, HASH_SIZE};
use stegos_crypto::pbc::secure;
use stegos_crypto::CryptoError;

/// A magic value used to encode/decode payload.
const PAYMENT_PAYLOAD_MAGIC: [u8; 4] = [112, 97, 121, 109]; // "paym"

/// Exact size of encrypted payload of PaymentOutput.
pub const PAYMENT_PAYLOAD_LEN: usize = 1024;

/// Maximum length of data field of encrypted payload of PaymentOutput.
/// Equals to PAYMENT_PAYLOAD_LEN - magic - delta - gamma - amount.
pub const PAYMENT_DATA_LEN: usize = PAYMENT_PAYLOAD_LEN - 4 - 32 - 32 - 8;

/// UTXO errors.
#[derive(Debug, Fail)]
pub enum OutputError {
    #[fail(display = "Invalid stake: utxo={}", _0)]
    InvalidStake(Hash),
    #[fail(display = "Invalid bulletproof: utxo={}", _0)]
    InvalidBulletProof(Hash),
    #[fail(
        display = "Invalid payload length: utxo={}, expected={}, got={}",
        _0, _1, _2
    )]
    InvalidPayloadLength(Hash, usize, usize),
    #[fail(display = "Failed to decrypt payload: utxo={}", _0)]
    PayloadDecryptionError(Hash),
    #[fail(display = "Data is too long: max={}, got={}", _0, _1)]
    DataIsTooLong(usize, usize),
    #[fail(display = "Unsupported data type: utxo={}, typecode={}", _0, _1)]
    UnsupportedDataType(Hash, u8),
    #[fail(display = "Trailing garbage in payload: utxo={}", _0)]
    TrailingGarbage(Hash),
    #[fail(display = "Negative amount: utxo={}, amount={}", _0, _1)]
    NegativeAmount(Hash, i64),
    #[fail(display = "Invalid signature on validator pkey: utxo={}", _0)]
    InvalidStakeSignature(Hash),
}

/// Payment UTXO.
#[derive(Debug, Clone)]
pub struct PaymentOutput {
    /// Cloaked public key of recipient.
    pub recipient: PublicKey,

    /// Cloaking hint for recipient, to speed up UTXO search.
    pub cloaking_hint: Pt,

    /// Bulletproof on range on amount x.
    /// Contains Pedersen commitment.
    /// Size is approx. 1 KB (very structured data type).
    pub proof: BulletProof,

    /// Encrypted payload.
    ///
    /// E_M(x, γ, δ)
    /// Represents an encrypted packet contain the information about x, γ, δ
    /// that only receiver can red
    /// Size is approx 137 Bytes =
    ///     (R-val 65B, crypto-text 72B = (amount 8B, gamma 32B, delta 32B))
    pub payload: EncryptedPayload,
}

/// PublicPayment UTXO.
#[derive(Debug, Clone)]
pub struct PublicPaymentOutput {
    /// Uncloaked public key of recipient.
    pub recipient: PublicKey,

    /// Randomize for hash collision avoidance
    pub serno: i64,

    /// Uncloaked amount
    pub amount: i64,
}

/// Stake UTXO.
#[derive(Debug, Clone)]
pub struct StakeOutput {
    /// Uncloaked wallet key of validator.
    pub recipient: PublicKey,

    /// Uncloaked network key of validator.
    pub validator: secure::PublicKey,

    /// Amount to stake.
    pub amount: i64,

    // some randomization to prevent hash collisions
    pub serno: i64,

    /// BLS signature of recipient, validator and payload.
    pub signature: secure::Signature,
}

/// Blockchain UTXO.
#[derive(Debug, Clone)]
pub enum Output {
    PaymentOutput(PaymentOutput),
    PublicPaymentOutput(PublicPaymentOutput),
    StakeOutput(StakeOutput),
}

/// Cloak recipient's public key.
fn cloak_key(recipient_pkey: &PublicKey, gamma: &Fr) -> Result<(PublicKey, Fr), Error> {
    // h is the digest of the recipients actual public key mixed with a timestamp.
    let mut hasher = Hasher::new();
    recipient_pkey.hash(&mut hasher);
    Fq::random().hash(&mut hasher);
    let h = hasher.result();
    let uniq = UNIQ.clone();

    // Use deterministic randomness here too, to protect against PRNG attacks.
    let delta: Fr = Fr::synthetic_random(&"PKey", &uniq, &h);

    // Resulting publickey will be a random-like value in a safe range of the field,
    // not too small, and not too large. This helps avoid brute force attacks, looking
    // for the discrete log corresponding to delta.

    let pt = recipient_pkey.decompress()?;
    let cloaked_pt = {
        if (*gamma) == Fr::zero() {
            pt + delta * (*G)
        } else {
            pt + (*gamma) * delta * (*G)
        }
    };
    let cloaked_pkey = PublicKey::from(cloaked_pt);
    Ok((cloaked_pkey, delta))
}

/// Unpacked data field of PaymentPayload.
#[derive(Serialize, Debug, Eq, PartialEq, Clone)]
pub enum PaymentPayloadData {
    /// A string up to PAYLOAD_DATA_LEN - 2 bytes inclusive.
    Comment(String),
    /// A hash of secret content.
    ContentHash(Hash),
}

impl PaymentPayloadData {
    fn discriminant(&self) -> u8 {
        match self {
            PaymentPayloadData::Comment(_) => 0,
            PaymentPayloadData::ContentHash(_) => 1,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        match &self {
            PaymentPayloadData::Comment(comment) => {
                let data_bytes = comment.as_bytes();
                if data_bytes.len() > PAYMENT_DATA_LEN - 2 {
                    return Err(
                        OutputError::DataIsTooLong(PAYMENT_DATA_LEN - 2, data_bytes.len()).into(),
                    );
                }
            }
            PaymentPayloadData::ContentHash(_hash) => {}
        }
        Ok(())
    }
}

/// Unpacked encrypted payload of PaymentOutput.
#[derive(Debug, Eq, PartialEq)]
pub struct PaymentPayload {
    pub delta: Fr,
    pub gamma: Fr,
    pub amount: i64,
    pub data: PaymentPayloadData,
}

impl PaymentPayload {
    /// Serialize and encrypt payload.
    fn encrypt(&self, pkey: &PublicKey) -> Result<EncryptedPayload, Error> {
        let mut payload: [u8; PAYMENT_PAYLOAD_LEN] = [0u8; PAYMENT_PAYLOAD_LEN];
        let mut pos: usize = 0;

        // Magic.
        payload[pos..pos + 4].copy_from_slice(&PAYMENT_PAYLOAD_MAGIC);
        pos += PAYMENT_PAYLOAD_MAGIC.len();

        // Gamma.
        let gamma_bytes: [u8; 32] = self.gamma.to_lev_u8();
        payload[pos..pos + gamma_bytes.len()].copy_from_slice(&gamma_bytes);
        pos += gamma_bytes.len();

        // Delta.
        let delta_bytes: [u8; 32] = self.delta.to_lev_u8();
        payload[pos..pos + delta_bytes.len()].copy_from_slice(&delta_bytes);
        pos += delta_bytes.len();

        // Amount.
        let amount_bytes: [u8; 8] = unsafe { transmute(self.amount.to_le()) };
        payload[pos..pos + amount_bytes.len()].copy_from_slice(&amount_bytes);
        pos += amount_bytes.len();

        // Data.
        payload[pos] = self.data.discriminant();
        pos += 1;
        self.data.validate().expect("is valid");
        match &self.data {
            PaymentPayloadData::Comment(comment) => {
                let data_bytes = comment.as_bytes();
                assert!(data_bytes.len() <= PAYMENT_DATA_LEN - 2);
                payload[pos..pos + data_bytes.len()].copy_from_slice(data_bytes);
                pos += data_bytes.len();
            }
            PaymentPayloadData::ContentHash(hash) => {
                let data_bytes = &hash.to_bytes();
                payload[pos..pos + data_bytes.len()].copy_from_slice(data_bytes);
                pos += data_bytes.len();
            }
        }

        // The rest is zeros.
        assert!(pos <= PAYMENT_PAYLOAD_LEN);

        // Encrypt payload.
        let payload = aes_encrypt(&payload, &pkey)?;
        Ok(payload)
    }

    /// Decrypt and deserialize payload.
    fn decrypt(
        output_hash: Hash,
        payload: &EncryptedPayload,
        skey: &SecretKey,
    ) -> Result<Self, Error> {
        if payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
            return Err(OutputError::InvalidPayloadLength(
                output_hash,
                PAYMENT_PAYLOAD_LEN,
                payload.ctxt.len(),
            )
            .into());
        }
        let payload: Vec<u8> = aes_decrypt(payload, skey)?;
        assert_eq!(payload.len(), PAYMENT_PAYLOAD_LEN);
        let mut pos: usize = 0;

        // Magic.
        let mut magic: [u8; 4] = [0u8; 4];
        magic.copy_from_slice(&payload[pos..pos + 4]);
        pos += 4;
        if magic != PAYMENT_PAYLOAD_MAGIC {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError(output_hash).into());
        }

        // Gamma.
        let mut gamma_bytes: [u8; 32] = [0u8; 32];
        gamma_bytes.copy_from_slice(&payload[pos..pos + 32]);
        pos += gamma_bytes.len();
        let gamma: Fr = Fr::from_lev_u8(gamma_bytes);

        // Delta.
        let mut delta_bytes: [u8; 32] = [0u8; 32];
        delta_bytes.copy_from_slice(&payload[pos..pos + 32]);
        pos += delta_bytes.len();
        let delta: Fr = Fr::from_lev_u8(delta_bytes);

        // Amount.
        let mut amount_bytes: [u8; 8] = [0u8; 8];
        amount_bytes.copy_from_slice(&payload[pos..pos + 8]);
        pos += amount_bytes.len();
        let amount: i64 = i64::from_le(unsafe { transmute(amount_bytes) });
        if amount < 0 {
            return Err(OutputError::NegativeAmount(output_hash, amount).into());
        }

        // Data.
        let code: u8 = payload[pos];
        pos += 1;
        let data = match code {
            0 => {
                let mut end: usize = payload.len();
                while end > pos && payload[end - 1] == 0 {
                    end -= 1;
                }
                let s = std::str::from_utf8(&payload[pos..end])?;
                pos = payload.len();
                PaymentPayloadData::Comment(s.to_string())
            }
            1 => {
                let hash = Hash::try_from_bytes(&payload[pos..pos + HASH_SIZE])?;
                pos += HASH_SIZE;
                PaymentPayloadData::ContentHash(hash)
            }
            code @ _ => return Err(OutputError::UnsupportedDataType(output_hash, code).into()),
        };

        // Check for trailing garbage.
        for byte in &payload[pos..] {
            if *byte != 0 {
                return Err(OutputError::TrailingGarbage(output_hash).into());
            }
        }

        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        Ok(payload)
    }
}

impl PaymentOutput {
    /// Create a new PaymentOutput with generic payload.
    pub fn with_payload(
        recipient_pkey: &PublicKey,
        amount: i64,
        data: PaymentPayloadData,
    ) -> Result<(Self, Fr), Error> {
        // Create range proofs.
        let (proof, gamma) = make_range_proof(amount);

        // Cloak recipient public key
        let (cloaked_pkey, delta) = cloak_key(recipient_pkey, &gamma)?;

        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        // NOTE: real public key should be used to encrypt payload
        let payload = payload.encrypt(recipient_pkey)?;

        // Key cloaking hint for recipient = gamma * delta * Pkey
        let hint = recipient_pkey.decompress()? * gamma * delta;

        let output = PaymentOutput {
            recipient: cloaked_pkey,
            cloaking_hint: hint.compress(),
            proof,
            payload,
        };

        Ok((output, gamma))
    }

    /// Create a new PaymentOutput.
    pub fn new(recipient_pkey: &PublicKey, amount: i64) -> Result<(Self, Fr), Error> {
        let data = PaymentPayloadData::Comment(String::new());
        Self::with_payload(recipient_pkey, amount, data)
    }

    /// Decrypt payload.
    pub fn decrypt_payload(&self, skey: &SecretKey) -> Result<PaymentPayload, Error> {
        let output_hash = Hash::digest(&self);
        PaymentPayload::decrypt(output_hash, &self.payload, skey)
    }

    /// Validates UTXO structure and keying.
    pub fn validate(&self) -> Result<(), Error> {
        // valid recipient PKey?
        let pt: Pt = self.recipient.clone().into();
        pt.decompress()?;

        // valid PKey cloaking?
        if self.cloaking_hint != Pt::zero() {
            self.cloaking_hint.decompress()?;
        };

        // check Bulletproof
        if !validate_range_proof(&self.proof) {
            let h = Hash::digest(self);
            return Err(OutputError::InvalidBulletProof(h).into());
        };

        // Validate payload.
        if self.payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
            let h = Hash::digest(self);
            return Err(OutputError::InvalidPayloadLength(
                h,
                PAYMENT_PAYLOAD_LEN,
                self.payload.ctxt.len(),
            )
            .into());
        }
        Ok(())
    }

    /// Returns Pedersen commitment.
    pub fn pedersen_commitment(&self) -> Result<ECp, CryptoError> {
        self.proof.vcmt.decompress()
    }

    /// Checks that UTXO belongs to given key.
    pub fn is_my_utxo(&self, skey: &SecretKey, _pkey: &PublicKey) -> bool {
        // TODO: use cloaking_hint here.
        self.decrypt_payload(&skey).is_ok()
    }
}

impl PublicPaymentOutput {
    pub fn new(recipient_pkey: &PublicKey, amount: i64) -> Result<Self, Error> {
        let serno = random::<i64>();
        Ok(PublicPaymentOutput {
            recipient: recipient_pkey.clone(),
            serno,
            amount,
        })
    }

    /// Validates UTXO structure and keying.
    pub fn validate(&self) -> Result<(), Error> {
        self.recipient.decompress()?;
        if self.amount <= 0 {
            let h = Hash::digest(self);
            return Err(OutputError::InvalidStake(h).into());
        }
        Ok(())
    }

    /// Returns Pedersen commitment.
    pub fn pedersen_commitment(&self) -> Result<ECp, CryptoError> {
        Ok(fee_a(self.amount))
    }

    /// Checks that UTXO belongs to given key.
    pub fn is_my_utxo(&self, pkey: &PublicKey) -> bool {
        &self.recipient == pkey
    }
}

impl StakeOutput {
    /// Create a new StakeOutput.
    pub fn new(
        recipient_pkey: &PublicKey,
        validator_skey: &secure::SecretKey,
        validator_pkey: &secure::PublicKey,
        amount: i64,
    ) -> Result<Self, Error> {
        assert!(amount > 0);

        let serno = random::<i64>();

        let mut output = StakeOutput {
            recipient: recipient_pkey.clone(),
            validator: validator_pkey.clone(),
            amount,
            serno,
            signature: secure::Signature::zero(),
        };

        // Form BLS signature on the Stake UTXO
        let h = Hash::digest(&output);
        output.signature = secure::sign_hash(&h, validator_skey);

        Ok(output)
    }

    /// Validates UTXO structure and keying.
    pub fn validate(&self) -> Result<(), Error> {
        let output_hash = Hash::digest(self);
        self.recipient.decompress()?;
        if self.amount <= 0 {
            return Err(OutputError::InvalidStake(output_hash).into());
        }

        // Validate BLS signature of validator_pkey
        if let Err(_e) = secure::check_hash(&output_hash, &self.signature, &self.validator) {
            return Err(OutputError::InvalidStakeSignature(output_hash).into());
        }
        Ok(())
    }

    /// Returns Pedersen commitment.
    pub fn pedersen_commitment(&self) -> Result<ECp, CryptoError> {
        Ok(fee_a(self.amount))
    }

    /// Checks that UTXO belongs to given key.
    pub fn is_my_utxo(&self, pkey: &PublicKey) -> bool {
        &self.recipient == pkey
    }
}

impl Output {
    /// Create a new payment UTXO.
    pub fn new_payment(recipient_pkey: &PublicKey, amount: i64) -> Result<(Self, Fr), Error> {
        let (output, delta) = PaymentOutput::new(recipient_pkey, amount)?;
        Ok((Output::PaymentOutput(output), delta))
    }

    /// Create a new escrow transaction.
    pub fn new_stake(
        recipient_pkey: &PublicKey,
        validator_skey: &secure::SecretKey,
        validator_pkey: &secure::PublicKey,
        amount: i64,
    ) -> Result<Self, Error> {
        let output = StakeOutput::new(recipient_pkey, validator_skey, validator_pkey, amount)?;
        Ok(Output::StakeOutput(output))
    }

    /// Validates UTXO structure and keying.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Output::PaymentOutput(o) => o.validate(),
            Output::PublicPaymentOutput(o) => o.validate(),
            Output::StakeOutput(o) => o.validate(),
        }
    }

    /// Returns decompressed public key.
    pub fn recipient_pkey(&self) -> Result<ECp, CryptoError> {
        match self {
            Output::PaymentOutput(o) => o.recipient,
            Output::PublicPaymentOutput(o) => o.recipient,
            Output::StakeOutput(o) => o.recipient,
        }
        .decompress()
    }

    /// Returns Pedersen commitment.
    pub fn pedersen_commitment(&self) -> Result<ECp, CryptoError> {
        match self {
            Output::PaymentOutput(o) => o.pedersen_commitment(),
            Output::PublicPaymentOutput(o) => o.pedersen_commitment(),
            Output::StakeOutput(o) => o.pedersen_commitment(),
        }
    }

    /// Checks that UTXO belongs to given key.
    pub fn is_my_utxo(&self, skey: &SecretKey, pkey: &PublicKey) -> bool {
        match self {
            Output::PaymentOutput(o) => o.is_my_utxo(skey, pkey),
            Output::PublicPaymentOutput(o) => o.is_my_utxo(&pkey),
            Output::StakeOutput(o) => o.is_my_utxo(&pkey),
        }
    }
}

impl Hashable for PaymentOutput {
    fn hash(&self, state: &mut Hasher) {
        "Payment".hash(state);
        self.recipient.hash(state);
        self.cloaking_hint.hash(state);
        self.proof.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for PublicPaymentOutput {
    fn hash(&self, state: &mut Hasher) {
        "PublicPayment".hash(state);
        self.recipient.hash(state);
        self.serno.hash(state);
        self.amount.hash(state);
    }
}

impl Hashable for StakeOutput {
    fn hash(&self, state: &mut Hasher) {
        "Stake".hash(state);
        self.recipient.hash(state);
        self.validator.hash(state);
        self.amount.hash(state);
        self.serno.hash(state);
    }
}

impl Hashable for Output {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Output::PaymentOutput(payment) => payment.hash(state),
            Output::PublicPaymentOutput(payment) => payment.hash(state),
            Output::StakeOutput(stake) => stake.hash(state),
        }
    }
}

impl Hashable for Box<Output> {
    fn hash(&self, state: &mut Hasher) {
        let output = self.as_ref();
        output.hash(state)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use stegos_crypto::curve1174::cpt::make_random_keys;

    fn random_string(len: usize) -> String {
        thread_rng().sample_iter(&Alphanumeric).take(len).collect()
    }

    ///
    /// Tests encoding/decoding of PaymentPayload used by PaymentOutput.
    ///
    #[test]
    fn payment_payload() {
        use simple_logger;
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let output_hash = Hash::digest("test");

        fn rt(payload: &PaymentPayload, skey: &SecretKey, pkey: &PublicKey) {
            let output_hash = Hash::digest("test");
            let encrypted = payload.encrypt(&pkey).expect("keys are valid");
            let payload2 =
                PaymentPayload::decrypt(output_hash, &encrypted, &skey).expect("keys are valid");
            assert_eq!(payload, &payload2);
        }

        let (skey, pkey) = make_random_keys();

        // With empty comment.
        let gamma: Fr = Fr::random();
        let delta: Fr = Fr::random();
        let amount: i64 = 100500;
        let data = PaymentPayloadData::Comment(String::new());
        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        rt(&payload, &skey, &pkey);

        // With non-empty comment.
        let gamma: Fr = Fr::random();
        let delta: Fr = Fr::random();
        let amount: i64 = 100500;
        let data = PaymentPayloadData::ContentHash(Hash::digest(&100500u64));
        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        rt(&payload, &skey, &pkey);

        // With long comment.
        let gamma: Fr = Fr::random();
        let delta: Fr = Fr::random();
        let amount: i64 = 100500;
        let data = PaymentPayloadData::Comment(random_string(PAYMENT_DATA_LEN - 2));
        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        rt(&payload, &skey, &pkey);

        // Overflow.
        let data = PaymentPayloadData::Comment(random_string(PAYMENT_DATA_LEN - 1));
        let e = data.validate().unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::DataIsTooLong(max, got) => {
                assert_eq!(max, PAYMENT_DATA_LEN - 2);
                assert_eq!(got, PAYMENT_DATA_LEN - 1);
            }
            _ => unreachable!(),
        }

        // With content hash.
        let gamma: Fr = Fr::random();
        let delta: Fr = Fr::random();
        let amount: i64 = 100500;
        let data = PaymentPayloadData::ContentHash(Hash::digest(&100500u64));
        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        rt(&payload, &skey, &pkey);

        //
        // Corrupted payload.
        //
        let gamma: Fr = Fr::random();
        let delta: Fr = Fr::random();
        let amount: i64 = 100500;
        let data = PaymentPayloadData::ContentHash(Hash::digest(&100500u64));
        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        let encrypted = payload.encrypt(&pkey).expect("keys are valid");
        let raw = aes_decrypt(&encrypted, &skey).expect("keys are valid");

        // Invalid length.
        let mut invalid = raw.clone();
        invalid.push(0);
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(output_hash, &invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::InvalidPayloadLength(_output_hash, expected, got) => {
                assert_eq!(expected, PAYMENT_PAYLOAD_LEN);
                assert_eq!(got, PAYMENT_PAYLOAD_LEN + 1);
            }
            _ => unreachable!(),
        }

        // Invalid magic.
        let mut invalid = raw.clone();
        invalid[3] = 5;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(output_hash, &invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::PayloadDecryptionError(_output_hash) => {}
            _ => unreachable!(),
        }

        // Negative amount.
        let mut invalid = raw.clone();
        let amount: i64 = -100500;
        let amount_bytes: [u8; 8] = unsafe { transmute(amount.to_le()) };
        invalid[68..68 + amount_bytes.len()].copy_from_slice(&amount_bytes);
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(output_hash, &invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::NegativeAmount(_output_hash, amount2) => assert_eq!(amount, amount2),
            _ => unreachable!(),
        }

        // Unsupported type code.
        let mut invalid = raw.clone();
        let code: u8 = 10;
        invalid[76] = code;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(output_hash, &invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::UnsupportedDataType(_output_hash, code2) => assert_eq!(code, code2),
            _ => unreachable!(),
        }

        // Trailing garbage.
        let mut invalid = raw.clone();
        invalid[77 + HASH_SIZE] = 1;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(output_hash, &invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::TrailingGarbage(_output_hash) => {}
            _ => unreachable!(),
        }
    }

    ///
    /// Tests PaymentOutput encryption/decryption.
    ///
    #[test]
    pub fn payment_encrypt_decrypt() {
        let (skey1, _pkey1) = make_random_keys();
        let (skey2, pkey2) = make_random_keys();

        let amount: i64 = 100500;

        let (output, gamma) = PaymentOutput::new(&pkey2, amount).expect("encryption successful");
        let payload = output
            .decrypt_payload(&skey2)
            .expect("decryption successful");

        assert_eq!(amount, payload.amount);
        assert_eq!(gamma, payload.gamma);

        // Error handling
        if let Err(e) = output.decrypt_payload(&skey1) {
            match e.downcast::<OutputError>() {
                Ok(OutputError::PayloadDecryptionError(_output_hash)) => (),
                _ => assert!(false),
            };
        } else {
            assert!(false);
        }
    }
}
