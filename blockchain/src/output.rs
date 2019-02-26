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
use std::fmt;
use std::mem::transmute;
use stegos_crypto::bulletproofs::{make_range_proof, BulletProof};
use stegos_crypto::curve1174::cpt::{
    aes_decrypt, aes_encrypt, EncryptedPayload, Pt, PublicKey, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
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

/// A magic value used to encode/decode payload.
const STAKE_PAYLOAD_MAGIC: [u8; 4] = [115, 116, 107, 101]; // "stke"

/// Escrow payload size.
pub const STAKE_PAYLOAD_LEN: usize = 36;

/// UTXO errors.
#[derive(Debug, Fail)]
pub enum OutputError {
    #[fail(display = "Invalid stake.")]
    InvalidStake,
    #[fail(display = "Invalid bulletproof.")]
    InvalidBulletProof,
    #[fail(display = "Invalid payload length: expected={}, got={}", _0, _1)]
    InvalidPayloadLength(usize, usize),
    #[fail(display = "Failed to decrypt payload")]
    PayloadDecryptionError,
    #[fail(display = "Data is too long:  max={}, got={}.", _0, _1)]
    DataIsTooLong(usize, usize),
    #[fail(display = "Unsupported data type: typecode={}.", _0)]
    UnsupportedDataType(u8),
    #[fail(display = "Trailing garbage in payload")]
    TrailingGarbage,
    #[fail(display = "Negative amount: amount={}", _0)]
    NegativeAmount(i64),
}

/// Payment UTXO.
/// Transaction output.
/// (ID, P_{M, δ}, Bp, E_M(x, γ, δ))
#[derive(Debug, Clone)]
pub struct PaymentOutput {
    /// Clocked public key of recipient.
    /// P_M + δG
    pub recipient: PublicKey,

    /// Bulletproof on range on amount x.
    /// Contains Pedersen commitment.
    /// Size is approx. 3-5 KB (very structured data type).
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

/// Escrow UTXO.
#[derive(Debug, Clone)]
pub struct StakeOutput {
    /// Cloaked wallet key of validator.
    pub recipient: PublicKey,

    /// Uncloaked network key of validator.
    pub validator: secure::PublicKey,

    /// Amount to stake.
    pub amount: i64,

    /// Encrypted payload.
    pub payload: EncryptedPayload,
}

/// Blockchain UTXO.
#[derive(Debug, Clone)]
pub enum Output {
    PaymentOutput(PaymentOutput),
    StakeOutput(StakeOutput),
}

/// Cloak recipient's public key.
fn cloak_key(
    sender_skey: &SecretKey,
    recipient_pkey: &PublicKey,
    gamma: &Fr,
    timestamp: u64,
) -> Result<(PublicKey, Fr), CryptoError> {
    // h is the digest of the recipients actual public key mixed with a timestamp.
    let mut hasher = Hasher::new();
    recipient_pkey.hash(&mut hasher);
    timestamp.hash(&mut hasher);
    let h = hasher.result();

    // Use deterministic randomness here too, to protect against PRNG attacks.
    let delta: Fr = Fr::synthetic_random(&"PKey", sender_skey, &h);

    // Resulting publickey will be a random-like value in a safe range of the field,
    // not too small, and not too large. This helps avoid brute force attacks, looking
    // for the discrete log corresponding to delta.

    let pt = Pt::from(*recipient_pkey);
    let pt = ECp::decompress(pt)?;
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
#[derive(Debug, Eq, PartialEq, Clone)]
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
    fn decrypt(payload: &EncryptedPayload, skey: &SecretKey) -> Result<Self, Error> {
        if payload.ctxt.len() != PAYMENT_PAYLOAD_LEN {
            return Err(
                OutputError::InvalidPayloadLength(PAYMENT_PAYLOAD_LEN, payload.ctxt.len()).into(),
            );
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
            return Err(OutputError::PayloadDecryptionError.into());
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
            return Err(OutputError::NegativeAmount(amount).into());
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
            code @ _ => return Err(OutputError::UnsupportedDataType(code).into()),
        };

        // Check for trailing garbage.
        for byte in &payload[pos..] {
            if *byte != 0 {
                return Err(OutputError::TrailingGarbage.into());
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

/// Unpacked encrypted payload of PaymentOutput.
#[derive(Debug, Eq, PartialEq)]
pub struct StakePayload {
    pub delta: Fr,
}

impl StakePayload {
    /// Serialize and encrypt payload.
    fn encrypt(&self, pkey: &PublicKey) -> Result<EncryptedPayload, Error> {
        // Delta.
        let delta_bytes: [u8; 32] = self.delta.to_lev_u8();

        let payload: Vec<u8> = [&STAKE_PAYLOAD_MAGIC[..], &delta_bytes[..]].concat();

        // Ensure that the total length of package is valid.
        assert_eq!(payload.len(), STAKE_PAYLOAD_LEN);

        // Encrypt payload.
        let payload = aes_encrypt(&payload, &pkey)?;
        Ok(payload)
    }

    /// Decrypt and deserialize payload.
    fn decrypt(payload: &EncryptedPayload, skey: &SecretKey) -> Result<Self, Error> {
        if payload.ctxt.len() != STAKE_PAYLOAD_LEN {
            return Err(
                OutputError::InvalidPayloadLength(STAKE_PAYLOAD_LEN, payload.ctxt.len()).into(),
            );
        }
        let payload: Vec<u8> = aes_decrypt(&payload, &skey)?;
        assert_eq!(payload.len(), STAKE_PAYLOAD_LEN);
        let mut pos: usize = 0;

        // Magic.
        let mut magic: [u8; 4] = [0u8; 4];
        magic.copy_from_slice(&payload[pos..pos + 4]);
        pos += 4;
        if magic != STAKE_PAYLOAD_MAGIC {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        // Delta.
        let mut delta_bytes: [u8; 32] = [0u8; 32];
        delta_bytes.copy_from_slice(&payload[pos..pos + 32]);
        pos += delta_bytes.len();
        let delta: Fr = Fr::from_lev_u8(delta_bytes);

        assert_eq!(pos, STAKE_PAYLOAD_LEN);

        let payload = StakePayload { delta };
        Ok(payload)
    }
}

impl PaymentOutput {
    /// Create a new PaymentOutput with generic payload.
    pub fn with_payload(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        amount: i64,
        data: PaymentPayloadData,
    ) -> Result<(Self, Fr), Error> {
        // Create range proofs.
        let (proof, gamma) = make_range_proof(amount);

        // Clock recipient public key
        let (cloaked_pkey, delta) = cloak_key(sender_skey, recipient_pkey, &gamma, timestamp)?;

        let payload = PaymentPayload {
            delta,
            gamma,
            amount,
            data,
        };
        // NOTE: real public key should be used to encrypt payload
        let payload = payload.encrypt(recipient_pkey)?;

        let output = PaymentOutput {
            recipient: cloaked_pkey,
            proof,
            payload,
        };

        Ok((output, gamma))
    }

    /// Create a new PaymentOutput.
    pub fn new(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        amount: i64,
    ) -> Result<(Self, Fr), Error> {
        let data = PaymentPayloadData::Comment(String::new());
        Self::with_payload(timestamp, sender_skey, recipient_pkey, amount, data)
    }

    /// Decrypt payload.
    pub fn decrypt_payload(&self, skey: &SecretKey) -> Result<PaymentPayload, Error> {
        PaymentPayload::decrypt(&self.payload, skey)
    }
}

impl StakeOutput {
    /// Create a new StakeOutput.
    pub fn new(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        validator_pkey: &secure::PublicKey,
        amount: i64,
    ) -> Result<Self, Error> {
        assert!(amount > 0);

        // Cloak recipient public key.
        let gamma = Fr::zero();
        let (cloaked_pkey, delta) = cloak_key(sender_skey, recipient_pkey, &gamma, timestamp)?;

        // Encrypt payload.
        let payload = StakePayload { delta };
        // NOTE: real public key should be used to encrypt payload
        let payload = payload.encrypt(recipient_pkey)?;

        let output = StakeOutput {
            recipient: cloaked_pkey,
            validator: validator_pkey.clone(),
            amount,
            payload,
        };

        Ok(output)
    }

    /// Decrypt payload of StakeOutput.
    pub fn decrypt_payload(&self, skey: &SecretKey) -> Result<StakePayload, Error> {
        StakePayload::decrypt(&self.payload, skey)
    }
}

impl Output {
    /// Create a new payment UTXO.
    pub fn new_payment(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        amount: i64,
    ) -> Result<(Self, Fr), Error> {
        let (output, delta) = PaymentOutput::new(timestamp, sender_skey, recipient_pkey, amount)?;
        Ok((Output::PaymentOutput(output), delta))
    }

    /// Create a new escrow transaction.
    pub fn new_stake(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        validator_pkey: &secure::PublicKey,
        amount: i64,
    ) -> Result<Self, Error> {
        let output = StakeOutput::new(
            timestamp,
            sender_skey,
            recipient_pkey,
            validator_pkey,
            amount,
        )?;
        Ok(Output::StakeOutput(output))
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Output({})", Hash::digest(self))
    }
}

impl Hashable for PaymentOutput {
    fn hash(&self, state: &mut Hasher) {
        "Payment".hash(state);
        self.recipient.hash(state);
        self.proof.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for StakeOutput {
    fn hash(&self, state: &mut Hasher) {
        "Stake".hash(state);
        self.recipient.hash(state);
        self.validator.hash(state);
        self.amount.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for Output {
    fn hash(&self, state: &mut Hasher) {
        match self {
            Output::PaymentOutput(monetary) => monetary.hash(state),
            Output::StakeOutput(escrow) => escrow.hash(state),
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

    use chrono::Utc;
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

        fn rt(payload: &PaymentPayload, skey: &SecretKey, pkey: &PublicKey) {
            let encrypted = payload.encrypt(&pkey).expect("keys are valid");
            let payload2 = PaymentPayload::decrypt(&encrypted, &skey).expect("keys are valid");
            assert_eq!(payload, &payload2);
        }

        let (skey, pkey, _sig) = make_random_keys();

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
        let e = PaymentPayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::InvalidPayloadLength(expected, got) => {
                assert_eq!(expected, PAYMENT_PAYLOAD_LEN);
                assert_eq!(got, PAYMENT_PAYLOAD_LEN + 1);
            }
            _ => unreachable!(),
        }

        // Invalid magic.
        let mut invalid = raw.clone();
        invalid[3] = 5;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::PayloadDecryptionError => {}
            _ => unreachable!(),
        }

        // Negative amount.
        let mut invalid = raw.clone();
        let amount: i64 = -100500;
        let amount_bytes: [u8; 8] = unsafe { transmute(amount.to_le()) };
        invalid[68..68 + amount_bytes.len()].copy_from_slice(&amount_bytes);
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::NegativeAmount(amount2) => assert_eq!(amount, amount2),
            _ => unreachable!(),
        }

        // Unsupported type code.
        let mut invalid = raw.clone();
        let code: u8 = 10;
        invalid[76] = code;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::UnsupportedDataType(code2) => assert_eq!(code, code2),
            _ => unreachable!(),
        }

        // Trailing garbage.
        let mut invalid = raw.clone();
        invalid[77 + HASH_SIZE] = 1;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = PaymentPayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::TrailingGarbage => {}
            _ => unreachable!(),
        }
    }

    ///
    /// Tests encoding/decoding of StakePayload used by StakeOutput.
    ///
    #[test]
    fn stake_payload() {
        use simple_logger;
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        fn rt(payload: &StakePayload, skey: &SecretKey, pkey: &PublicKey) {
            let encrypted = payload.encrypt(&pkey).expect("keys are valid");
            let payload2 = StakePayload::decrypt(&encrypted, &skey).expect("keys are valid");
            assert_eq!(payload, &payload2);
        }

        let (skey, pkey, _sig) = make_random_keys();

        // Basic.
        let delta: Fr = Fr::random();
        let payload = StakePayload { delta };
        rt(&payload, &skey, &pkey);

        //
        // Corrupted payload.
        //
        let delta: Fr = Fr::random();
        let payload = StakePayload { delta };
        let encrypted = payload.encrypt(&pkey).expect("keys are valid");
        let raw = aes_decrypt(&encrypted, &skey).expect("keys are valid");

        // Invalid length.
        let mut invalid = raw.clone();
        invalid.push(0);
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = StakePayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::InvalidPayloadLength(expected, got) => {
                assert_eq!(expected, STAKE_PAYLOAD_LEN);
                assert_eq!(got, STAKE_PAYLOAD_LEN + 1);
            }
            _ => unreachable!(),
        }

        // Invalid magic.
        let mut invalid = raw.clone();
        invalid[3] = 5;
        let invalid = aes_encrypt(&invalid, &pkey).expect("keys are valid");
        let e = StakePayload::decrypt(&invalid, &skey).unwrap_err();
        match e.downcast::<OutputError>().unwrap() {
            OutputError::PayloadDecryptionError => {}
            _ => unreachable!(),
        }
    }

    ///
    /// Tests PaymentOutput encryption/decryption.
    ///
    #[test]
    pub fn payment_encrypt_decrypt() {
        let (skey1, _pkey1, _sig1) = make_random_keys();
        let (skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 100500;

        let (output, gamma) =
            PaymentOutput::new(timestamp, &skey1, &pkey2, amount).expect("encryption successful");
        let payload = output
            .decrypt_payload(&skey2)
            .expect("decryption successful");

        assert_eq!(amount, payload.amount);
        assert_eq!(gamma, payload.gamma);

        // Error handling
        if let Err(e) = output.decrypt_payload(&skey1) {
            match e.downcast::<OutputError>() {
                Ok(OutputError::PayloadDecryptionError) => (),
                _ => assert!(false),
            };
        } else {
            assert!(false);
        }
    }

    ///
    /// Tests StakeOutput encryption/decryption.
    ///
    #[test]
    pub fn stake_encrypt_decrypt() {
        let (skey1, _pkey1, _sig1) = make_random_keys();
        let (skey2, pkey2, _sig2) = make_random_keys();
        let (_secure_skey1, secure_pkey1, _secure_sig1) = secure::make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 100500;

        let output = StakeOutput::new(timestamp, &skey1, &pkey2, &secure_pkey1, amount)
            .expect("encryption successful");
        let _payload = output
            .decrypt_payload(&skey2)
            .expect("decryption successful");

        // Error handling
        if let Err(e) = output.decrypt_payload(&skey1) {
            match e.downcast::<OutputError>() {
                Ok(OutputError::PayloadDecryptionError) => (),
                _ => assert!(false),
            };
        } else {
            assert!(false);
        }
    }
}
