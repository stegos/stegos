//! Transaction output.

//
// Copyright (c) 2018 Stegos
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
use stegos_crypto::bulletproofs::{make_range_proof, pedersen_commitment, BulletProof};
use stegos_crypto::curve1174::cpt::{
    aes_decrypt, aes_encrypt, EncryptedPayload, Pt, PublicKey, SecretKey,
};
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::curve1174::G;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_crypto::CryptoError;

/// A magic value used to encode/decode payload.
const PAYMENT_PAYLOAD_MAGIC: [u8; 4] = [112, 97, 121, 109]; // "paym"

/// Payment payload size.
const PAYMENT_PAYLOAD_LEN: usize = 76;

/// A magic value used to encode/decode payload.
const DATA_PAYLOAD_MAGIC: [u8; 4] = [100, 97, 116, 97]; // "data"

/// Data payload size.
const DATA_PAYLOAD_LEN: usize = 68;

/// A magic value used to encode/decode payload.
const ESCROW_PAYLOAD_MAGIC: [u8; 4] = [101, 115, 99, 114]; // "escr"

/// Escrow payload size.
const ESCROW_PAYLOAD_LEN: usize = 36;

/// Errors.
#[derive(Debug, Fail)]
pub enum OutputError {
    #[fail(display = "Failed to decrypt payload")]
    PayloadDecryptionError,
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

/// Data UTXO.
#[derive(Debug, Clone)]
pub struct DataOutput {
    /// Clocked public key of recipient.
    /// P_M + δG
    pub recipient: PublicKey,

    /// Pedersen commitment to zero.
    pub vcmt: Pt,

    /// The number of blocks for which this UTXO should be kept on the blockchain since
    /// it has been added to it.
    pub ttl: u64,

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
pub struct EscrowOutput {
    /// Cloaked wallet key of validator.
    pub recipient: PublicKey,

    /// Uncloaked secure key of validator.
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
    DataOutput(DataOutput),
    EscrowOutput(EscrowOutput),
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

impl PaymentOutput {
    /// Create a new PaymentOutput.
    pub fn new(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        amount: i64,
    ) -> Result<(Self, Fr), Error> {
        // Create range proofs.
        let (proof, gamma) = make_range_proof(amount);

        // Clock recipient public key
        let (cloaked_pkey, delta) = cloak_key(sender_skey, recipient_pkey, &gamma, timestamp)?;

        // NOTE: real public key should be used to encrypt payload
        let payload = Self::encrypt_payload(delta, gamma, amount, recipient_pkey)?;

        let output = PaymentOutput {
            recipient: cloaked_pkey,
            proof,
            payload,
        };

        Ok((output, gamma))
    }

    /// Encrypt payload for PaymentOutput.
    fn encrypt_payload(
        delta: Fr,
        gamma: Fr,
        amount: i64,
        pkey: &PublicKey,
    ) -> Result<EncryptedPayload, CryptoError> {
        // Convert amount to BE vector.
        let amount_bytes: [u8; 8] = unsafe { transmute(amount.to_be()) };

        let gamma_bytes: [u8; 32] = gamma.to_lev_u8();
        let delta_bytes: [u8; 32] = delta.to_lev_u8();

        let payload: Vec<u8> = [
            &PAYMENT_PAYLOAD_MAGIC[..],
            &amount_bytes[..],
            &delta_bytes[..],
            &gamma_bytes[..],
        ]
        .concat();

        // Ensure that the total length of package is 76 bytes.
        assert_eq!(payload.len(), PAYMENT_PAYLOAD_LEN);

        // String together a gamma, delta, and Amount (i64) all in one long vector and encrypt it.
        aes_encrypt(&payload, &pkey)
    }

    /// Decrypt payload of PaymentOutput.
    pub fn decrypt_payload(&self, skey: &SecretKey) -> Result<(Fr, Fr, i64), Error> {
        let payload: Vec<u8> = aes_decrypt(&self.payload, &skey)?;

        if payload.len() != PAYMENT_PAYLOAD_LEN {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        let mut magic: [u8; 4] = [0u8; 4];
        let mut amount_bytes: [u8; 8] = [0u8; 8];
        let mut delta_bytes: [u8; 32] = [0u8; 32];
        let mut gamma_bytes: [u8; 32] = [0u8; 32];
        magic.copy_from_slice(&payload[0..4]);
        amount_bytes.copy_from_slice(&payload[4..12]);
        delta_bytes.copy_from_slice(&payload[12..44]);
        gamma_bytes.copy_from_slice(&payload[44..76]);

        if magic != PAYMENT_PAYLOAD_MAGIC {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        let amount: i64 = i64::from_be(unsafe { transmute(amount_bytes) });
        let gamma: Fr = Fr::from_lev_u8(gamma_bytes);
        let delta: Fr = Fr::from_lev_u8(delta_bytes);

        Ok((delta, gamma, amount))
    }
}

impl DataOutput {
    /// Create a new DataOutput.
    pub fn new(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        ttl: u64,
        data: &[u8],
    ) -> Result<(Self, Fr), Error> {
        assert!(ttl > 0);
        assert!(data.len() > 0);

        // Create pedersen commitment
        let (vcmt, gamma) = pedersen_commitment(0);
        let vcmt = vcmt.compress();

        // Clock recipient public key
        let (cloaked_pkey, delta) = cloak_key(sender_skey, recipient_pkey, &gamma, timestamp)?;

        // NOTE: real public key should be used to encrypt payload
        let payload = Self::encrypt_payload(delta, gamma, data, recipient_pkey)?;

        let output = DataOutput {
            recipient: cloaked_pkey,
            ttl,
            vcmt,
            payload,
        };

        Ok((output, gamma))
    }

    /// Encrypt payload for DataOutput.
    fn encrypt_payload(
        delta: Fr,
        gamma: Fr,
        data: &[u8],
        pkey: &PublicKey,
    ) -> Result<EncryptedPayload, CryptoError> {
        let gamma_bytes: [u8; 32] = gamma.to_lev_u8();
        let delta_bytes: [u8; 32] = delta.to_lev_u8();

        let payload: Vec<u8> = [
            &DATA_PAYLOAD_MAGIC[..],
            &delta_bytes[..],
            &gamma_bytes[..],
            &data[..],
        ]
        .concat();

        // Ensure that the total length of package is 68 bytes + data.len().
        assert_eq!(payload.len(), DATA_PAYLOAD_LEN + data.len());

        // Encrypt the payload.
        let payload = aes_encrypt(&payload, &pkey)?;
        assert_eq!(payload.ctxt.len(), DATA_PAYLOAD_LEN + data.len());
        Ok(payload)
    }

    /// Decrypt payload of DataOutput.
    pub fn decrypt_payload(&self, skey: &SecretKey) -> Result<(Fr, Fr, Vec<u8>), Error> {
        let payload: Vec<u8> = aes_decrypt(&self.payload, &skey)?;

        if payload.len() < DATA_PAYLOAD_LEN {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        let mut magic: [u8; 4] = [0u8; 4];
        let mut delta_bytes: [u8; 32] = [0u8; 32];
        let mut gamma_bytes: [u8; 32] = [0u8; 32];
        magic.copy_from_slice(&payload[0..4]);
        delta_bytes.copy_from_slice(&payload[4..36]);
        gamma_bytes.copy_from_slice(&payload[36..68]);
        let data = payload[68..].to_vec(); // the rest is data

        if magic != DATA_PAYLOAD_MAGIC {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        let gamma: Fr = Fr::from_lev_u8(gamma_bytes);
        let delta: Fr = Fr::from_lev_u8(delta_bytes);

        Ok((delta, gamma, data))
    }

    pub fn data_size(&self) -> usize {
        assert!(self.payload.ctxt.len() > DATA_PAYLOAD_LEN);
        (self.payload.ctxt.len() - DATA_PAYLOAD_LEN)
    }
}

impl EscrowOutput {
    /// Create a new EscrowOutput.
    pub fn new(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        validator_pkey: &secure::PublicKey,
        amount: i64,
    ) -> Result<Self, Error> {
        // Cloak recipient public key.
        let gamma = Fr::zero();
        let (cloaked_pkey, delta) = cloak_key(sender_skey, recipient_pkey, &gamma, timestamp)?;

        // Encrypt payload.
        let payload = Self::encrypt_payload(delta, recipient_pkey)?;

        let output = EscrowOutput {
            recipient: cloaked_pkey,
            validator: validator_pkey.clone(),
            amount,
            payload,
        };

        Ok(output)
    }

    /// Encrypt payload for EscrowOutput.
    fn encrypt_payload(delta: Fr, pkey: &PublicKey) -> Result<EncryptedPayload, CryptoError> {
        let delta_bytes: [u8; 32] = delta.to_lev_u8();

        let payload: Vec<u8> = [&ESCROW_PAYLOAD_MAGIC[..], &delta_bytes[..]].concat();

        // Ensure that the total length of package is valid.
        assert_eq!(payload.len(), ESCROW_PAYLOAD_LEN);

        // Encrypt payload it.
        aes_encrypt(&payload, &pkey)
    }

    /// Decrypt payload of EscrowOutput.
    pub fn decrypt_payload(&self, skey: &SecretKey) -> Result<Fr, Error> {
        let payload: Vec<u8> = aes_decrypt(&self.payload, &skey)?;

        if payload.len() != ESCROW_PAYLOAD_LEN {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        let mut magic: [u8; 4] = [0u8; 4];
        let mut delta_bytes: [u8; 32] = [0u8; 32];
        magic.copy_from_slice(&payload[0..4]);
        delta_bytes.copy_from_slice(&payload[4..36]);

        if magic != ESCROW_PAYLOAD_MAGIC {
            // Invalid payload or invalid secret key supplied.
            return Err(OutputError::PayloadDecryptionError.into());
        }

        let delta: Fr = Fr::from_lev_u8(delta_bytes);

        Ok(delta)
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

    /// Create a new data UTXO.
    pub fn new_data(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        ttl: u64,
        data: &[u8],
    ) -> Result<(Self, Fr), Error> {
        let (output, delta) = DataOutput::new(timestamp, sender_skey, recipient_pkey, ttl, data)?;
        Ok((Output::DataOutput(output), delta))
    }

    /// Create a new escrow transaction.
    pub fn new_escrow(
        timestamp: u64,
        sender_skey: &SecretKey,
        recipient_pkey: &PublicKey,
        validator_pkey: &secure::PublicKey,
        amount: i64,
    ) -> Result<Self, Error> {
        let output = EscrowOutput::new(
            timestamp,
            sender_skey,
            recipient_pkey,
            validator_pkey,
            amount,
        )?;
        Ok(Output::EscrowOutput(output))
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Output({})", Hash::digest(self))
    }
}

impl Hashable for PaymentOutput {
    fn hash(&self, state: &mut Hasher) {
        "Monetary".hash(state);
        self.recipient.hash(state);
        self.proof.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for DataOutput {
    fn hash(&self, state: &mut Hasher) {
        "Data".hash(state);
        self.recipient.hash(state);
        self.vcmt.hash(state);
        self.ttl.hash(state);
        self.payload.hash(state);
    }
}

impl Hashable for EscrowOutput {
    fn hash(&self, state: &mut Hasher) {
        "Escrow".hash(state);
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
            Output::DataOutput(data) => data.hash(state),
            Output::EscrowOutput(escrow) => escrow.hash(state),
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
    use stegos_crypto::curve1174::cpt::make_random_keys;

    #[test]
    pub fn payment_encrypt_decrypt() {
        let (skey1, _pkey1, _sig1) = make_random_keys();
        let (skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 100500;

        let (output, gamma) =
            PaymentOutput::new(timestamp, &skey1, &pkey2, amount).expect("encryption successful");
        let (_delta2, gamma2, amount2) = output
            .decrypt_payload(&skey2)
            .expect("decryption successful");

        assert_eq!(amount, amount2);
        assert_eq!(gamma, gamma2);

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

    #[test]
    pub fn escrow_encrypt_decrypt() {
        let (skey1, _pkey1, _sig1) = make_random_keys();
        let (skey2, pkey2, _sig2) = make_random_keys();
        let (_secure_skey1, secure_pkey1, _secure_sig1) = secure::make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 100500;

        let output = EscrowOutput::new(timestamp, &skey1, &pkey2, &secure_pkey1, amount)
            .expect("encryption successful");
        let _delta2 = output
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

    #[test]
    pub fn data_encrypt_decrypt() {
        let (skey1, _pkey1, _sig1) = make_random_keys();
        let (skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let data = b"hello";
        let ttl = 5;

        let (output, gamma) =
            DataOutput::new(timestamp, &skey1, &pkey2, ttl, data).expect("encryption successful");
        let (_delta2, gamma2, data2) = output
            .decrypt_payload(&skey2)
            .expect("decryption successful");

        assert_eq!(data.to_vec(), data2);
        assert_eq!(gamma, gamma2);

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
