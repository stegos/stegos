//! Chat output.

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

use crate::timestamp::Timestamp;
use crate::{BlockchainError, OutputError};
// use curve25519_dalek::scalar::Scalar;
// use failure::{Error, Fail};
use failure::Fail;
// use rand::{random, Rng};
// use serde::de::{Deserialize, Deserializer};
// use serde::ser::{Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::fmt;
// use std::mem::transmute;
use std::time::Duration;
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::scc::{
    aes_encrypt_with_key, sign_hash, validate_sig, Fr, Pt, PublicKey, SchnorrSig, SecretKey,
};
use stegos_crypto::CryptoError;
// use stegos_serialization::traits::ProtoConvert;

// -----------------------------------------------------------

pub const CHAT_MESSAGE_LIFETIME: Duration = Duration::from_secs(30 * 86400);

// expected total size 2048 Bytes
// Assumed overhead of  248 bytes
pub const BYTES_PER_MESSAGE: usize = 1739;
pub const PTS_PER_CHAIN_LIST: usize = 54; // = Floor((BYTES_PER_MESSAGE-2)/32)
pub const PAIRS_PER_MEMBER_LIST: usize = 27; // = Floor(PTS_PER_CHAIN_LIST / 2)

enum SubMsgType {
    Evictions = 0,
    NewMembers = 1,
    RawMsg = 2,
}

impl SubMsgType {
    fn decoding(byte: u8) -> Self {
        match byte {
            0u8 => SubMsgType::Evictions,
            1u8 => SubMsgType::NewMembers,
            _ => SubMsgType::RawMsg,
        }
    }
}

// Chat Message UTXO.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChatMessageOutput {
    /// Cloaked pubkey of owner
    pub recipient: Pt, // = key_hint_A * Chain_owner
    pub recipient_keying_hint: Pt, // key_hint_A = random_A * PKey_owner
    pub recipient_cloaking_hint: Fr, // = random_A * Chain_sender

    // Cloaked pubkey of sender
    pub sender: Pt,               // = key_hint_B * Chain_sender
    pub sender_keying_hint: Pt,   // key_hint_B = random_B * PKey_sender
    pub sender_cloaking_hint: Fr, // = random_B * Chain_owner

    /// Creation time of output. (= u64)
    pub created: Timestamp,

    /// Message sequence ID - just a random value,
    /// constant across all fragments
    pub sequence: u64,
    // Segmentation info msg #x of #n
    pub msg_nbr: u32,
    pub msg_tot: u32,

    // Signature of hash of UTXO wrt cloaked Sender pkey
    pub signature: SchnorrSig,

    // size limited so that total UTXO size is 2048 bytes
    pub payload: MessagePayload,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    EncryptedMessage(Vec<u8>),
    EncryptedChainCodes(Vec<Pt>),
}

#[derive(Debug, Fail)]
pub enum ChatError {
    #[fail(display = "Unknown Chat Message Payload Type '{}'.", _0)]
    UnknownChatPayload(u8),
    #[fail(display = "Invalid Cloaked Chain code Pt")]
    InvalidPoint,
    #[fail(display = "Duplicate Group/Channel ID")]
    DuplicateID,
    #[fail(display = "Invalid Group or Channel ID: {}", _0)]
    InvalidGroup(String),
}

impl Hashable for ChatMessageOutput {
    fn hash(&self, hasher: &mut Hasher) {
        // hash of everything in UTXO except signature
        self.recipient.hash(hasher);
        self.recipient_keying_hint.hash(hasher);
        self.recipient_cloaking_hint.hash(hasher);
        self.sender.hash(hasher);
        self.sender_keying_hint.hash(hasher);
        self.sender_cloaking_hint.hash(hasher);
        self.created.hash(hasher);
        self.sequence.hash(hasher);
        self.msg_nbr.hash(hasher);
        self.msg_tot.hash(hasher);
        self.payload.hash(hasher);
    }
}

impl Hashable for MessagePayload {
    fn hash(&self, hasher: &mut Hasher) {
        match self {
            MessagePayload::EncryptedMessage(m) => {
                "Message".hash(hasher);
                m.hash(hasher);
            }
            MessagePayload::EncryptedChainCodes(pts) => {
                "ChainCodes".hash(hasher);
                pts.iter().for_each(|pt| pt.hash(hasher));
            }
        }
    }
}

// --------------------------------------------------------------
// Dummy routines for use during incremental development

impl ChatMessageOutput {
    pub fn new() -> Self {
        ChatMessageOutput {
            recipient: Pt::one(),
            recipient_keying_hint: Pt::one(),
            recipient_cloaking_hint: Fr::zero(),
            sender: Pt::one(),
            sender_keying_hint: Pt::one(),
            sender_cloaking_hint: Fr::zero(),
            created: Timestamp::now(),
            sequence: 0,
            msg_nbr: 0,
            msg_tot: 0,
            signature: SchnorrSig::new(),
            payload: MessagePayload::dum(),
        }
    }

    /*
    pub fn to_str(&self) -> &str {
        // TODO
        "ChatMessageOutput".clone()
    }

    pub fn from_str(s: &str) -> Result<Self, CryptoError> {
        // TODO
        Ok(Self::new())
    }
    */
}

impl MessagePayload {
    pub fn dum() -> Self {
        MessagePayload::EncryptedMessage(Vec::<u8>::new())
    }

    /*
    pub fn to_str(&self) -> &str {
        // TODO
        "MessagePayload".clone()
    }

    pub fn from_str(s: &str) -> Result<Self, CryptoError> {
        // TODO
        Ok(Self::dum())
    }
    */
}

impl fmt::Debug for ChatMessageOutput {
    // TODO
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChatMessageOutput()")
    }
}

impl fmt::Debug for MessagePayload {
    // TODO
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessagePayload()")
    }
}

impl Eq for MessagePayload {}
impl PartialEq<MessagePayload> for MessagePayload {
    fn eq(&self, other: &MessagePayload) -> bool {
        match (self, other) {
            (MessagePayload::EncryptedChainCodes(a), MessagePayload::EncryptedChainCodes(b)) => {
                a.iter().zip(b.iter()).all(|(ka, kb)| *ka == *kb)
            }
            (MessagePayload::EncryptedMessage(a), MessagePayload::EncryptedMessage(b)) => {
                a.iter().zip(b.iter()).all(|(ta, tb)| *ta == *tb)
            }
            _ => false,
        }
    }
}

// -------------------------------------------------------------

#[derive(Clone)]
pub enum OutgoingChatPayload {
    // payload was decrypted into a list of evicted members
    Evictions(Vec<PublicKey>),
    // payload for telling group about new member (pkey,chain) info
    NewMembers(Vec<(PublicKey, Hash)>),
    // payload has been decrypted into plaintext of whatever content
    // leave room for 1 byte of SubMsgType info in encrypted payload
    PlainText(Vec<u8>),
}

#[derive(Clone)]
pub enum IncomingChatPayload {
    Evictions(Vec<PublicKey>),
    NewMembers(Vec<(PublicKey, Hash)>),
    PlainText(Vec<u8>),
    Rekeying(Hash),
}

/// ChatMessageOutput canary  canary for the light nodes..
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChatCanary {
    pub recipient: Pt,
    pub key_hint: Pt,
}

impl Hashable for ChatCanary {
    fn hash(&self, hasher: &mut Hasher) {
        self.recipient.hash(hasher);
        self.key_hint.hash(hasher);
    }
}

impl ChatMessageOutput {
    pub fn validate(&self) -> Result<(), BlockchainError> {
        let h = Hash::digest(&self);
        match validate_sig(&h, &self.signature, &PublicKey::from(self.sender)) {
            Ok(_) => Ok(()),
            Err(_) => Err(OutputError::InvalidMessageSignature(h).into()),
        }
    }

    pub fn get_expiration_date(&self) -> Option<Timestamp> {
        self.created.checked_add(CHAT_MESSAGE_LIFETIME)
    }

    pub fn canary(&self) -> ChatCanary {
        ChatCanary {
            recipient: self.recipient,
            key_hint: self.recipient_keying_hint,
        }
    }

    // tools for constructing new group messsages
    pub fn cloak_recipient(
        &mut self,
        owner_pkey: &PublicKey,
        owner_chain: &Hash,
        r_owner: &Fr,
        sender_chain: &Hash,
    ) {
        // key_hint = random_A * PKey_owner
        // cloaked_owner = key_hint * Chain_owner
        // cloak_hint = random_A * Chain_sender
        // To verify owner, check that Chain_owner * key_hint = cloaked_owner

        // During rekeying, everyone will use prior epoch Chain_owner.
        // But senders will use their new chain codes. Members will discover
        // the new chain code of sender by scanning payload list of cloaked Pkeys:
        //
        //   cloaked_Pkey = Pkey_member * new_chain_seed
        //
        // where, new_chain_seed was the seed of the new_chain_code:
        //
        //     new_chain_code = Fr(H(new_chain_seed * G)),
        //
        // for curve generator, G.
        //
        // So, assume the cloaked entry is for you. Divide by your secret key to
        // obtain trial value:
        //
        //   new_chain_code' = Fr(H(PKey_member * new_chain_seed/SKey_member))
        //
        //   You can know when you have correct new_chain_code by seeing if:
        //
        //      cloaked_sender == new_chain_code' * Key_hint_sender
        //
        //   If so, then you have found the new_chain_code from sender.
        //   Verify by seeing that:
        //
        //      owner_key_hint == owner_cloak_hint / new_chain_code * Pkey_owner
        //
        //   Now identify sender by scanning membership roster looking for PKey_member
        //   such that
        //
        //      sender_key_hint = sender_cloak_hint / chain_owner * PKey_member
        //
        self.recipient_keying_hint = *r_owner * Pt::from(*owner_pkey);
        self.recipient = self.recipient_keying_hint * Fr::from(*owner_chain);
        self.recipient_cloaking_hint = *r_owner * Fr::from(*sender_chain);
    }

    pub fn cloak_sender(
        &mut self,
        sender_pkey: &PublicKey,
        sender_chain: &Hash,
        r_sender: &Fr,
        owner_chain: &Hash,
    ) {
        // key_hint = random_B * PKey_sender
        // cloaked_sender = key_hint * Chain_sender
        // cloak_hint = random_B * Chain_owner
        //
        // To find sender, scan membership roster looking for Chain * key_hint = cloaked_sender.
        // You will then know PKey_sender from association with Chain_sender.
        self.sender_keying_hint = *r_sender * Pt::from(*sender_pkey);
        self.sender = self.sender_keying_hint * Fr::from(*sender_chain);
        self.sender_cloaking_hint = *r_sender * Fr::from(*owner_chain);
    }

    pub fn sign(&mut self, sender_skey: &SecretKey, sender_chain: &Hash, r_sender: &Fr) {
        // signed in key of = random_B * Chain_sender * PKey_sender
        let h = Hash::digest(self);
        let eff_skey =
            SecretKey::from(*r_sender * Fr::from(*sender_skey) * Fr::from(*sender_chain));
        self.signature = sign_hash(&h, &eff_skey);
    }

    pub fn compute_encryption_key(
        &self,
        owner_pkey: &PublicKey,
        owner_chain: &Hash,
        sender_pkey: &PublicKey,
        sender_chain: &Hash,
    ) -> Hash {
        // Key for payload AES/128 encryption/decryption
        // = H(Chain_owner * PKey_sender + Chain_sender * PKey_owner +
        //       random_B * PKey_sender + random_A * PKey_owner)
        let pt = Fr::from(*owner_chain) * Pt::from(*sender_pkey)
            + Fr::from(*sender_chain) * Pt::from(*owner_pkey)
            + self.sender_keying_hint
            + self.recipient_keying_hint;
        let mut hasher = Hasher::new();
        pt.hash(&mut hasher);
        hasher.result()
    }

    pub fn encrypt(&self, payload: &OutgoingChatPayload, key: &Hash) -> MessagePayload {
        let mut payload_bytes = [0u8; BYTES_PER_MESSAGE];
        match payload {
            OutgoingChatPayload::PlainText(m) => {
                let mut nel = m.len();
                if nel > BYTES_PER_MESSAGE - 1 {
                    nel = BYTES_PER_MESSAGE - 1
                }
                payload_bytes[0] = SubMsgType::RawMsg as u8;
                payload_bytes[1..nel + 1].copy_from_slice(&m[..nel]);
            }
            OutgoingChatPayload::Evictions(es) => {
                let ct = es.len();
                payload_bytes[0] = SubMsgType::Evictions as u8;
                payload_bytes[1] = ct as u8;
                let mut pos = 2;
                for e in es {
                    let e_bytes = e.to_bytes();
                    payload_bytes[pos..pos + 32].copy_from_slice(&e_bytes[..]);
                    pos += 32;
                }
            }
            OutgoingChatPayload::NewMembers(mems) => {
                let ct = mems.len();
                payload_bytes[0] = SubMsgType::NewMembers as u8;
                payload_bytes[1] = ct as u8;
                let mut pos = 2;
                for (pkey, chain) in mems {
                    let pkey_bytes = pkey.to_bytes();
                    payload_bytes[pos..pos + 32].copy_from_slice(&pkey_bytes[..]);
                    pos += 32;
                    let chain_bytes = chain.to_bytes();
                    payload_bytes[pos..pos + 32].copy_from_slice(&chain_bytes[..]);
                    pos += 32;
                }
            }
        }
        let cypher_text = aes_encrypt_with_key(&payload_bytes, &key.bits());
        MessagePayload::EncryptedMessage(cypher_text)
    }

    pub fn decrypt(&self, key: &Hash, ctxt: &[u8]) -> Result<IncomingChatPayload, CryptoError> {
        let plain_text = stegos_crypto::scc::aes_encrypt_with_key(ctxt, &key.bits());
        let nb = plain_text.len();
        if nb < 1 {
            return Ok(IncomingChatPayload::PlainText(plain_text));
        }
        match SubMsgType::decoding(plain_text[0]) {
            SubMsgType::RawMsg => Ok(IncomingChatPayload::PlainText(plain_text[1..].to_vec())),
            SubMsgType::NewMembers => {
                let mut pairs = Vec::<(PublicKey, Hash)>::new();
                if nb > 1 {
                    let ct = plain_text[1] as usize;
                    if (ct * 32 * 2 + 2) > nb {
                        return Err(CryptoError::InvalidDecryption);
                    }
                    let mut pos = 2;
                    for _ in 0..ct {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&plain_text[pos..pos + 32]);
                        pos += 32;
                        let pkey = PublicKey::try_from_bytes(&bytes)?;
                        bytes.copy_from_slice(&plain_text[pos..pos + 32]);
                        pos += 32;
                        let chain = Hash::try_from_bytes(&bytes)?;
                        pairs.push((pkey, chain));
                    }
                }
                Ok(IncomingChatPayload::NewMembers(pairs))
            }
            SubMsgType::Evictions => {
                let mut pkeys = Vec::<PublicKey>::new();
                if nb > 1 {
                    let ct = plain_text[1] as usize;
                    if (ct * 32 + 2) > nb {
                        return Err(CryptoError::InvalidDecryption);
                    }
                    let mut pos = 2;
                    for _ in 0..ct {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&plain_text[pos..pos + 32]);
                        pos += 32;
                        let pkey = PublicKey::try_from_bytes(&bytes)?;
                        pkeys.push(pkey);
                    }
                }
                Ok(IncomingChatPayload::Evictions(pkeys))
            }
        }
    }
}

/// Send in some plaintext, get a ChatMessageOutput UTXO in return.
pub fn make_chat_message(
    owner_pkey: &PublicKey,
    owner_chain: &Hash,
    sender_skey: &SecretKey,
    sender_pkey: &PublicKey,
    sender_chain: &Hash,
    message: &[u8],
) -> ChatMessageOutput {
    let mut msg = ChatMessageOutput::new();
    let r_owner = detrand(owner_pkey, owner_chain);
    let r_sender = detrand(sender_pkey, sender_chain);
    msg.cloak_recipient(owner_pkey, owner_chain, &r_owner, sender_chain);
    msg.cloak_sender(sender_pkey, sender_chain, &r_sender, owner_chain);
    let mut payload_bytes = [0u8; BYTES_PER_MESSAGE];
    let nmsg = message.len();
    payload_bytes[..nmsg].copy_from_slice(&message[..]);
    let key = msg.compute_encryption_key(owner_pkey, owner_chain, sender_pkey, sender_chain);
    msg.payload = msg.encrypt(
        &OutgoingChatPayload::PlainText(payload_bytes.to_vec()),
        &key,
    );
    msg.sign(sender_skey, sender_chain, &r_sender);
    msg
}

pub fn detrand(pkey: &PublicKey, chain: &Hash) -> Fr {
    // make a deterministic random Fr value
    let mut hasher = Hasher::new();
    pkey.hash(&mut hasher);
    chain.hash(&mut hasher);
    let x = Fr::random();
    x.hash(&mut hasher);
    let h = hasher.result().rshift(4);
    Fr::from(h)
}

pub fn new_chain_code(pkey: &PublicKey, chain: &Hash) -> (Fr, Hash) {
    // Use deterministic randomness based on hash of pkey, chain, random Fr
    let c = detrand(pkey, chain);
    let pt = c * Pt::one();
    let chain = Hash::digest(&pt).rshift(4); // ensure fits in Fr
    (c, chain)
}

// ------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use stegos_crypto::scc;
    use stegos_serialization::traits::ProtoConvert;

    #[test]
    fn check_chat_message_size() {
        let (_owner_skey, owner_pkey) = scc::make_random_keys();
        let (sender_skey, sender_pkey) = scc::make_random_keys();
        let initial_owner_chain = Hash::digest(&owner_pkey);
        let (_owner_c, owner_chain) = new_chain_code(&owner_pkey, &initial_owner_chain);
        let initial_sender_chain = Hash::digest(&sender_pkey);
        let (_sender_c, sender_chain) = new_chain_code(&sender_pkey, &initial_sender_chain);
        let txt = b"This is a test";
        // Check that we can construct an encrypted group message UTXO
        let utxo = make_chat_message(
            &owner_pkey,
            &owner_chain,
            &sender_skey,
            &sender_pkey,
            &sender_chain,
            &txt[..],
        );
        let key =
            utxo.compute_encryption_key(&owner_pkey, &owner_chain, &sender_pkey, &sender_chain);
        // Check that we can serialize this UTXO
        let buffer = utxo.into_buffer().expect("Can't serialize Chat UTXO");
        // Check that it has the expected length
        println!("Chat UTXO size = {}", buffer.len());
        assert!(buffer.len() == 2048);
        // Check that we can deserialize back to a ChatMessageOutput UTXO
        let reconst = ChatMessageOutput::from_buffer(&buffer).expect("Can't deserialize");
        // Check that it has the expected contents
        match reconst.payload.clone() {
            MessagePayload::EncryptedMessage(enc) => {
                // Yes, it should have been an EncryptedMessage
                // Try to decrypt it...
                match reconst.decrypt(&key, &enc[..]).expect("Can't decrypt") {
                    IncomingChatPayload::PlainText(recovered) => {
                        // Yes, it should have been seen as a PlainText
                        // Check that it has the expected length
                        assert!(recovered.len() == BYTES_PER_MESSAGE - 1);
                        // Now compare the contents of the decrypted message
                        // against what we expect should be there....
                        let mut expected = [0u8; BYTES_PER_MESSAGE - 1];
                        let nel = txt.len();
                        expected[0..nel].copy_from_slice(&txt[..]);
                        assert!(recovered.iter().zip(expected.iter()).all(|(a, b)| *a == *b));
                    }
                    _ => {
                        panic!("Expected IncomingChatPayload::PlainText");
                    }
                }
            }
            _ => {
                panic!("Expected MessagePayload::EncryptedMessage");
            }
        }
    }
}
