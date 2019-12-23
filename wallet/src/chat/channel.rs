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

#![allow(unused_variables)]
#![allow(dead_code)]
use failure::{bail, Error};
use stegos_blockchain::{make_chat_message, ChatMessageOutput, IncomingChatPayload};
use stegos_crypto::hash::Hash;

use stegos_crypto::scc::{Fr, PublicKey, SecretKey};

use super::{Chat, UtxoInfo};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChannelInvite {
    pub owner_pkey: PublicKey,
    pub owner_chain: Fr,
}

impl Serialize for ChannelInvite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_data = self.to_base64();
        hex_data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChannelInvite {
    fn deserialize<D>(deserializer: D) -> Result<ChannelInvite, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_data: &str = Deserialize::deserialize(deserializer)?;
        ChannelInvite::try_from_base64(hex_data).map_err(de::Error::custom)
    }
}

impl ChannelInvite {
    const DATA_SIZE: usize = 64;
    fn to_base64(&self) -> String {
        let mut data = Vec::with_capacity(Self::DATA_SIZE);
        data.extend_from_slice(&self.owner_pkey.to_bytes());
        data.extend_from_slice(&self.owner_chain.to_bytes());
        base64::encode(&data)
    }

    fn try_from_base64(source: &str) -> Result<Self, Error> {
        let data = base64::decode(source)?;
        if data.len() != Self::DATA_SIZE {
            bail!(
                "Hex string not equal to {}, invite_len={}",
                Self::DATA_SIZE,
                data.len()
            )
        }
        let owner_pkey = PublicKey::try_from_bytes(&data[..32])?;
        let owner_chain = Fr::try_from_bytes(&data[32..])?;

        Ok(ChannelInvite {
            owner_pkey,
            owner_chain,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChannelOwnerInfo {
    // description of the Group / Channel
    pub channel_id: String,
    // Public key used for this group ownership
    pub owner_pkey: PublicKey,
    // Secret key used for this group ownership
    pub owner_skey: SecretKey,
    // current chain code
    pub owner_chain: Fr,
}

#[derive(Debug, Clone)]
pub struct ChannelSession {
    // description of the Channel
    pub channel_id: String,
    // owner of the Channel
    pub owner_pkey: PublicKey,
    // owner chain code for session
    pub owner_chain: Fr,
}

impl ChannelSession {
    pub fn decrypt_channel_message(
        &self,
        utxo: &ChatMessageOutput,
        ctxt: &[u8],
    ) -> Option<Vec<u8>> {
        let key = utxo.compute_encryption_key(
            &self.owner_pkey,
            &self.owner_chain,
            &self.owner_pkey,
            &self.owner_chain,
        );
        match utxo.decrypt(&key, ctxt) {
            Ok(m) => {
                match m {
                    IncomingChatPayload::PlainText(txt) => Some(txt),

                    // ignore these - they shouldn't exist for Channels
                    IncomingChatPayload::Evictions(_) => None,
                    // ignore these - they shouldn't exist for Channels
                    IncomingChatPayload::NewMembers(_) => None,
                    // no reason for channel owner to ever switch chain codes
                    IncomingChatPayload::Rekeying(_) => unreachable!(),
                }
            }
            Err(_) => None,
        }
    }
}

// -----------------------------------------------------------------

impl ChannelOwnerInfo {
    pub fn record_utxo(&self, chat: &mut Chat, utxo: &ChatMessageOutput) {
        chat.my_utxos.push(UtxoInfo {
            id: Hash::digest(utxo),
            created: utxo.created,
            keying: utxo.recipient_cloaking_hint * Fr::from(self.owner_skey),
        })
    }

    pub fn new_message(&self, msg: Vec<u8>) -> ChatMessageOutput {
        make_chat_message(
            &self.owner_pkey,
            &self.owner_chain,
            &self.owner_skey,
            &self.owner_pkey,
            &self.owner_chain,
            &msg[..],
        )
    }
}
