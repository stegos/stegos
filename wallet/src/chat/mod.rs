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

#![allow(unused_variables)]
#![allow(dead_code)]
// use stegos_blockchain::timestamp::Timestamp;
use stegos_blockchain::{
    detrand, make_chat_message, new_chain_code, ChatError, ChatMessageOutput, IncomingChatPayload,
    MessagePayload, OutgoingChatPayload, Timestamp, PAIRS_PER_MEMBER_LIST, PTS_PER_CHAIN_LIST,
};
use stegos_crypto::hash::Hash;
// use crate::{BlockchainError, OutputError};
// use curve25519_dalek::scalar::Scalar;
// use failure::{Error, Fail};
use rand::Rng;
// use serde::de::{Deserialize, Deserializer};
// use serde::ser::{Serialize, Serializer};
// use serde_derive::{Deserialize, Serialize};
// use std::fmt;
// use std::mem::transmute;
// use std::time::Duration;
use stegos_crypto::scc::{Fr, Pt, PublicKey, SecretKey};
// use stegos_crypto::CryptoError;
use stegos_serialization::traits::ProtoConvert;

// ----------------------------------------------------------------------------------

/*
macro_rules! sdebug {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Debug, concat!("[{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}
macro_rules! sinfo {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Info, concat!("[{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}
*/
macro_rules! swarn {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Warn, concat!("[{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}

macro_rules! serror {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Error, concat!("[{}] ({}) ", $fmt), $self.account_pkey, $self.state.name(), $($arg),*);
    );
}

// --------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct GroupMember {
    pub pkey: PublicKey,
    pub chain: Hash,
    pub epoch: Timestamp,
}

#[derive(Clone)]
pub struct MemberRoster(Vec<GroupMember>);

#[derive(Clone)]
pub struct GroupOwnerInfo {
    // description of the Group / Channel
    pub group_id: String,
    // Public key used for this group ownership
    pub owner_pkey: PublicKey,
    // Secret key used for this group ownership
    pub owner_skey: SecretKey,
    // current chain code
    pub owner_chain: Hash,
    // chain for use in group rekeyings
    pub owner_rekeying_chain: Hash,
    // list of members / subscribers
    pub members: MemberRoster,
    // list of ignored members
    pub ignored_members: Vec<PublicKey>,
    // list of messages received
    pub messages: Vec<(PublicKey, Vec<u8>)>,
}

#[derive(Clone)]
pub struct ChatSession {
    // description of the Group
    pub group_id: String,
    // owner of the group
    pub owner_pkey: PublicKey,
    // owner chain code for session
    pub owner_chain: Hash,
    // owner chain code for rekeying purposes
    pub owner_rekeying_chain: Hash,
    // my public key for group chat purposees
    pub my_pkey: PublicKey,
    // my secret key for group chat purposes
    pub my_skey: SecretKey,
    // my current chain code
    pub my_chain: Hash,
    // list of other group members and their chain codes
    pub members: MemberRoster,
    // list of ignored members
    pub ignored_members: Vec<PublicKey>,
    // list of messages received
    pub messages: Vec<(PublicKey, Vec<u8>)>,
}

#[derive(Clone)]
pub struct ChannelOwnerInfo {
    // description of the Group / Channel
    pub channel_id: String,
    // Public key used for this group ownership
    pub owner_pkey: PublicKey,
    // Secret key used for this group ownership
    pub owner_skey: SecretKey,
    // current chain code
    pub owner_chain: Hash,
}

#[derive(Clone)]
pub struct ChannelSession {
    // description of the Channel
    pub channel_id: String,
    // owner of the Channel
    pub owner_pkey: PublicKey,
    // owner chain code for session
    pub owner_chain: Hash,
    // list of messages received
    pub messages: Vec<(PublicKey, Vec<u8>)>,
}

#[derive(Clone)]
pub enum ChatMessage {
    // represents the output of get_message()
    None,
    Rekeying(Vec<ChatMessageOutput>),
    Text((PublicKey, Vec<u8>)),
}

impl MemberRoster {
    pub fn evict(&mut self, evicted_members: &Vec<PublicKey>) {
        // remove indicated members from our roster
        let remaining: Vec<GroupMember> = self
            .0
            .iter()
            .filter(|&mem| !evicted_members.contains(&mem.pkey))
            .cloned()
            .collect();
        self.0 = remaining;
    }

    pub fn generate_rekeying_messages(
        &mut self,
        owner_pkey: &PublicKey,
        owner_chain: &Hash,
        sender_skey: &SecretKey,
        sender_pkey: &PublicKey,
        sender_chain: &Hash,
        new_chain_seed: &Fr,
    ) -> Vec<ChatMessageOutput> {
        // Generate one or more Rekeying messages for use in a Transaction
        let n_members = self.0.len();
        let msg_tot = ((n_members + PTS_PER_CHAIN_LIST - 1) / PTS_PER_CHAIN_LIST) as u32;
        let mut msg_nbr = 0;
        let msg_ser: u64 = rand::thread_rng().gen();
        let mut mem_nbr = 0;
        let mut cloaked_pkeys = Vec::<Pt>::new();
        let mut msgs = Vec::<ChatMessageOutput>::new();

        // this kind of shit is really infuriating... why not make a real closure with lexical bindings?
        fn generate_message(
            owner_pkey: &PublicKey,
            owner_chain: &Hash,
            sender_skey: &SecretKey,
            sender_pkey: &PublicKey,
            sender_chain: &Hash,
            msg_ser: u64,
            msg_nbr: u32,
            msg_tot: u32,
            cloaked_pkeys: &Vec<Pt>,
        ) -> ChatMessageOutput {
            let mut msg = ChatMessageOutput::new();
            msg.sequence = msg_ser;
            msg.msg_nbr = msg_nbr;
            msg.msg_tot = msg_tot;
            msg.payload = MessagePayload::EncryptedChainCodes(cloaked_pkeys.clone());
            let r_owner = detrand(owner_pkey, owner_chain);
            let r_sender = detrand(sender_pkey, sender_chain);
            msg.cloak_recipient(owner_pkey, owner_chain, &r_owner, sender_chain);
            msg.cloak_sender(sender_pkey, sender_chain, &r_sender, owner_chain);
            msg.sign(sender_skey, sender_chain, &r_sender);
            msg
        }

        self.0.iter().for_each(|mem| {
            let cpt = *new_chain_seed * Pt::from(mem.pkey);
            cloaked_pkeys.push(cpt);
            mem_nbr += 1;
            if mem_nbr >= PTS_PER_CHAIN_LIST {
                msgs.push(generate_message(
                    owner_pkey,
                    owner_chain,
                    sender_skey,
                    sender_pkey,
                    sender_chain,
                    msg_ser,
                    msg_nbr,
                    msg_tot,
                    &cloaked_pkeys,
                ));
                cloaked_pkeys = Vec::<Pt>::new();
                msg_nbr += 1;
                mem_nbr = 0;
            }
        });
        if mem_nbr > 0 {
            msgs.push(generate_message(
                owner_pkey,
                owner_chain,
                sender_skey,
                sender_pkey,
                sender_chain,
                msg_ser,
                msg_nbr,
                msg_tot,
                &cloaked_pkeys,
            ));
        };
        msgs
    }

    pub fn find_sender_chain(&self, utxo: &ChatMessageOutput) -> Option<&GroupMember> {
        // for use on general group messages
        self.0
            .iter()
            .find(|mem| utxo.sender == utxo.sender_keying_hint * Fr::from(mem.chain))
    }

    pub fn decrypt_chat_message(
        &self,
        owner_pkey: &PublicKey,
        owner_chain: &Hash,
        utxo: &ChatMessageOutput,
        ctxt: &[u8],
    ) -> Option<(PublicKey, IncomingChatPayload)> {
        // for use on general group messages
        match self.find_sender_chain(utxo) {
            None => None,
            Some(member) => {
                let key = utxo.compute_encryption_key(
                    owner_pkey,
                    owner_chain,
                    &member.pkey,
                    &member.chain,
                );
                match utxo.decrypt(&key, ctxt) {
                    Ok(m) => Some((member.pkey.clone(), m)),
                    Err(_) => None,
                }
            }
        }
    }

    pub fn find_sender_newchain(
        &self,
        skey: &SecretKey,
        owner_chain: &Hash,
        utxo: &ChatMessageOutput,
        pts: &Vec<Pt>,
    ) -> Option<(PublicKey, Hash, Timestamp)> {
        // utxo is expected to carry cloaked chain codes
        let sf = Fr::one() / Fr::from(*skey);
        let sfk = utxo.sender_cloaking_hint / Fr::from(*owner_chain);
        let mut ans = None;
        pts.iter().find(|&&pt| {
            let cg = sf * pt;
            let chain = Hash::digest(&cg).rshift(4);
            let fr = Fr::from(chain);
            self.0.iter().find(|mem| {
                if utxo.sender_keying_hint == sfk * Pt::from(mem.pkey) {
                    ans = Some((mem.pkey.clone(), chain.clone(), mem.epoch));
                    true
                } else {
                    false
                }
            });
            ans.is_some()
        });
        ans
    }

    pub fn process_rekeying_message(
        &mut self,
        my_skey: &SecretKey,
        owner_pkey: &PublicKey,
        owner_chain: &Hash,
        utxo: &ChatMessageOutput,
        pts: &Vec<Pt>,
    ) -> Option<(PublicKey, Hash)> {
        // when utxo is a rekeying message
        match self.find_sender_newchain(my_skey, owner_chain, utxo, pts) {
            Some((pkey, chain, epoch)) => {
                // ignore stale rekeying UTXOs
                if utxo.created > epoch {
                    let trimmed: Vec<GroupMember> = self
                        .0
                        .iter()
                        .filter(|mem| mem.pkey != pkey)
                        .cloned()
                        .collect();
                    self.0 = trimmed;
                    self.0.push(GroupMember {
                        pkey,
                        chain,
                        epoch: utxo.created,
                    });
                    Some((pkey, chain))
                } else {
                    None
                }
            }
            None => None,
        }
    }

    fn is_one_of_mine(
        &self,
        owner_chain: &Hash,
        my_pkey: &PublicKey,
        my_chain: &Hash,
        utxo: &ChatMessageOutput,
    ) -> bool {
        utxo.sender
            == utxo.sender_cloaking_hint * Fr::from(*my_chain) / Fr::from(*owner_chain)
                * Pt::from(*my_pkey)
    }

    pub fn get_decrypted_message(
        &mut self,
        owner_pkey: &PublicKey,
        owner_chain: &Hash,
        my_skey: &SecretKey,
        my_pkey: &PublicKey,
        my_chain: &Hash,
        utxo: &ChatMessageOutput,
    ) -> Option<(PublicKey, IncomingChatPayload)> {
        match &utxo.payload {
            MessagePayload::EncryptedChainCodes(m) => {
                // Silently handle rekeyings
                if !self.is_one_of_mine(owner_chain, my_pkey, my_chain, utxo) {
                    // ignore my own messages
                    if let Some((sender, chain)) =
                        self.process_rekeying_message(my_skey, owner_pkey, owner_chain, utxo, m)
                    {
                        Some((sender, IncomingChatPayload::Rekeying(chain)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            MessagePayload::EncryptedMessage(m) => {
                self.decrypt_chat_message(owner_pkey, owner_chain, utxo, m)
            }
        }
    }

    pub fn add_members_to_roster(&mut self, vec: &Vec<(PublicKey, Hash)>, epoch: Timestamp) {
        let mut members = Vec::<GroupMember>::new();
        for (pkey, chain) in vec.iter() {
            // the following test weeds out duplicate entries by pkey
            if !members
                .clone()
                .iter()
                .find(|mem| mem.pkey == *pkey)
                .is_some()
            {
                members.push(GroupMember {
                    pkey: pkey.clone(),
                    chain: chain.clone(),
                    epoch,
                });
            }
        }
        for mem in self.0.iter() {
            // if we already have a member our old roster,
            // then delete our existing entry, and accept owner's suggestion
            // as definitive.
            if !members
                .clone()
                .iter()
                .find(|existing| mem.pkey == existing.pkey)
                .is_some()
            {
                members.push(mem.clone());
            }
        }
        self.0 = members;
    }
}

impl ChannelOwnerInfo {
    fn record_utxo(&self, chat: &mut Chat, utxo: &ChatMessageOutput) {
        chat.my_utxos.push(UtxoInfo {
            id: Hash::digest(utxo),
            created: utxo.created,
            keying: utxo.recipient_cloaking_hint * Fr::from(self.owner_skey),
        })
    }

    fn get_message(&self, chat: &mut Chat, utxo: &ChatMessageOutput) -> ChatMessage {
        // verify that message was from me
        if utxo.sender_cloaking_hint * Pt::from(self.owner_pkey) == utxo.sender {
            self.record_utxo(chat, utxo);
        } else {
            swarn!(
                chat,
                "Channel Owner received Channel message from non-owner"
            );
        }
        ChatMessage::None
    }

    fn new_message(&self, msg: Vec<u8>) -> ChatMessageOutput {
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

impl GroupOwnerInfo {
    /// GUI Alert - someone needs to decide when to do this
    pub fn evict_members(&mut self, evicted_members: &Vec<PublicKey>) -> Vec<ChatMessageOutput> {
        // Generate one or more Member Eviction messages, plus one or more Rekeying messages,
        // all for use in a Transaction
        self.members.evict(evicted_members);
        let mut msgs = self.generate_eviction_notice(evicted_members);
        let (chain_seed, new_chain) = new_chain_code(&self.owner_pkey, &self.owner_chain);
        self.owner_chain = new_chain;
        let mut more_msgs = self.members.generate_rekeying_messages(
            &self.owner_pkey,
            &self.owner_rekeying_chain,
            &self.owner_skey,
            &self.owner_pkey,
            &self.owner_chain,
            &chain_seed,
        );
        msgs.append(&mut more_msgs);
        // GUI Alert - on return, caller should send a transaction with these UTXO
        msgs
    }

    pub fn generate_eviction_notice(&self, members: &Vec<PublicKey>) -> Vec<ChatMessageOutput> {
        let msg_ser: u64 = rand::thread_rng().gen();
        let msg_tot = ((members.len() + PTS_PER_CHAIN_LIST - 1) / PTS_PER_CHAIN_LIST) as u32;
        let mut msg_nbr = 0u32;
        let mut mem_nbr = 0;
        let mut msgs = Vec::<ChatMessageOutput>::new();
        let mut evicted = Vec::<PublicKey>::new();

        fn generate_message(
            info: &GroupOwnerInfo,
            msg_ser: u64,
            msg_nbr: u32,
            msg_tot: u32,
            r_owner: Fr,
            r_sender: Fr,
            evicted: &Vec<PublicKey>,
        ) -> ChatMessageOutput {
            let mut msg = ChatMessageOutput::new();
            msg.sequence = msg_ser;
            msg.msg_nbr = msg_nbr;
            msg.msg_tot = msg_tot;
            msg.cloak_recipient(
                &info.owner_pkey,
                &info.owner_chain,
                &r_owner,
                &info.owner_chain,
            );
            msg.cloak_sender(
                &info.owner_pkey,
                &info.owner_chain,
                &r_sender,
                &info.owner_chain,
            );
            let key = msg.compute_encryption_key(
                &info.owner_pkey,
                &info.owner_chain,
                &info.owner_pkey,
                &info.owner_chain,
            );
            msg.payload = msg.encrypt(&OutgoingChatPayload::Evictions(evicted.clone()), &key);
            msg.sign(&info.owner_skey, &info.owner_chain, &r_sender);
            msg
        }

        members.iter().for_each(|m| {
            evicted.push(*m);
            mem_nbr += 1;
            if mem_nbr >= PTS_PER_CHAIN_LIST {
                let r_owner = detrand(&self.owner_pkey, &self.owner_rekeying_chain);
                let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
                msgs.push(generate_message(
                    self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &evicted,
                ));
                msg_nbr += 1;
                mem_nbr = 0;
                evicted = Vec::<PublicKey>::new();
            }
        });
        if mem_nbr > 0 {
            let r_owner = detrand(&self.owner_pkey, &self.owner_rekeying_chain);
            let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
            msgs.push(generate_message(
                self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &evicted,
            ));
        }
        msgs
    }

    fn record_utxo(
        &mut self,
        chat: &mut Chat,
        utxo: &ChatMessageOutput,
        owner_chain: &Hash,
        sender: PublicKey,
    ) {
        match self.members.find_sender_chain(utxo) {
            Some(member) => {
                chat.my_utxos.push(UtxoInfo {
                    id: Hash::digest(utxo),
                    created: utxo.created,
                    keying: utxo.recipient_cloaking_hint * Fr::from(*owner_chain)
                        / Fr::from(member.chain)
                        * Fr::from(self.owner_skey),
                });
            }
            None => unreachable!(),
        }
    }

    pub fn get_message(
        &mut self,
        chat: &mut Chat,
        utxo: &ChatMessageOutput,
        owner_chain: &Hash,
    ) -> ChatMessage {
        match self.members.get_decrypted_message(
            &self.owner_pkey,
            owner_chain,
            &self.owner_skey,
            &self.owner_pkey,
            &self.owner_chain,
            utxo,
        ) {
            None => ChatMessage::None,
            Some((sender, msg)) => {
                // All chat messages belong to me...
                self.record_utxo(chat, utxo, owner_chain, sender);
                if sender == self.owner_pkey {
                    // was my own message
                    ChatMessage::None
                } else {
                    match msg {
                        IncomingChatPayload::Evictions(_) => {
                            // should never happend since only I can produce them
                            ChatMessage::None
                        }
                        IncomingChatPayload::Rekeying(chain) => {
                            // rekeying was already handled by side effect of get_decrypted_message
                            ChatMessage::None
                        }
                        IncomingChatPayload::NewMembers(_) => {
                            // only I ever send these messages, when legitimate.
                            // if someone else sent one of these, just ignore it.
                            ChatMessage::None
                        }
                        IncomingChatPayload::PlainText(m) => ChatMessage::Text((sender, m)),
                    }
                }
            }
        }
    }

    fn new_message(&self, msg: Vec<u8>) -> ChatMessageOutput {
        make_chat_message(
            &self.owner_pkey,
            &self.owner_chain,
            &self.owner_skey,
            &self.owner_pkey,
            &self.owner_chain,
            &msg[..],
        )
    }

    fn get_owner_chain(&self, msg: &ChatMessageOutput) -> Hash {
        match msg.payload {
            MessagePayload::EncryptedMessage(_) => self.owner_chain,
            MessagePayload::EncryptedChainCodes(_) => self.owner_rekeying_chain,
        }
    }

    // GUI Alert -- call this after you have a list of one or more new member PublicKeys.
    pub fn add_new_members(
        &mut self,
        new_members: Vec<PublicKey>,
    ) -> (Vec<(PublicKey, Hash)>, Vec<ChatMessageOutput>) {
        // Accept a list of new member PublicKeys
        // Add them with new chain codes to our own roster,
        // then send one or more NewMember messages to the group
        let mut pairs = Vec::<(PublicKey, Hash)>::new();
        for pkey in new_members.iter() {
            let (_, chain) = new_chain_code(&pkey, &self.owner_chain);
            pairs.push((pkey.clone(), chain.clone()));
        }
        let epoch = Timestamp::now();
        self.members.add_members_to_roster(&mut pairs, epoch);

        let msg_ser: u64 = rand::thread_rng().gen();
        let msg_tot = ((pairs.len() + PAIRS_PER_MEMBER_LIST - 1) / PAIRS_PER_MEMBER_LIST) as u32;
        let mut msg_nbr = 0u32;
        let mut mem_nbr = 0;
        let mut msgs = Vec::<ChatMessageOutput>::new();
        let mut joined = Vec::<(PublicKey, Hash)>::new();

        fn generate_message(
            info: &GroupOwnerInfo,
            msg_ser: u64,
            msg_nbr: u32,
            msg_tot: u32,
            r_owner: Fr,
            r_sender: Fr,
            joined: &Vec<(PublicKey, Hash)>,
        ) -> ChatMessageOutput {
            let mut msg = ChatMessageOutput::new();
            msg.sequence = msg_ser;
            msg.msg_nbr = msg_nbr;
            msg.msg_tot = msg_tot;
            msg.cloak_recipient(
                &info.owner_pkey,
                &info.owner_chain,
                &r_owner,
                &info.owner_chain,
            );
            msg.cloak_sender(
                &info.owner_pkey,
                &info.owner_chain,
                &r_sender,
                &info.owner_chain,
            );
            let key = msg.compute_encryption_key(
                &info.owner_pkey,
                &info.owner_chain,
                &info.owner_pkey,
                &info.owner_chain,
            );
            msg.payload = msg.encrypt(&OutgoingChatPayload::NewMembers(joined.clone()), &key);
            msg.sign(&info.owner_skey, &info.owner_chain, &r_sender);
            msg
        }

        pairs.iter().for_each(|pair| {
            joined.push(pair.clone());
            mem_nbr += 1;
            if mem_nbr >= PAIRS_PER_MEMBER_LIST {
                let r_owner = detrand(&self.owner_pkey, &self.owner_rekeying_chain);
                let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
                msgs.push(generate_message(
                    self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &joined,
                ));
                msg_nbr += 1;
                mem_nbr = 0;
                joined = Vec::<(PublicKey, Hash)>::new();
            }
        });
        if mem_nbr > 0 {
            let r_owner = detrand(&self.owner_pkey, &self.owner_rekeying_chain);
            let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
            msgs.push(generate_message(
                self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &joined,
            ));
        }
        (pairs, msgs)
    }
}

impl ChatSession {
    // one of these for every member of a group, except owner
    pub fn evict_members(&mut self, evicted_members: &Vec<PublicKey>) -> Vec<ChatMessageOutput> {
        // Upon receiving a list of member to evict from the group,
        // remove them from our local roster, and make one or more Rekeying
        // messages for a Transaction.
        self.members.evict(evicted_members);
        self.tell_rekeying()
    }

    pub fn tell_rekeying(&mut self) -> Vec<ChatMessageOutput> {
        // Make one or more Rekeying messages for a Transaction.
        let (chain_seed, new_chain) = new_chain_code(&self.my_pkey, &self.my_chain);
        self.my_chain = new_chain;
        self.members.generate_rekeying_messages(
            &self.owner_pkey,
            &self.owner_rekeying_chain,
            &self.my_skey,
            &self.my_pkey,
            &self.my_chain,
            &chain_seed,
        )
    }

    pub fn get_message(
        &mut self,
        chat: &mut Chat,
        utxo: &ChatMessageOutput,
        owner_chain: &Hash,
    ) -> ChatMessage {
        match self.members.get_decrypted_message(
            &self.owner_pkey,
            owner_chain,
            &self.my_skey,
            &self.my_pkey,
            &self.my_chain,
            utxo,
        ) {
            None => ChatMessage::None,
            Some((sender, msg)) => {
                if sender == self.my_pkey {
                    // ignore my own messages
                    ChatMessage::None
                } else {
                    match msg {
                        IncomingChatPayload::Evictions(evicted_members) => {
                            if sender == self.owner_pkey {
                                // form and send a transaction with rekeying messages0
                                let rekeying_msgs = self.evict_members(&evicted_members);
                                ChatMessage::Rekeying(rekeying_msgs)
                            } else {
                                // someone is trying to spoof us - just ignore them
                                ChatMessage::None
                            }
                        }
                        IncomingChatPayload::Rekeying(_) => {
                            // already handled
                            ChatMessage::None
                        }
                        IncomingChatPayload::NewMembers(vec) => {
                            if sender == self.owner_pkey {
                                // just ignore if from anyone other than group owner
                                self.members.add_members_to_roster(&vec, utxo.created);
                            }
                            ChatMessage::None
                        }
                        IncomingChatPayload::PlainText(m) => ChatMessage::Text((sender, m)),
                    }
                }
            }
        }
    }

    fn new_message(&self, msg: Vec<u8>) -> ChatMessageOutput {
        make_chat_message(
            &self.owner_pkey,
            &self.owner_chain,
            &self.my_skey,
            &self.my_pkey,
            &self.my_chain,
            &msg[..],
        )
    }

    fn get_owner_chain(&self, msg: &ChatMessageOutput) -> Hash {
        match msg.payload {
            MessagePayload::EncryptedMessage(_) => self.owner_chain,
            MessagePayload::EncryptedChainCodes(_) => self.owner_rekeying_chain,
        }
    }
}

impl ChannelSession {
    // one of these for every member of a group, except owner
    pub fn get_message(&mut self, chat: &mut Chat, utxo: &ChatMessageOutput) -> ChatMessage {
        match &utxo.payload {
            MessagePayload::EncryptedChainCodes(_) => {
                // ignore these - they shouldn't exist in Channels
                ChatMessage::None
            }
            MessagePayload::EncryptedMessage(m) => match self.decrypt_channel_message(utxo, m) {
                None => ChatMessage::None,
                Some(txt) => ChatMessage::Text((self.owner_pkey.clone(), txt)),
            },
        }
    }

    fn decrypt_channel_message(&self, utxo: &ChatMessageOutput, ctxt: &[u8]) -> Option<Vec<u8>> {
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

// use futures::task::current;
use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;
use futures_stream_select_all_send::select_all;
use log::{log, Level};
use stegos_network::Network;

pub const CHAT_TOPIC: &'static str = "chat";

enum ChatEvent {
    MessageReceived(Vec<u8>),
}

enum ChatState {
    None,
    HandlingOwnedChatGroup,
    HandlingSubscribedChatGroup,
    HandlingOwnedChannel,
    HandlingSubscribedChannel,
}

impl ChatState {
    fn name(&self) -> &'static str {
        match *self {
            ChatState::None => "None",
            ChatState::HandlingOwnedChatGroup => "HandlingOwnedChatGroup",
            ChatState::HandlingSubscribedChatGroup => "HandlingSubscribedChatGroup",
            ChatState::HandlingOwnedChannel => "HandlingOwnedChannel",
            ChatState::HandlingSubscribedChannel => "HandlingSubscribedChannel",
        }
    }
}

#[derive(Clone)]
pub struct UtxoInfo {
    pub id: Hash,
    pub created: Timestamp,
    pub keying: Fr,
}

pub struct Chat {
    // Public key being used wallet transactions
    account_pkey: PublicKey,

    // Secret key for wallet transactions
    account_skey: SecretKey,

    // Public key being used for Chat purposes
    chat_pkey: PublicKey,

    // Secret key being used for Chat purposes
    chat_skey: SecretKey,

    // Collection of Groups that I own
    owned_groups: Vec<GroupOwnerInfo>,

    // Collection of Channels that I own
    owned_channels: Vec<ChannelOwnerInfo>,

    // Collection of Channels I subscribe to
    subscribed_channels: Vec<ChannelSession>,

    // Collection of Groups I subscribe to
    subscribed_groups: Vec<ChatSession>,

    // Collection of UTXOs that belong to me
    my_utxos: Vec<UtxoInfo>,

    /// Network API.
    network: Network,

    /// Incoming events.
    events: Box<dyn Stream<Item = ChatEvent, Error = ()> + Send>,

    /// State while processing
    state: ChatState,
}

impl Chat {
    // GUI Alert - somebody needs to call this to set things up
    // We probably need functions here to save/restore state info to
    // startup database.
    pub fn new(
        account_skey: SecretKey,
        account_pkey: PublicKey,
        chat_skey: SecretKey,
        chat_pkey: PublicKey,
        network: Network,
    ) -> Chat {
        let mut events: Vec<Box<dyn Stream<Item = ChatEvent, Error = ()> + Send>> = Vec::new();
        // Network.
        let groups_joined = network
            .subscribe_unicast(CHAT_TOPIC)
            .expect("connected")
            .map(|m| ChatEvent::MessageReceived(m.data));
        events.push(Box::new(groups_joined));

        let events = select_all(events);

        let chat_info = Chat {
            account_pkey,
            account_skey,
            chat_skey,
            chat_pkey,
            owned_groups: Vec::new(),
            owned_channels: Vec::new(),
            subscribed_channels: Vec::new(),
            subscribed_groups: Vec::new(),
            my_utxos: Vec::new(),
            network,
            events,
            state: ChatState::None,
        };
        chat_info
    }

    // NOTE: In their present form, add_owned_group() and add_subscribed_group()
    // can be used for state restore on startup.
    //
    // But if we are newly joining a group then we must send out rekeyings
    // so that others can learn of us, and include us in their future rekeyings.
    //
    // That is the purpose of subscribe_to_group().
    pub fn add_owned_group(&mut self, info: GroupOwnerInfo) -> Result<(), ChatError> {
        if self.is_unique_id(info.group_id.clone()) {
            self.owned_groups.push(info);
            Ok(())
        } else {
            Err(ChatError::DuplicateID)
        }
    }

    pub fn add_owned_channel(&mut self, info: ChannelOwnerInfo) -> Result<(), ChatError> {
        if self.is_unique_id(info.channel_id.clone()) {
            self.owned_channels.push(info);
            Ok(())
        } else {
            Err(ChatError::DuplicateID)
        }
    }

    pub fn add_subscribed_group(&mut self, info: ChatSession) -> Result<(), ChatError> {
        // the ChatSession contains the current member roster and my initial chain code
        // (assigned initially by group owner)
        if self.is_unique_id(info.group_id.clone()) {
            self.subscribed_groups.push(info);
            Ok(())
        } else {
            Err(ChatError::DuplicateID)
        }
    }

    pub fn add_subscribed_channel(&mut self, info: ChannelSession) -> Result<(), ChatError> {
        if self.is_unique_id(info.channel_id.clone()) {
            self.subscribed_channels.push(info);
            Ok(())
        } else {
            Err(ChatError::DuplicateID)
        }
    }

    pub fn remove_owned_group(&mut self, name: String) {
        if let Some(pos) = self.owned_groups.iter().position(|g| name == g.group_id) {
            self.owned_groups.remove(pos);
        }
    }

    pub fn remove_owned_channel(&mut self, name: String) {
        if let Some(pos) = self
            .owned_channels
            .iter()
            .position(|g| name == g.channel_id)
        {
            self.owned_channels.remove(pos);
        }
    }

    pub fn remove_subscribed_group(&mut self, name: String) {
        if let Some(pos) = self
            .subscribed_groups
            .iter()
            .position(|g| name == g.group_id)
        {
            self.subscribed_groups.remove(pos);
        }
    }

    pub fn remove_subscribed_channel(&mut self, name: String) {
        if let Some(pos) = self
            .subscribed_channels
            .iter()
            .position(|g| name == g.channel_id)
        {
            self.subscribed_channels.remove(pos);
        }
    }

    pub fn add_ignored_member(&mut self, group_name: String, member_pkey: PublicKey) {
        if let Some(pos) = self.find_owned_group(group_name.clone()) {
            let grp = &self.owned_groups[pos];
            if grp
                .ignored_members
                .iter()
                .find(|&&p| p == member_pkey)
                .is_none()
            {
                let mut grp = self.owned_groups.remove(pos);
                grp.ignored_members.push(member_pkey);
                self.owned_groups.push(grp);
            }
        } else if let Some(pos) = self.find_subscribed_group(group_name.clone()) {
            let grp = &self.subscribed_groups[pos];
            if grp
                .ignored_members
                .iter()
                .find(|&&p| p == member_pkey)
                .is_none()
            {
                let mut grp = self.subscribed_groups.remove(pos);
                grp.ignored_members.push(member_pkey);
                self.subscribed_groups.push(grp);
            }
        }
    }

    pub fn remove_ignored_member(&mut self, group_name: String, member_pkey: PublicKey) {
        if let Some(pos) = self.find_owned_group(group_name.clone()) {
            let grp = &self.owned_groups[pos];
            if let Some(mempos) = grp.ignored_members.iter().position(|&p| p == member_pkey) {
                let mut grp = self.owned_groups.remove(pos);
                grp.ignored_members.remove(mempos);
                self.owned_groups.push(grp);
            }
        } else if let Some(pos) = self.find_subscribed_group(group_name.clone()) {
            let grp = &self.subscribed_groups[pos];
            if let Some(mempos) = grp.ignored_members.iter().position(|&p| p == member_pkey) {
                let mut grp = self.subscribed_groups.remove(pos);
                grp.ignored_members.remove(mempos);
                self.subscribed_groups.push(grp);
            }
        }
    }

    fn find_owned_channel(&self, name: String) -> Option<usize> {
        self.owned_channels
            .iter()
            .position(|g| name == g.channel_id)
    }

    fn find_owned_group(&self, name: String) -> Option<usize> {
        self.owned_groups.iter().position(|g| name == g.group_id)
    }

    fn find_subscribed_group(&self, name: String) -> Option<usize> {
        self.subscribed_groups
            .iter()
            .position(|g| name == g.group_id)
    }

    fn find_subscribed_channel(&self, name: String) -> Option<usize> {
        self.subscribed_channels
            .iter()
            .position(|g| name == g.channel_id)
    }

    fn is_unique_id(&self, name: String) -> bool {
        !(self.find_owned_channel(name.clone()).is_some()
            || self.find_owned_group(name.clone()).is_some()
            || self.find_subscribed_channel(name.clone()).is_some()
            || self.find_subscribed_group(name).is_some())
    }

    pub fn new_message(
        &mut self,
        group_name: String,
        message: Vec<u8>,
    ) -> Result<ChatMessageOutput, ChatError> {
        if let Some(pos) = self.find_owned_channel(group_name.clone()) {
            let chan = &self.owned_channels[pos];
            Ok(chan.new_message(message))
        } else if let Some(pos) = self.find_owned_group(group_name.clone()) {
            let grp = &self.owned_groups[pos];
            Ok(grp.new_message(message))
        } else if let Some(pos) = self.find_subscribed_group(group_name.clone()) {
            let grp = &self.subscribed_groups[pos];
            Ok(grp.new_message(message))
        } else {
            Err(ChatError::InvalidGroup(group_name))
        }
    }

    // ----------------------------------------------------------------
    // Here and below are actions spurred by incoming network traffic

    fn notify_wallet_of_new_incomning_message(&self, sender: PublicKey, msg: Vec<u8>) {
        // GUI Alert
        unimplemented!();
    }

    fn notify_wallet_to_send_transaction(&self, msgs: Vec<ChatMessageOutput>) {
        // called when an eviction notice causes us to produce one or
        // more rekeying messages for others in the group

        // GUI Alert
        unimplemented!();
    }

    fn process_owned_group_message(
        &mut self,
        info: &mut GroupOwnerInfo,
        msg: &ChatMessageOutput,
        owner_chain: &Hash,
    ) {
        // Here is where incoming messages for Groups are being decrypted and handed
        // back with the public key of the sender. Rekeying messages are handled
        // internally here, and a result of None is produced for their final output.
        //
        // A Group Owner is no different from any other group members as far as
        // receiving incoming group messages.
        self.state = ChatState::HandlingOwnedChatGroup;
        match info.get_message(self, msg, owner_chain) {
            ChatMessage::None => {}
            ChatMessage::Rekeying(_rekeying_msgs) => {
                // This should not happen if I own the group...
                unreachable!();
            }
            ChatMessage::Text((sender, txt)) => {
                // Filter for senders that I want to ignore
                // archive and/or display the message for those that I want
                if sender != info.owner_pkey
                    && None == info.ignored_members.iter().find(|&&p| p == sender)
                {
                    info.messages.push((sender, txt.clone()));
                    self.notify_wallet_of_new_incomning_message(sender, txt);
                }
            }
        }
    }

    fn process_subscribed_group_message(
        &mut self,
        info: &mut ChatSession,
        msg: &ChatMessageOutput,
        owner_chain: &Hash,
    ) {
        // Here is where incoming messages for Groups are being decrypted and handed
        // back with the public key of the sender. Rekeying messages are handled
        // internally here, and a result of None is produced for their final output.
        self.state = ChatState::HandlingSubscribedChatGroup;
        match info.get_message(self, msg, owner_chain) {
            ChatMessage::None => {}
            ChatMessage::Rekeying(rekeying_msgs) => {
                // This should not happen if I own the group...
                self.notify_wallet_to_send_transaction(rekeying_msgs);
            }
            ChatMessage::Text((sender, txt)) => {
                // Filter for senders that I want to ignore
                // archive and/or display the message for those that I want
                if None == info.ignored_members.iter().find(|&&p| p == sender) {
                    info.messages.push((sender, txt.clone()));
                    self.notify_wallet_of_new_incomning_message(sender, txt);
                }
            }
        }
    }

    fn process_subscribed_channel_message(
        &mut self,
        info: &mut ChannelSession,
        msg: &ChatMessageOutput,
    ) {
        // Here is where incoming messages for Channels are being
        // decrypted and handed back.
        self.state = ChatState::HandlingSubscribedChannel;
        match info.get_message(self, msg) {
            ChatMessage::None => {}
            ChatMessage::Rekeying(_vec) => {
                // should never get any rekeying or member evictions on Channels
                unreachable!();
            }
            ChatMessage::Text((sender, txt)) => {
                // Filter for senders that I want to ignore
                // archive and/or display the message for those that I want
                info.messages.push((sender, txt.clone()));
                self.notify_wallet_of_new_incomning_message(sender, txt);
            }
        }
    }

    fn process_owned_channel_messages(
        &mut self,
        info: &ChannelOwnerInfo,
        utxo: &ChatMessageOutput,
    ) {
        self.state = ChatState::HandlingOwnedChannel;
        match info.get_message(self, utxo) {
            // side effect of get_message is to record utxo as one of
            // my spendable Chat UTXO
            ChatMessage::None => {}
            ChatMessage::Rekeying(_) => unreachable!(),
            ChatMessage::Text(_) => unreachable!(),
        }
    }

    fn on_message_received(&mut self, msg: &ChatMessageOutput) {
        let owner_pt = Pt::from(msg.recipient);
        let owner_hint = msg.recipient_keying_hint;
        let mut owner_chain = Hash::zero();
        // Look for messages from owned groups.
        // Rekeying messages will arrive on rekeying chain code.
        if let Some(pos) = self.owned_groups.iter().position(|g| {
            owner_chain = g.get_owner_chain(msg);
            owner_pt == Fr::from(owner_chain) * owner_hint
        }) {
            let mut info = self.owned_groups.remove(pos);
            self.process_owned_group_message(&mut info, msg, &owner_chain);
            self.owned_groups.push(info);

        // Look for incoming messages on subscribed groups.
        // Rekeying messages will arrive on rekeying chain code.
        } else if let Some(pos) = self.subscribed_groups.iter().position(|g| {
            owner_chain = g.get_owner_chain(msg);
            owner_pt == Fr::from(owner_chain) * owner_hint
        }) {
            let mut info = self.subscribed_groups.remove(pos);
            self.process_subscribed_group_message(&mut info, msg, &owner_chain);
            self.subscribed_groups.push(info);

        // look for incoming messages on subscribed channels
        } else if let Some(pos) = self
            .subscribed_channels
            .iter()
            .position(|g| owner_pt == Fr::from(g.owner_chain) * owner_hint)
        {
            let mut info = self.subscribed_channels.remove(pos);
            self.process_subscribed_channel_message(&mut info, msg);
            self.subscribed_channels.push(info);

        // look for incoming messages on owned channels
        // (can only come from owner, sent to owner)
        } else if let Some(pos) = self
            .owned_channels
            .iter()
            .position(|g| owner_pt == Fr::from(g.owner_chain) * owner_hint)
        {
            // getting back one of my own channel messages
            // record it as a spendable UTXO
            let info = self.owned_channels.remove(pos);
            self.process_owned_channel_messages(&info, msg);
            self.owned_channels.push(info);
        }
    }
}

impl Future for Chat {
    type Item = Option<ChatMessageOutput>;
    type Error = ChatError;

    /// Event loop.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    ChatEvent::MessageReceived(msg) => {
                        let msg = match ChatMessageOutput::from_buffer(&msg) {
                            Ok(msg) => msg,
                            Err(e) => {
                                serror!(self, "Ignore invalid message: {}", e);
                                continue;
                            }
                        };
                        self.on_message_received(&msg);
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(None)), // Shutdown.
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

// -------------------------------------------------------------------
/*
Pseudo code for wallet interactions:

Session Start:
--------------
Call chat::new() with keying information, initial groups/channels owned
by wallet, groups subscribed to, channels subscribed to.

Create a Group:
---------------
call chat::add_owned_group() GroupOwnerInfo to describe the new group.

Send out invitations to prospective group members. Invitation tells prospective
member what group owner pkey and chain code to use. Invitation sent to members chosen
chat pkey. These are private messages sent by way of PaymentUTXO with encrypted message
in their payload.

Create a Channel:
-----------------
call chat::add_owned_channel() with ChannelOwnerInfo to describe new channel.

No need to deal with membership lists. This is an encrypted broadcast channel
for the owner, for him to post messages whenever he feels like it.

Add an Ignore of Member to Chat Group:
--------------------------------------
Call add_ignored_member() with member pkey, identifying the group with its
identity string.

Remove a member from ignored list:
----------------------------------
Call remove_ignored_member() with member pkey, identifying the group with its
identity string.

Subscribe to a Group:
---------------------
Call add_subscribed_group() with ChatSession struct describing the group and the
user's keying.

Keying need not be the same as indicated when new Chat struct was formed.
Every group can use different keying if desired. Whatever keying is chosen,
the wallet needs to watch for private messages = Payment UTXO in that keying.

Subscribe to a Channel:
-----------------------
call add_subscribed_channel () with ChannelSession struct filled in with
identifying information.

Send a Message to a Group/Channel:
-------------------------
call new_messge() with group identification string, and plaintext of message -
receive back a ChatMsgOutput UTXO. Only Channel Owner can send messages to channels.

*/
