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
use failure::{bail, Error};
use rand::Rng;
use stegos_blockchain::{
    detrand, new_chain_code, ChatError, ChatMessageOutput, IncomingChatPayload,
    MessagePayload, PaymentOutput, Timestamp,
    PTS_PER_CHAIN_LIST,
};
use stegos_crypto::hash::{Hash, Hashable, Hasher};

use derivative::Derivative;
use stegos_crypto::scc::{Fr, Pt, PublicKey, SchnorrSig, SecretKey};

use super::AccountDatabase;
use log::{log, debug, Level};
use serde::{Deserialize, Serialize};
// ----------------------------------------------------------------------------------

/*

macro_rules! sdebug {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Debug, concat!("[{}] ({}) ", $fmt), $self.chat_pkey, $self.state.name(), $($arg),*);
    );
}
macro_rules! sinfo {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Info, concat!("[{}] ({}) ", $fmt), $self.chat_pkey, $self.state.name(), $($arg),*);
    );
}
*/

macro_rules! strace {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Trace, concat!("[{}] ({}) ", $fmt), $self.chat_pkey, $self.state.name(), $($arg),*);
    );
}

macro_rules! swarn {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Warn, concat!("[{}] ({}) ", $fmt), $self.chat_pkey, $self.state.name(), $($arg),*);
    );
}

macro_rules! serror {
    ($self:expr, $fmt:expr $(,$arg:expr)*) => (
        log!(Level::Error, concat!("[{}] ({}) ", $fmt), $self.chat_pkey, $self.state.name(), $($arg),*);
    );
}

mod channel;
mod group;
mod private_message;
mod storage;
pub use storage::*;
pub use channel::*;
pub use group::*;
pub use private_message::*;
// --------------------------------------------------------------------------------------

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub pkey: PublicKey,
    pub chain: Fr,
    pub epoch: Timestamp,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct MemberRoster(Vec<GroupMember>);

impl From<Vec<GroupMember>> for MemberRoster {
    fn from(d: Vec<GroupMember>) -> MemberRoster {
        MemberRoster(d)
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
// #[serde(tag = "chat_type", content="chat_id")]
pub enum ChatId {
    ChannelId(String),
    GroupId(String),
    // PrivateMessage(PublicKey)
}

#[derive(Clone, Debug)]
pub enum ChatItem {
    Rekeying(Vec<ChatMessageOutput>),
    Text {
        chat_id: ChatId,
        sender: PublicKey,
        msg: String,
    },
}

type ChatMessage = Option<ChatItem>;

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
        owner_chain: &Fr,
        sender_skey: &SecretKey,
        sender_pkey: &PublicKey,
        sender_chain: &Fr,
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
            owner_chain: &Fr,
            sender_skey: &SecretKey,
            sender_pkey: &PublicKey,
            sender_chain: &Fr,
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

    pub fn find_member(&self, pkey: &PublicKey) -> Option<&GroupMember> {
        self.0.iter().find(|mem| *pkey == mem.pkey)
    }

    pub fn find_sender_chain(&self, utxo: &ChatMessageOutput) -> Option<&GroupMember> {
        // for use on general group messages
        self.0
            .iter()
            .find(|mem| utxo.sender == utxo.sender_keying_hint * mem.chain)
    }

    pub fn decrypt_chat_message(
        &self,
        owner_pkey: &PublicKey,
        owner_chain: &Fr,
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
        owner_chain: &Fr,
        utxo: &ChatMessageOutput,
        pts: &Vec<Pt>,
    ) -> Option<(PublicKey, Fr, Timestamp)> {
        // utxo is expected to carry cloaked chain codes
        let sf = Fr::one() / Fr::from(*skey);
        let sfk = utxo.sender_cloaking_hint / *owner_chain;
        let mut ans = None;
        pts.iter().find(|&&pt| {
            let cg = sf * pt;
            let chain = Fr::from(Hash::digest(&cg).rshift(4));
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
        owner_chain: &Fr,
        utxo: &ChatMessageOutput,
        pts: &Vec<Pt>,
    ) -> Option<(PublicKey, Fr)> {
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
        owner_chain: &Fr,
        my_pkey: &PublicKey,
        my_chain: &Fr,
        utxo: &ChatMessageOutput,
    ) -> bool {
        utxo.sender == utxo.sender_cloaking_hint * *my_chain / *owner_chain * Pt::from(*my_pkey)
    }

    pub fn get_decrypted_message(
        &mut self,
        owner_pkey: &PublicKey,
        owner_chain: &Fr,
        my_skey: &SecretKey,
        my_pkey: &PublicKey,
        my_chain: &Fr,
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

    pub fn add_members_to_roster(&mut self, vec: &Vec<(PublicKey, Fr)>, epoch: Timestamp) {
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

#[derive(Clone)]
pub enum NewMemberMessage {
    GroupMessage(ChatMessageOutput),
    PrivateMessage((PaymentOutput, Fr, Fr)),
}

#[derive(Clone)]
pub struct NewMemberInfo {
    // Owner PubKey identifies which group
    pub owner_pkey: PublicKey,
    // current keying
    pub owner_chain: Fr,
    // emergency rekeying chain
    pub rekeying_chain: Fr,
    // my initial chain code
    pub my_initial_chain: Fr,
    // total number of members, including self,
    pub num_members: u32,
    // members [0..10) (Pubkey, Chain)
    pub members: Vec<(PublicKey, Fr)>,
    // owner signature on this payload info
    pub signature: SchnorrSig,
}

#[derive(Clone)]
pub struct NewMemberInfoCont {
    pub owner_pkey: PublicKey,
    pub num_members: u32,
    pub member_index: u32,
    // up to 12 more members (Pubkey, chain)
    pub members: Vec<(PublicKey, Fr)>,
    // owner signature on this payload info
    pub signature: SchnorrSig,
}

impl Hashable for NewMemberInfo {
    fn hash(&self, hasher: &mut Hasher) {
        self.owner_pkey.hash(hasher);
        self.owner_chain.hash(hasher);
        self.rekeying_chain.hash(hasher);
        self.my_initial_chain.hash(hasher);
        self.num_members.hash(hasher);
        for (pkey, chain) in self.members.iter() {
            pkey.hash(hasher);
            chain.hash(hasher);
        }
    }
}

impl Hashable for NewMemberInfoCont {
    fn hash(&self, hasher: &mut Hasher) {
        self.owner_pkey.hash(hasher);
        self.num_members.hash(hasher);
        self.member_index.hash(hasher);
        for (pkey, chain) in self.members.iter() {
            pkey.hash(hasher);
            chain.hash(hasher);
        }
    }
}


#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub id: Hash,
    pub created: Timestamp,
    pub keying: Fr,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Chat {
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
    subscribed_groups: Vec<GroupSession>,

    // Collection of UTXOs that belong to me
    my_utxos: Vec<UtxoInfo>,

    /// State while processing
    state: ChatState,
}

impl Chat {
    // GUI Alert - somebody needs to call this to set things up
    // We probably need functions here to save/restore state info to
    // startup database.
    pub fn new(chat_skey: SecretKey, chat_pkey: PublicKey) -> Chat {
        let chat_info = Chat {
            chat_skey,
            chat_pkey,
            owned_groups: Vec::new(),
            owned_channels: Vec::new(),
            subscribed_channels: Vec::new(),
            subscribed_groups: Vec::new(),
            my_utxos: Vec::new(),
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

    pub fn add_subscribed_group(&mut self, info: GroupSession) -> Result<(), ChatError> {
        // the GroupSession contains the current member roster and my initial chain code
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

    // ----------------------------------------------------------------
    // Here and below are actions spurred by incoming network traffic

    fn process_owned_group_message(
        &mut self,
        info: &mut GroupOwnerInfo,
        utxo: &ChatMessageOutput,
        owner_chain: &Fr,
    ) -> ChatMessage {
        // Here is where incoming messages for Groups are being decrypted and handed
        // back with the public key of the sender. Rekeying messages are handled
        // internally here, and a result of None is produced for their final output.
        //
        // A Group Owner is no different from any other group members as far as
        // receiving incoming group messages.
        self.state = ChatState::HandlingOwnedChatGroup;
        let (sender, msg) = info.decrypt_message(utxo, owner_chain)?;

        // All chat messages belong to me...
        info.record_utxo(self, utxo, owner_chain, sender);
        if sender == info.owner_pkey {
            // was my own message
            return None
        };

        let mut txt = match msg {
            IncomingChatPayload::PlainText(m) => m,

            // should never happend since only I can produce them
            IncomingChatPayload::Evictions(_) |

            // rekeying was already handled by side effect of get_decrypted_message
            IncomingChatPayload::Rekeying(_) |
             
            // only I ever send these messages, when legitimate.
            // if someone else sent one of these, just ignore it.
            IncomingChatPayload::NewMembers(_) 
            => {
                return None
            }
        };

        // Filter for senders that I want to ignore
        // archive and/or display the message for those that I want
        if sender == info.owner_pkey
            || info.ignored_members.iter().find(|&&p| p == sender).is_some()
        {
            return None
        }

        let txt_len = txt.iter().enumerate().find(|(_,v)| **v == 0).map(|(k,_)|k).unwrap_or(txt.len());
        txt.truncate(txt_len);
        let msg = match String::from_utf8(txt) {
            Ok(m) => m,
            Err(e) => {
                serror!(self, "Incorrect utf string {}", e);
                return None;
            }
        };
        return ChatItem::Text {
            chat_id: ChatId::GroupId(info.group_id.clone()),
            sender,
            msg,
        }
        .into();
        
    }

    fn process_subscribed_group_message(
        &mut self,
        info: &mut GroupSession,
        utxo: &ChatMessageOutput,
        owner_chain: &Fr,
    ) -> ChatMessage {
        // Here is where incoming messages for Groups are being decrypted and handed
        // back with the public key of the sender. Rekeying messages are handled
        // internally here, and a result of None is produced for their final output.
        self.state = ChatState::HandlingSubscribedChatGroup;


        let (sender, msg) = info.decrypt_message(utxo, owner_chain)?;
        if sender == info.my_pkey {
            // ignore my own messages
            return None
        }

        let mut txt = match msg {
            // Handle new message on outer level.
            IncomingChatPayload::PlainText(m) => m,

            // Form and send a transaction with rekeying messages
            IncomingChatPayload::Evictions(evicted_members) if sender == info.owner_pkey => {
                let rekeying_msgs = info.evict_members(&evicted_members);
                return ChatItem::Rekeying(rekeying_msgs).into()
            }
            // Add member to group list.
            IncomingChatPayload::NewMembers(vec) if sender == info.owner_pkey  => {
                info.members.add_members_to_roster(&vec, utxo.created);
                return None;
            }

            // NewMembers and Eviction from other is mean that someone is trying to spoof us - just ignore them
            IncomingChatPayload::NewMembers(_) | 
            IncomingChatPayload::Evictions(_) |
            // Already handled
            IncomingChatPayload::Rekeying(_) => {
                return None;
            }
        };

        // Filter for senders that I want to ignore
        // archive and/or display the message for those that I want
        if sender == info.my_pkey || info.ignored_members.iter().find(|&&p| p == sender).is_some() {
            return None;
        }

        let txt_len = txt.iter().enumerate().find(|(_,v)| **v == 0).map(|(k,_)|k).unwrap_or(txt.len());
        txt.truncate(txt_len);

        let msg = match String::from_utf8(txt) {
            Ok(m) => m,
            Err(e) => {
                serror!(self, "Incorrect utf string {}", e);
                return None;
            }
        };
        return ChatItem::Text {
            chat_id: ChatId::GroupId(info.group_id.clone()),
            sender,
            msg,
        }.into();
    
    }

    fn process_subscribed_channel_message(
        &mut self,
        info: &mut ChannelSession,
        utxo: &ChatMessageOutput,
    ) -> ChatMessage {
        // Here is where incoming messages for Channels are being
        // decrypted and handed back.
        self.state = ChatState::HandlingSubscribedChannel;
        let ctx = match &utxo.payload {
            MessagePayload::EncryptedChainCodes(_) => {
                // ignore these - they shouldn't exist in Channels
                return None;
            }
            MessagePayload::EncryptedMessage(m) => m
        };
        let mut txt = info.decrypt_channel_message(utxo, ctx)?;
        let sender = info.owner_pkey;
        // Filter for senders that I want to ignore
        // archive and/or display the message for those that I want
        let txt_len = txt.iter().enumerate().find(|(_,v)| **v == 0).map(|(k,_)|k).unwrap_or(txt.len());
        txt.truncate(txt_len);
        let msg = match String::from_utf8(txt) {
            Ok(m) => m,
            Err(e) => {
                serror!(self, "Incorrect utf string {}", e);
                return None;
            }
        };
        let item = ChatItem::Text {
            chat_id: ChatId::ChannelId(info.channel_id.clone()),
            sender,
            msg,
        };

        item.into()
    }

    fn process_owned_channel_messages(
        &mut self,
        info: &ChannelOwnerInfo,
        utxo: &ChatMessageOutput,
    ) -> ChatMessage {
        self.state = ChatState::HandlingOwnedChannel;

        if utxo.sender_cloaking_hint * Pt::from(info.owner_pkey) == utxo.sender {
            info.record_utxo(self, utxo);
        } else {
            swarn!(
                self,
                "Channel Owner received Channel message from non-owner"
            );
        }
        None
    }

    // Returns Ok, if message was for us.
    // Return Err, if error was not for us.
    #[must_use]
    fn on_message_received(&mut self, msg: &ChatMessageOutput) -> ChatMessage {
        let owner_pt = Pt::from(msg.recipient);
        let owner_hint = msg.recipient_keying_hint;
        let mut owner_chain = Fr::zero();
        // Look for messages from owned groups.
        // Rekeying messages will arrive on rekeying chain code.
        if let Some(pos) = self.owned_groups.iter().position(|g| {
            owner_chain = g.get_owner_chain(msg);
            owner_pt == owner_chain * owner_hint
        }) {
            let mut info = self.owned_groups.remove(pos);
            let event = self.process_owned_group_message(&mut info, msg, &owner_chain);
            self.owned_groups.push(info);
            return event;

        // Look for incoming messages on subscribed groups.
        // Rekeying messages will arrive on rekeying chain code.
        } else if let Some(pos) = self.subscribed_groups.iter().position(|g| {
            owner_chain = g.get_owner_chain(msg);
            owner_pt == owner_chain * owner_hint
        }) {
            let mut info = self.subscribed_groups.remove(pos);
            let event = self.process_subscribed_group_message(&mut info, msg, &owner_chain);
            self.subscribed_groups.push(info);
            return event;

        // look for incoming messages on subscribed channels
        } else if let Some(pos) = self
            .subscribed_channels
            .iter()
            .position(|g| owner_pt == g.owner_chain * owner_hint)
        {
            let mut info = self.subscribed_channels.remove(pos);
            let event = self.process_subscribed_channel_message(&mut info, msg);
            self.subscribed_channels.push(info);
            return event;

        // look for incoming messages on owned channels
        // (can only come from owner, sent to owner)
        } else if let Some(pos) = self
            .owned_channels
            .iter()
            .position(|g| owner_pt == g.owner_chain * owner_hint)
        {
            // getting back one of my own channel messages
            // record it as a spendable UTXO
            let info = self.owned_channels.remove(pos);
            let event = self.process_owned_channel_messages(&info, msg);
            self.owned_channels.push(info);
            return event;
        }
        return None;
    }

    // ===========================
    // High level API start there.
    // ===========================

    pub fn process_incomming(&mut self, db: &mut AccountDatabase, utxo: ChatMessageOutput) {
        let i = self.on_message_received(&utxo);
        if let Some(ChatItem::Text {
                chat_id,
                sender,
                msg,
            }) = i {
            let output = ChatOutputValue {
                sender,
                text: msg,
                utxo
            };

            strace!(self, "Found message that belong to us. ={:?}", output);
            db.push_chat_history(chat_id, output).unwrap();
        }
    }

    /// Create channel, and return invition ID.
    pub fn create_channel(
        &mut self,
        db: &mut AccountDatabase,
        channel_id: String,
    ) -> Result<ChannelInvite, Error> {
        let unique_id = Hash::digest_chain(&[&self.chat_skey, &channel_id]);
        let owner_pkey = self.chat_pkey.clone();
        let owner_skey = self.chat_skey.clone();
        // Create owner_chain.
        let initial_owner_chain = Fr::from(unique_id);
        // Use random-based chain creation.
        // And forget about secret part of owner_chain, because we didn't need to rekey it later.
        let (_owner_c, owner_chain) = new_chain_code(&owner_pkey, &initial_owner_chain);

        let channel_info = ChannelOwnerInfo {
            channel_id,
            owner_pkey,
            owner_skey,
            owner_chain: owner_chain.clone(),
        };

        self.add_owned_channel(channel_info.clone())?;
        let invite = ChannelInvite {
            owner_chain,
            owner_pkey,
        };
        db.push_chat_session(channel_info.into())?;
        return Ok(invite);
    }

    /// Join newly created channel.
    pub fn join_channel(
        &mut self,
        db: &mut AccountDatabase,
        channel_id: String,
        invite_id: ChannelInvite,
    ) -> Result<(), Error> {
        let session = ChannelSession {
            channel_id: channel_id.clone(),
            owner_pkey: invite_id.owner_pkey,
            owner_chain: invite_id.owner_chain,
        };

        self.add_subscribed_channel(session.clone())?;

        db.push_chat_session(session.into())?;
        Ok(())
    }

    /// Create new message
    pub fn new_message(
        &self,
        db: &mut AccountDatabase,
        chat_id: ChatId,
        message: Vec<u8>,
    ) -> Result<ChatMessageOutput, Error> {
        // Try process new message, return error if no group found.
        match chat_id.clone() {
            ChatId::ChannelId(name) => {
                if let Some(pos) = self.find_owned_channel(name) {
                    let chan = &self.owned_channels[pos];
                    return Ok(chan.new_message(message));
                }
            }
            ChatId::GroupId(name) => {
                if let Some(pos) = self.find_owned_group(name.clone()) {
                    let grp = &self.owned_groups[pos];
                    return Ok(grp.new_message(message));
                } else if let Some(pos) = self.find_subscribed_group(name) {
                    let grp = &self.subscribed_groups[pos];
                    return Ok(grp.new_message(message));
                }
            }
        }

        bail!("Invalid chat id = {:?}", chat_id)
    }

    // pub fn join_group()
    // pub fn create_group()
    // pub fn add_member() 
    // pub fn remove_member()

    pub fn recover_chats(&mut self, 
        db: &AccountDatabase) {
        for (chat_id, chat_session) in db.chats.iter().map(|(k,v)| (k.clone(), v.clone())) {
            debug!("Recovered chat = {:?}", chat_id);
            match chat_id {
                ChatId::ChannelId(channel_id) => {
                    assert!(chat_session.group_info.is_none());
                    
                    if chat_session.owner_pkey == self.chat_pkey { // owner of channel
                        debug!("Recovered owned chat");
                        self.add_owned_channel(ChannelOwnerInfo {
                            channel_id,
                            owner_pkey: chat_session.owner_pkey,
                            owner_skey: self.chat_skey.clone(),
                            owner_chain: chat_session.owner_chain,
                        }).expect("No duplicate owned channels")
                    } else {
                        debug!("Recovered subscribed chat");
                        self.add_subscribed_channel(ChannelSession {
                            channel_id,
                            owner_pkey: chat_session.owner_pkey,
                            owner_chain: chat_session.owner_chain,
                        }).expect("No duplicate subscribed channels")
                    }
                },
                ChatId::GroupId(group_id) => {
                    let group_info = chat_session.group_info.expect("Group session should exist");
                    
                    if chat_session.owner_pkey == self.chat_pkey { // owner of group
                        debug!("Recovered owned group");
                        self.add_owned_group(GroupOwnerInfo {
                            group_id,
                            owner_pkey: chat_session.owner_pkey,
                            owner_skey: self.chat_skey.clone(),
                            owner_chain: chat_session.owner_chain,
                            owner_rekeying_chain: group_info.owner_rekeying_chain,
                            members: group_info.members,
                            ignored_members: group_info.ignored_members,
                        }).expect("No duplicate owned channels")
                    } else {
                        debug!("Recovered subscribed group");
                        self.add_subscribed_group(GroupSession {
                            group_id,
                            owner_pkey: chat_session.owner_pkey,
                            owner_chain: chat_session.owner_chain,
                            owner_rekeying_chain: group_info.owner_rekeying_chain,
                            my_pkey: self.chat_pkey,
                            my_skey: self.chat_skey.clone(),
                            my_chain: group_info.my_chain.expect("Chain should exist for subscribed member."),
                            members: group_info.members,
                            ignored_members: group_info.ignored_members,
                        }).expect("No duplicate subscribed channels")
                    }

                }
            }    
        
        }
    }

    // pub fn mark_output(&mut self, ) |Mempool(broadcasted)
    //                                 |Microblock(prepare)
    //                                 |Macroblock(final)
    //                                 |Conflicted(other was received)
}

// -------------------------------------------------------------------
#[cfg(test)]
mod test {
    use super::*;

    // Session Start:
    // --------------
    // Call chat::new() with keying information, initial groups/channels owned
    // by wallet, groups subscribed to, channels subscribed to.

    #[test]
    fn start_session() {
        stegos_node::test::futures_testing::start_test(|timer| {
            let (loopback, network, _, _) = stegos_network::loopback::Loopback::new();
            let (chat_skey, chat_pkey) = stegos_crypto::scc::make_random_keys();

            let session = Chat::new(chat_skey, chat_pkey);
            // TODO: add asserts.
        });
    }

    // Create a Group:
    // ---------------
    // call chat::add_owned_group() GroupOwnerInfo to describe the new group.

    // Send out invitations to prospective group members. Invitation tells prospective
    // member what group owner pkey and chain code to use. Invitation sent to members chosen
    // chat pkey. These are private messages sent by way of PaymentUTXO with encrypted message
    // in their payload.

    // Subscribe to a Group:
    // ---------------------
    // Call add_subscribed_group() with GroupSession struct describing the group and the
    // user's keying.

    // Keying need not be the same as indicated when new Chat struct was formed.
    // Every group can use different keying if desired. Whatever keying is chosen,
    // the wallet needs to watch for private messages = Payment UTXO in that keying.

    // #[test]
    // fn group() {
    //     stegos_node::test::futures_testing::start_test(|timer| {
    //         const N: usize = 3;
    //         let group_id: String = String::from("GROUP_ID");
    //         let epoch = Timestamp::now();

    //         let (loopback, network, _, _) = stegos_network::loopback::Loopback::new();

    //         let (owner_skey, owner_pkey) = stegos_crypto::scc::make_random_keys();
    //         let initial_owner_chain = Fr::from(Hash::digest(&owner_pkey));
    //         let (_owner_c, owner_chain) = new_chain_code(&owner_pkey, &initial_owner_chain);
    //         let (_owner_c, rekeying_chain) = new_chain_code(&owner_pkey, &owner_chain);

    //         let members: Vec<_> = (0..N)
    //             .map(|_| stegos_crypto::scc::make_random_keys())
    //             .collect();

    //         let mut session = Chat::new(owner_skey, owner_pkey);

    //         // invite all members except first
    //         // let group_members: Vec<_> = members
    //         //     .iter()
    //         //     .skip(1)
    //         //     .map(|(_, pkey)| GroupMember {
    //         //         pkey: *pkey,
    //         //         chain: owner_chain.clone(),
    //         //         epoch,
    //         //     })
    //         //     .collect();

    //         let group = GroupOwnerInfo {
    //             group_id: group_id.clone(),
    //             owner_pkey,
    //             owner_skey,
    //             owner_chain: owner_chain.clone(), // TODO: Chain code replace
    //             owner_rekeying_chain: rekeying_chain.clone(),
    //             members: vec![].into(),
    //             ignored_members: vec![],
    //         };
    //         session.add_owned_group(group).unwrap();

    //         // Subscribe from member side on group updates.
    //         let mut members_sessions: Vec<_> = members
    //             .into_iter()
    //             .map(|(my_skey, my_pkey)| {
    //                 let (_, my_chain) = new_chain_code(&my_pkey, &owner_chain);
    //                 let session = GroupSession {
    //                     group_id: group_id.clone(),
    //                     owner_pkey,
    //                     owner_chain: owner_chain.clone(),
    //                     owner_rekeying_chain: rekeying_chain.clone(),
    //                     my_pkey,
    //                     my_skey,
    //                     my_chain,
    //                     members: vec![].into(),
    //                     ignored_members: vec![],
    //                 };
    //                 let mut chat = Chat::new(my_skey, my_pkey);
    //                 chat.add_subscribed_group(session).unwrap();
    //                 chat
    //             })
    //             .collect();
    //         let output = session
    //             .new_message(group_id.clone(), vec![0u8, 1, 2, 3])
    //             .unwrap();

    //         let mut member_outputs: Vec<_> = members_sessions
    //             .iter()
    //             .map(|chat| {
    //                 chat.new_message(group_id.clone(), vec![0u8, 1, 2, 3])
    //                     .unwrap()
    //             })
    //             .collect();

    //         // User that not belong to group, should failed to process messages.
    //         let members = members_sessions.iter_mut();
    //         // let first = members.next().unwrap();
    //         // println!("{:?}", first.on_message_received(&output).unwrap());
    //         // assert!(first.on_message_received(&output).unwrap().is_none());
    //         for member_chat in members {
    //             let result = member_chat.on_message_received(&output).unwrap();
    //             println!("{:?}", result);
    //             // TODO: assert message valid.
    //         }

    //         let member_outputs = member_outputs.iter_mut();

    //         // // invalid outputs should not be processed.
    //         // let invalid = member_outputs.next().unwrap();
    //         // assert!(session.on_message_received(&invalid).unwrap().is_none());

    //         for member_output in member_outputs {
    //             let result = session.on_message_received(&member_output).unwrap();
    //             println!("{:?}", result);
    //             // TODO: assert message valid.
    //         }
    //         //TODO Assert sender, receiver.
    //     });
    //     panic!();
    // }

    // // Create a Channel:
    // // -----------------
    // // call chat::add_owned_channel() with ChannelOwnerInfo to describe new channel.

    // // No need to deal with membership lists. This is an encrypted broadcast channel
    // // for the owner, for him to post messages whenever he feels like it.

    // // Subscribe to a Channel:
    // // -----------------------
    // // call add_subscribed_channel () with ChannelSession struct filled in with
    // // identifying information.

    // #[test]
    // fn channel() {
    //     stegos_node::test::futures_testing::start_test(|timer| {
    //         const N: usize = 3;
    //         let channel_id: String = String::from("CHANNEL_ID");
    //         let epoch = Timestamp::now();

    //         let (loopback, network, _, _) = stegos_network::loopback::Loopback::new();
    //         let (my_skey, my_pkey) = stegos_crypto::scc::make_random_keys();
    //         let (owner_skey, owner_pkey) = stegos_crypto::scc::make_random_keys();
    //         let (chat_skey, chat_pkey) = stegos_crypto::scc::make_random_keys();

    //         let initial_owner_chain = Fr::from(Hash::digest(&owner_pkey));
    //         let (_owner_c, owner_chain) = new_chain_code(&owner_pkey, &initial_owner_chain);
    //         let (_owner_c, rekeying_chain) = new_chain_code(&owner_pkey, &owner_chain);

    //         let members: Vec<_> = (0..N)
    //             .map(|_| stegos_crypto::scc::make_random_keys())
    //             .collect();

    //         let mut session = Chat::new(chat_skey, chat_pkey);

    //         let channel = ChannelOwnerInfo {
    //             channel_id: channel_id.clone(),
    //             owner_pkey,
    //             owner_skey,
    //             owner_chain: owner_chain.clone(), // TODO: Chain code replace
    //         };
    //         session.add_owned_channel(channel).unwrap();

    //         let mut members_sessions: Vec<_> = members
    //             .into_iter()
    //             .map(|(my_skey, my_pkey)| {
    //                 let (_, my_chain) = new_chain_code(&my_pkey, &owner_chain);
    //                 let session = ChannelSession {
    //                     channel_id: channel_id.clone(),
    //                     owner_pkey,
    //                     owner_chain: owner_chain.clone(),
    //                     messages: vec![],
    //                 };
    //                 let mut chat = Chat::new(my_skey, my_pkey);
    //                 chat.add_subscribed_channel(session).unwrap();
    //                 chat
    //             })
    //             .collect();
    //         let output = session
    //             .new_message(channel_id.clone(), vec![0u8, 1, 2, 3])
    //             .unwrap();

    //         // User that not belong to group, should failed to process messages.
    //         let members = members_sessions.iter_mut();
    //         // let first = members.next().unwrap();
    //         // println!("{:?}", first.on_message_received(&output).unwrap());
    //         // assert!(first.on_message_received(&output).unwrap().is_none());
    //         for member_chat in members {
    //             let result = member_chat.on_message_received(&output).unwrap().unwrap();
    //             let result = if let ChatItem::Text {
    //                 raw_msg: result, ..
    //             } = result
    //             {
    //                 result
    //             } else {
    //                 unreachable!()
    //             };
    //             assert_eq!(&result[0..4], &[0u8, 1, 2, 3]);
    //             // TODO: assert message valid.
    //         }
    //     });
    // }

    // Add an Ignore of Member to Chat Group:
    // --------------------------------------
    // Call add_ignored_member() with member pkey, identifying the group with its
    // identity string.

    // Remove a member from ignored list:
    // ----------------------------------
    // Call remove_ignored_member() with member pkey, identifying the group with its
    // identity string.

    // Send a Message to a Group/Channel:
    // -------------------------
    // call new_message() with group identification string, and plaintext of message -
    // receive back a ChatMsgOutput UTXO. Only Channel Owner can send messages to channels.
}
