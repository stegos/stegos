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
use rand::Rng;
use stegos_blockchain::{
    detrand, make_chat_message, new_chain_code, ChatMessageOutput, IncomingChatPayload,
    MessagePayload, OutgoingChatPayload, PaymentOutput, PaymentPayloadData, Timestamp,
    PAIRS_PER_MEMBER_LIST, PTS_PER_CHAIN_LIST,
};
use stegos_crypto::hash::Hash;

use stegos_crypto::scc::{sign_hash, Fr, PublicKey, SchnorrSig, SecretKey};

use super::private_message::PrivateMessage;
use super::{Chat, MemberRoster, NewMemberInfo, NewMemberInfoCont, NewMemberMessage, UtxoInfo};

#[derive(Debug, Clone)]
pub struct GroupOwnerInfo {
    // description of the Group / Channel
    pub group_id: String,
    // Public key used for this group ownership
    pub owner_pkey: PublicKey,
    // Secret key used for this group ownership
    pub owner_skey: SecretKey,
    // current chain code
    pub owner_chain: Fr,
    // chain for use in group rekeyings
    pub owner_rekeying_chain: Fr,
    // list of members / subscribers
    pub members: MemberRoster,
    // list of ignored members
    pub ignored_members: Vec<PublicKey>,
}

#[derive(Debug, Clone)]
pub struct GroupSession {
    // description of the Group
    pub group_id: String,
    // owner of the group
    pub owner_pkey: PublicKey,
    // owner chain code for session
    pub owner_chain: Fr,
    // owner chain code for rekeying purposes
    pub owner_rekeying_chain: Fr,
    // my public key for group chat purposees
    pub my_pkey: PublicKey,
    // my secret key for group chat purposes
    pub my_skey: SecretKey,
    // my current chain code
    pub my_chain: Fr,
    // list of other group members and their chain codes
    pub members: MemberRoster,
    // list of ignored members
    pub ignored_members: Vec<PublicKey>,
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
                let r_owner = detrand(&self.owner_pkey, &self.owner_chain);
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
            let r_owner = detrand(&self.owner_pkey, &self.owner_chain);
            let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
            msgs.push(generate_message(
                self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &evicted,
            ));
        }
        msgs
    }

    pub fn record_utxo(
        &mut self,
        chat: &mut Chat,
        utxo: &ChatMessageOutput,
        owner_chain: &Fr,
        sender: PublicKey,
    ) {
        match self.members.find_sender_chain(utxo) {
            Some(member) => {
                chat.my_utxos.push(UtxoInfo {
                    id: Hash::digest(utxo),
                    created: utxo.created,
                    keying: utxo.recipient_cloaking_hint * *owner_chain / member.chain
                        * Fr::from(self.owner_skey),
                });
            }
            None => unreachable!(),
        }
    }

    pub fn decrypt_message(
        &mut self,
        utxo: &ChatMessageOutput,
        owner_chain: &Fr,
    ) -> Option<(PublicKey, IncomingChatPayload)> {
        self.members.get_decrypted_message(
            &self.owner_pkey,
            owner_chain,
            &self.owner_skey,
            &self.owner_pkey,
            &self.owner_chain,
            utxo,
        )
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

    pub fn get_owner_chain(&self, msg: &ChatMessageOutput) -> Fr {
        match msg.payload {
            MessagePayload::EncryptedMessage(_) => self.owner_chain,
            MessagePayload::EncryptedChainCodes(_) => self.owner_rekeying_chain,
        }
    }

    // GUI Alert -- call this after you have a list of one or more new member PublicKeys.
    pub fn add_new_members(&mut self, new_members: Vec<PublicKey>) -> Vec<NewMemberMessage> {
        // Accept a list of new member PublicKeys
        // Add them with new chain codes to our own roster,
        // then send one or more NewMember messages to the group
        // and send one or more private mesasges to new members
        let mut new_mems = new_members.clone();
        new_mems.sort();
        new_mems.dedup();
        let mut pairs = Vec::<(PublicKey, Fr)>::new();
        for pkey in new_mems.iter() {
            let (_, chain) = new_chain_code(&pkey, &self.owner_chain);
            pairs.push((pkey.clone(), chain.clone()));
        }
        let epoch = Timestamp::now();
        self.members.add_members_to_roster(&mut pairs, epoch);

        let msg_ser: u64 = rand::thread_rng().gen();
        let msg_tot = ((pairs.len() + PAIRS_PER_MEMBER_LIST - 1) / PAIRS_PER_MEMBER_LIST) as u32;
        let mut msg_nbr = 0u32;
        let mut mem_nbr = 0;
        let mut msgs = Vec::<NewMemberMessage>::new();
        let mut joined = Vec::<(PublicKey, Fr)>::new();

        fn generate_message(
            info: &GroupOwnerInfo,
            msg_ser: u64,
            msg_nbr: u32,
            msg_tot: u32,
            r_owner: Fr,
            r_sender: Fr,
            joined: &Vec<(PublicKey, Fr)>,
        ) -> NewMemberMessage {
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
            NewMemberMessage::GroupMessage(msg)
        }

        pairs.iter().for_each(|pair| {
            joined.push(pair.clone());
            mem_nbr += 1;
            if mem_nbr >= PAIRS_PER_MEMBER_LIST {
                let r_owner = detrand(&self.owner_pkey, &self.owner_chain);
                let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
                msgs.push(generate_message(
                    self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &joined,
                ));
                msg_nbr += 1;
                mem_nbr = 0;
                joined = Vec::<(PublicKey, Fr)>::new();
            }
        });
        if mem_nbr > 0 {
            let r_owner = detrand(&self.owner_pkey, &self.owner_chain);
            let r_sender = detrand(&self.owner_pkey, &self.owner_chain);
            msgs.push(generate_message(
                self, msg_ser, msg_nbr, msg_tot, r_owner, r_sender, &joined,
            ));
        }
        for mem in new_mems.iter() {
            let mut utxos = self.new_member_info_private_msg(mem);
            msgs.append(&mut utxos);
        }
        msgs
    }

    fn new_member_info_private_msg(&self, mem: &PublicKey) -> Vec<NewMemberMessage> {
        let mut msgs = Vec::<NewMemberMessage>::new();
        let grpinfo = self.members.find_member(mem).expect("ok");
        let num_members = self.members.0.len();
        let initial_count = if num_members > 10 { 10 } else { num_members };
        let initial_list = self.members.0.clone()[0..initial_count]
            .iter()
            .map(|g| (g.pkey.clone(), g.chain.clone()))
            .collect();
        let mut msg = NewMemberInfo {
            owner_pkey: self.owner_pkey.clone(),
            owner_chain: self.owner_chain.clone(),
            rekeying_chain: self.owner_rekeying_chain.clone(),
            my_initial_chain: grpinfo.chain.clone(),
            num_members: num_members as u32,
            members: initial_list,
            signature: SchnorrSig::new(),
        };
        msg.signature = sign_hash(&Hash::digest(&msg), &self.owner_skey);
        let info = PrivateMessage::NewMemberInfo(msg);
        let raw_info = info.encode().expect("ok");
        let data = PaymentPayloadData::Data(raw_info);
        let msg_stuff =
            PaymentOutput::with_payload(Some(&self.owner_skey), mem, 0, data).expect("okay");
        msgs.push(NewMemberMessage::PrivateMessage(msg_stuff));

        if num_members > 10 {
            let mut index = 10;
            while index < num_members {
                let remaining = num_members - index;
                let nel = if remaining > 12 { 12 } else { remaining };
                let sublist = self.members.0.clone()[index..index + nel]
                    .iter()
                    .map(|g| (g.pkey.clone(), g.chain.clone()))
                    .collect();
                let mut msg = NewMemberInfoCont {
                    owner_pkey: self.owner_pkey.clone(),
                    num_members: num_members as u32,
                    member_index: index as u32,
                    members: sublist,
                    signature: SchnorrSig::new(),
                };
                msg.signature = sign_hash(&Hash::digest(&msg), &self.owner_skey);

                let info = PrivateMessage::NewMemberInfoCont(msg);
                let raw_info = info.encode().expect("ok");
                let data = PaymentPayloadData::Data(raw_info);
                let msg_stuff = PaymentOutput::with_payload(Some(&self.owner_skey), mem, 0, data)
                    .expect("okay");
                msgs.push(NewMemberMessage::PrivateMessage(msg_stuff));
                index += nel;
            }
        }
        msgs
    }
}

// ----------------------------------------------------------

impl GroupSession {
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

    pub fn decrypt_message(
        &mut self,
        utxo: &ChatMessageOutput,
        owner_chain: &Fr,
    ) -> Option<(PublicKey, IncomingChatPayload)> {
        self.members.get_decrypted_message(
            &self.owner_pkey,
            owner_chain,
            &self.my_skey,
            &self.my_pkey,
            &self.my_chain,
            utxo,
        )
    }

    pub fn new_message(&self, msg: Vec<u8>) -> ChatMessageOutput {
        make_chat_message(
            &self.owner_pkey,
            &self.owner_chain,
            &self.my_skey,
            &self.my_pkey,
            &self.my_chain,
            &msg[..],
        )
    }

    pub fn get_owner_chain(&self, msg: &ChatMessageOutput) -> Fr {
        match msg.payload {
            MessagePayload::EncryptedMessage(_) => self.owner_chain,
            MessagePayload::EncryptedChainCodes(_) => self.owner_rekeying_chain,
        }
    }
}
