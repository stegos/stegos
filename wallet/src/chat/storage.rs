use super::ChatId;
use super::MemberRoster;
use super::{ChannelOwnerInfo, ChannelSession, GroupOwnerInfo, GroupSession};
use bincode;
use failure::Error;
use serde_derive::{Deserialize, Serialize};
use stegos_blockchain::ChatMessageOutput;
use stegos_crypto::scc::{Fr, PublicKey};

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct GroupSessionValue {
    // owner chain code for rekeying purposes.
    pub owner_rekeying_chain: Fr,
    // my current chain code, if it was different from owner chain.
    pub my_chain: Option<Fr>,
    // Ignored members list.
    pub ignored_members: Vec<PublicKey>,
    // Managed members list.
    pub members: MemberRoster,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ChatSessionValue {
    // description of the Group
    pub chat_id: String,
    // owner of the group
    pub owner_pkey: PublicKey,
    // owner chain code for session
    pub owner_chain: Fr,
    // Information specific for groups
    pub group_info: Option<GroupSessionValue>,
}

impl From<ChannelOwnerInfo> for ChatSessionValue {
    fn from(value: ChannelOwnerInfo) -> Self {
        ChatSessionValue {
            chat_id: value.channel_id,
            owner_pkey: value.owner_pkey,
            owner_chain: value.owner_chain,
            group_info: None,
        }
    }
}

impl From<ChannelSession> for ChatSessionValue {
    fn from(value: ChannelSession) -> Self {
        ChatSessionValue {
            chat_id: value.channel_id,
            owner_pkey: value.owner_pkey,
            owner_chain: value.owner_chain,
            group_info: None,
        }
    }
}

impl From<GroupOwnerInfo> for ChatSessionValue {
    fn from(value: GroupOwnerInfo) -> Self {
        let group_info = GroupSessionValue {
            owner_rekeying_chain: value.owner_rekeying_chain,
            my_chain: None,
            ignored_members: value.ignored_members,
            members: value.members,
        };
        ChatSessionValue {
            chat_id: value.group_id,
            owner_pkey: value.owner_pkey,
            owner_chain: value.owner_chain,
            group_info: group_info.into(),
        }
    }
}

impl From<GroupSession> for ChatSessionValue {
    fn from(value: GroupSession) -> Self {
        let group_info = GroupSessionValue {
            owner_rekeying_chain: value.owner_rekeying_chain,
            my_chain: value.my_chain.into(),
            ignored_members: value.ignored_members,
            members: value.members,
        };
        ChatSessionValue {
            chat_id: value.group_id,
            owner_pkey: value.owner_pkey,
            owner_chain: value.owner_chain,
            group_info: group_info.into(),
        }
    }
}

impl ChatSessionValue {
    pub fn id(&self) -> ChatId {
        if self.group_info.is_none() {
            ChatId::ChannelId(self.chat_id.clone())
        } else {
            ChatId::GroupId(self.chat_id.clone())
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        bincode::deserialize(data).map_err(Into::into)
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ChatOutputValue {
    pub sender: PublicKey,
    pub text: String,
    pub utxo: ChatMessageOutput,
}

impl ChatId {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        bincode::deserialize(data).map_err(Into::into)
    }
}

impl ChatOutputValue {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        bincode::deserialize(data).map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // serialization/deserialization roundtrip
    // Internally use encode/decode methods, writted as macro,
    // because we have lack of handwritten traits, and use raw methodfs.
    macro_rules! roundtrip {
        ($val:ident : $t: ident) => {
            let bytes = $val.encode().unwrap();
            let new_val = $t::decode(&bytes).unwrap();
            assert_eq!($val, new_val)
        };
    }
    #[test]
    fn serialize_roundtrip_chat_id() {
        let chat_id = ChatId::ChannelId("bla".to_owned());
        roundtrip!(chat_id: ChatId);
        let chat_id = ChatId::GroupId("bla".to_owned());
        roundtrip!(chat_id: ChatId);
    }
    #[test]
    fn deserializae_json() {
        let chat_id = ChatId::ChannelId("test".to_owned());
        let new_chat_id: ChatId = serde_json::from_str(r#"{"channel":"test"}"#).unwrap();
        assert_eq!(chat_id, new_chat_id);
    }

    // #[test]
    // fn serialize_roundtrip_output_value() {
    //     let chat_id = ChatId::Channel("bla".to_owned());
    //     roundtrip!(chat_id);
    // }
    //     pub struct GroupSessionValue {
    //     // owner chain code for rekeying purposes.
    //     pub owner_rekeying_chain: Fr,
    //     // my current chain code, if it was different from owner chain.
    //     pub my_chain: Option<Fr>,
    //     // Ignored members list.
    //     pub ignored_members: Vec<PublicKey>,
    //     // Managed members list.
    //     pub members: MemberRoster,
    // }

    // #[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
    // pub struct ChatSessionValue {
    //     // description of the Group
    //     pub chat_id: String,
    //     // owner of the group
    //     pub owner_pkey: PublicKey,
    //     // owner chain code for session
    //     pub owner_chain: Fr,
    //     // Information specific for groups
    //     pub group_info: Option<GroupSessionValue>,
    // }

    #[test]
    fn serialize_roundtrip_chat_session() {
        stegos_crypto::init_test_network_prefix();
        let chat_session = ChatSessionValue {
            chat_id: "Bla".to_owned(),
            owner_pkey: PublicKey::zero(),
            owner_chain: Fr::zero(),
            group_info: None,
        };
        roundtrip!(chat_session: ChatSessionValue);
    }
}
