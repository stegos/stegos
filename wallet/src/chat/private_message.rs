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
use failure::Error;
use stegos_blockchain::{ChatError, PaymentOutput, PaymentPayloadData, PAYMENT_DATA_LEN};
use stegos_crypto::hash::Hash;

use super::{NewMemberInfo, NewMemberInfoCont};
use byteorder::{ByteOrder, LittleEndian};
use stegos_crypto::scc::{validate_sig, Fr, PublicKey, SchnorrSig, SecretKey};
#[derive(Clone)]
pub enum PrivateMessage {
    // Payload is max of 882 bytes, including the initial type prefix byte
    NewMemberInfo(NewMemberInfo),
    NewMemberInfoCont(NewMemberInfoCont),
    OtherData(Vec<u8>),
}

// GUI Alert - call this function to produce general purpose secret messages
// with binary encoding in the payload = PaymentPayloadData::Data(Vec<u8>).
// Otherwise, use PaymentPayloadData subtypes Comment(String) or ContentHash(Hash)
// and make your own UTXO.
pub fn make_private_message(
    from_skey: &SecretKey,
    to_pkey: &PublicKey,
    amount: i64,
    msg: Vec<u8>,
) -> Result<(PaymentOutput, Fr, Fr), Error> {
    // Return a Paymnent UTXO and gamma, delta factors,
    // Max of 881 bytes in msg.
    // Secret messages can also transfer tokens.
    let data = PrivateMessage::OtherData(msg.clone()).encode()?;
    let payload = PaymentPayloadData::Data(data);
    match PaymentOutput::with_payload(Some(from_skey), to_pkey, amount, payload) {
        Ok(triple) => Ok(triple),
        Err(err) => Err(err.into()),
    }
}

impl PrivateMessage {
    pub fn encode(&self) -> Result<Vec<u8>, ChatError> {
        let mut enc = [0u8; PAYMENT_DATA_LEN - 2];
        match self {
            PrivateMessage::NewMemberInfo(data) => {
                if data.members.len() > 10 {
                    return Err(ChatError::DataTooLong);
                }
                enc[0] = 0u8;
                let bytes = data.owner_pkey.to_bytes();
                enc[1..33].copy_from_slice(&bytes[..]);
                let bytes = data.owner_chain.to_bytes();
                enc[33..65].copy_from_slice(&bytes[..]);
                let bytes = data.rekeying_chain.to_bytes();
                enc[65..97].copy_from_slice(&bytes[..]);
                let bytes = data.my_initial_chain.to_bytes();
                enc[97..129].copy_from_slice(&bytes[..]);
                let mut bytes = [0u8; 4];
                LittleEndian::write_u32(&mut bytes, data.num_members);
                enc[129..133].copy_from_slice(&bytes[..]);
                enc[133] = data.members.len() as u8;
                let mut pos = 134;
                for (pkey, chain) in data.members.iter() {
                    let bytes = pkey.to_bytes();
                    enc[pos..pos + 32].copy_from_slice(&bytes[..]);
                    pos += 32;
                    let bytes = chain.to_bytes();
                    enc[pos..pos + 32].copy_from_slice(&bytes[..]);
                    pos += 32;
                }
                let bytes = data.signature.to_bytes();
                enc[pos..pos + 64].copy_from_slice(&bytes[..]);
                Ok(enc.to_vec())
            }
            PrivateMessage::NewMemberInfoCont(data) => {
                if data.members.len() > 12 {
                    return Err(ChatError::DataTooLong);
                }
                enc[0] = 1u8;
                let bytes = data.owner_pkey.to_bytes();
                enc[1..33].copy_from_slice(&bytes[..]);
                let mut bytes = [0u8; 4];
                LittleEndian::write_u32(&mut bytes, data.num_members);
                enc[33..37].copy_from_slice(&bytes[..]);
                LittleEndian::write_u32(&mut bytes, data.member_index);
                enc[37..41].copy_from_slice(&bytes[..]);
                enc[41] = data.members.len() as u8;
                let mut pos = 42;
                for (pkey, chain) in data.members.iter() {
                    let bytes = pkey.to_bytes();
                    enc[pos..pos + 32].copy_from_slice(&bytes[..]);
                    pos += 32;
                    let bytes = chain.to_bytes();
                    enc[pos..pos + 32].copy_from_slice(&bytes[..]);
                    pos += 32;
                }
                let bytes = data.signature.to_bytes();
                enc[pos..pos + 64].copy_from_slice(&bytes[..]);
                Ok(enc.to_vec())
            }
            PrivateMessage::OtherData(data) => {
                if data.len() > PAYMENT_DATA_LEN - 3 {
                    return Err(ChatError::DataTooLong);
                }
                enc[0] = 2u8;
                enc[1..data.len() + 1].copy_from_slice(&data[..]);
                Ok(enc.to_vec())
            }
        }
    }

    // GUI Alert - when you want to decipher the PaymentPayloadData::Data from
    // a PaymentOutput UTXO that carries a private message...
    pub fn from_bytes(bytes: &Vec<u8>) -> Result<PrivateMessage, Error> {
        let nel = bytes.len();
        if nel < PAYMENT_DATA_LEN - 2 {
            return Err(ChatError::DataTooShort.into());
        }
        match bytes[0] {
            0 => {
                let owner_pkey = PublicKey::try_from_bytes(&bytes[1..33])?;
                let owner_chain = Fr::try_from_bytes(&bytes[33..65])?;
                let rekeying_chain = Fr::try_from_bytes(&bytes[65..97])?;
                let my_initial_chain = Fr::try_from_bytes(&bytes[97..129])?;
                let num_members = LittleEndian::read_u32(&bytes[129..133]);
                let mut members = Vec::<(PublicKey, Fr)>::new();
                let nmem = bytes[133] as usize;
                if nmem > 10 {
                    return Err(ChatError::DataTooLong.into());
                }
                let mut pos = 134;
                for _ in 0..nmem {
                    let pkey = PublicKey::try_from_bytes(&bytes[pos..pos + 32])?;
                    pos += 32;
                    let chain = Fr::try_from_bytes(&bytes[pos..pos + 32])?;
                    pos += 32;
                    members.push((pkey, chain));
                }
                let signature = SchnorrSig::try_from_bytes(&bytes[pos..pos + 64])?;
                let info = NewMemberInfo {
                    owner_pkey,
                    owner_chain,
                    rekeying_chain,
                    my_initial_chain,
                    num_members,
                    members,
                    signature,
                };
                validate_sig(&Hash::digest(&info), &signature, &info.owner_pkey)?;
                Ok(PrivateMessage::NewMemberInfo(info))
            }
            1 => {
                let owner_pkey = PublicKey::try_from_bytes(&bytes[1..33])?;
                let num_members = LittleEndian::read_u32(&bytes[33..37]);
                let member_index = LittleEndian::read_u32(&bytes[37..41]);
                let mut members = Vec::<(PublicKey, Fr)>::new();
                let nmem = bytes[41] as usize;
                if nmem > 12 {
                    return Err(ChatError::DataTooLong.into());
                }
                let mut pos = 42;
                for _ in 0..nmem {
                    let pkey = PublicKey::try_from_bytes(&bytes[pos..pos + 32])?;
                    pos += 32;
                    let chain = Fr::try_from_bytes(&bytes[pos..pos + 32])?;
                    pos += 32;
                    members.push((pkey, chain));
                }
                let signature = SchnorrSig::try_from_bytes(&bytes[pos..pos + 64])?;
                let info = NewMemberInfoCont {
                    owner_pkey,
                    num_members,
                    member_index,
                    members,
                    signature,
                };
                validate_sig(&Hash::digest(&info), &signature, &info.owner_pkey)?;
                Ok(PrivateMessage::NewMemberInfoCont(info))
            }
            _ => {
                let mut msg = [0u8; PAYMENT_DATA_LEN - 2];
                msg.copy_from_slice(&bytes[..]);
                Ok(PrivateMessage::OtherData(msg.to_vec()))
            }
        }
    }
}
