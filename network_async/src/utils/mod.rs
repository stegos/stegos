//
// MIT License
//
// Copyright (c) 2018-2019 Stegos AG
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

mod expiring_queue;
mod lru_bimap;
mod multihash;
mod peer_id_key;

pub use self::expiring_queue::ExpiringQueue;
pub use self::lru_bimap::LruBimap;
pub use self::multihash::IntoMultihash;
pub use self::peer_id_key::PeerIdKey;

use super::proto::unicast_proto;
use failure::{format_err, Error};
use libp2p::identity::ed25519;
use libp2p::Multiaddr;
use log::*;
use protobuf::Message;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use stegos_crypto::hash::{Hashable, Hasher};
use stegos_crypto::pbc;
use trust_dns_resolver::config::{NameServerConfig, Protocol};

pub type FutureResult<I, E> = futures::future::Ready<Result<I, E>>;

const IBE_ID: &[u8] = &[105u8, 13, 185, 148, 68, 76, 69, 155];

pub async fn resolve_seed_nodes(
    seed_pool: &str,
    dns_servers: &[String],
) -> Result<Vec<String>, Error> {
    use trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        AsyncResolver,
    };

    let dns_servers: Result<Vec<_>, std::net::AddrParseError> = dns_servers
        .iter()
        .map(|d| {
            let addr = d.parse::<SocketAddr>()?;
            Ok(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
            })
        })
        .collect();
    let dns_servers = dns_servers?;

    let mut seed_nodes = Vec::new();
    if seed_pool != "" {
        debug!("Initialising dns resolver.");
        let resolver = if dns_servers.is_empty() {
            AsyncResolver::tokio_from_system_conf().await?
        } else {
            debug!("Setting dns servers to {:?}.", dns_servers);
            let config = ResolverConfig::from_parts(None, vec![], dns_servers);
            AsyncResolver::tokio(config, ResolverOpts::default()).await?
        };
        info!("Trying to resolve seed nodes SRV records.");
        let srv_records = resolver.srv_lookup(seed_pool).await?;
        for srv in srv_records.iter() {
            let addr_records = resolver
                .ipv4_lookup(srv.target().clone())
                .await
                .map_err(|e| format_err!("Failed to resolve seed_pool: {}", e))?;

            for addr in addr_records.iter() {
                let addr = SocketAddrV4::new(*addr, srv.port());
                seed_nodes.push(addr.to_string());
            }
        }
        debug!("Validating seed_nodes addresses = {:?}.", seed_nodes);
        // Validate network.seed_nodes.
        for (i, addr) in seed_nodes.iter().enumerate() {
            SocketAddr::from_str(addr)
                .map_err(|e| format_err!("Invalid network.seed_nodes[{}] '{}': {}", i, addr, e))?;
        }
    }
    Ok(seed_nodes)
}

pub fn ed25519_from_pbc(source: &pbc::SecretKey) -> ed25519::Keypair {
    let mut raw = source.to_bytes();
    let secret = ed25519::SecretKey::from_bytes(&mut raw)
        .expect("this returns `Err` only if the length is wrong; the length is correct; qed");
    ed25519::Keypair::from(secret)
}

#[derive(Clone, Debug)]
pub struct UnicastPayload {
    pub from: pbc::PublicKey,
    pub to: pbc::PublicKey,
    pub protocol_id: String,
    pub data: Vec<u8>,
}

// Encode unicast message
pub fn encode_unicast(payload: UnicastPayload, sign_key: &pbc::SecretKey) -> Vec<u8> {
    let mut msg = unicast_proto::Message::new();

    // NOTE: ibe_encrypt() can fail if payload.to is an invalid PublicKey
    // It should be checked ahead of this place, using PublicKey::decompress()?
    let enc_packet = pbc::ibe_encrypt(&payload.data, &payload.to, IBE_ID).expect("ok");

    let mut hasher = Hasher::new();
    payload.from.hash(&mut hasher);
    payload.to.hash(&mut hasher);
    payload.protocol_id.hash(&mut hasher);
    enc_packet.rval().hash(&mut hasher);
    enc_packet.cmsg().hash(&mut hasher);
    let hash = hasher.result();
    let sig = pbc::sign_hash(&hash, sign_key);

    msg.set_data(enc_packet.cmsg().to_vec());
    msg.set_rval(enc_packet.rval().to_bytes().to_vec());
    msg.set_from(payload.from.to_bytes().to_vec());
    msg.set_to(payload.to.to_bytes().to_vec());
    msg.set_protocol_id(payload.protocol_id.into_bytes().to_vec());
    msg.set_signature(sig.to_bytes().to_vec());

    msg.write_to_bytes()
        .expect("protobuf encoding should never fail")
}

pub fn decode_unicast(
    input: Vec<u8>,
) -> Result<(UnicastPayload, pbc::Signature, pbc::RVal), Error> {
    let mut msg: unicast_proto::Message = protobuf::parse_from_bytes(&input)?;

    let from = pbc::PublicKey::try_from_bytes(&msg.take_from().to_vec())?;
    let to = pbc::PublicKey::try_from_bytes(&msg.take_to().to_vec())?;
    let signature = pbc::Signature::try_from_bytes(&msg.take_signature().to_vec())?;
    let protocol_id_bytes = &msg.get_protocol_id();
    let protocol_id = String::from_utf8(protocol_id_bytes.to_vec())?;
    let data = msg.take_data().to_vec();
    let rval = pbc::RVal::try_from_bytes(&msg.take_rval().to_vec())?;

    let payload = UnicastPayload {
        from,
        to,
        protocol_id,
        data,
    };

    Ok((payload, signature, rval))
}

pub fn decrypt_message(
    my_skey: &pbc::SecretKey,
    mut payload: UnicastPayload,
    signature: pbc::Signature,
    rval: pbc::RVal,
) -> Result<UnicastPayload, Error> {
    let enc_packet = pbc::EncryptedPacket::new(&payload.to, IBE_ID, &rval, &payload.data);

    let mut hasher = Hasher::new();
    payload.from.hash(&mut hasher);
    payload.to.hash(&mut hasher);
    payload.protocol_id.hash(&mut hasher);
    rval.hash(&mut hasher);
    payload.data.hash(&mut hasher);
    let hash = hasher.result();

    if let Err(_e) = pbc::check_hash(&hash, &signature, &payload.from) {
        return Err(format_err!("Bad packet signature."));
    }

    if let Ok(data) = pbc::ibe_decrypt(&enc_packet, my_skey) {
        // if decrypted fine, check the signature
        payload.data = data;
        Ok(payload)
    } else {
        Err(format_err!("Packet failed to decrypt."))
    }
}

pub fn socket_to_multi_addr(addr: &SocketAddr) -> Multiaddr {
    let mut maddr: Multiaddr = addr.ip().into();
    maddr.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
    maddr
}
