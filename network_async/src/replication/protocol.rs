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

use crate::metrics;

use crate::utils::FutureResult;
use bytes::BytesMut;
use derivative::Derivative;
use futures::future;
use futures_codec::{Decoder, Encoder, Framed};
use futures_io::{AsyncRead, AsyncWrite};
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use log::trace;
use std::fmt;
use std::io;
use unsigned_varint::codec;

use libp2p_core::ProtocolName;

// Protocol label for metrics
const PROTOCOL_LABEL: &str = "replication";

#[derive(Debug, Clone, Copy)]
pub enum ReplicationVersion {
    V0_13, // old version that was implemented in stegos 0.13
    V1_3,  // new version that was implemented during 1.3
}
impl ReplicationVersion {
    pub fn latest() -> Self {
        ReplicationVersion::V1_3
    }
}

impl fmt::Display for ReplicationVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplicationVersion::V0_13 => write!(f, "v0.13.0"),
            ReplicationVersion::V1_3 => write!(f, "v1.3.0"),
        }
    }
}

impl ProtocolName for ReplicationVersion {
    fn protocol_name(&self) -> &[u8] {
        match *self {
            ReplicationVersion::V0_13 => b"/replication/0.13.0",
            ReplicationVersion::V1_3 => b"/replication/1.3.0",
        }
    }
}

/// Implementation of `ConnectionUpgrade` for the replication protocol.
#[derive(Default, Debug, Clone)]
pub struct ReplicationConfig {}

impl ReplicationConfig {
    /// Builds a new `ReplicationConfig`.
    #[inline]
    pub fn new() -> ReplicationConfig {
        ReplicationConfig {}
    }
}

impl UpgradeInfo for ReplicationConfig {
    type Info = ReplicationVersion;
    type InfoIter = Vec<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        let mut protos = vec![ReplicationVersion::V1_3];
        if cfg!(feature = "old_protos") {
            protos.push(ReplicationVersion::V0_13)
        };
        protos
    }
}

impl<TSocket> InboundUpgrade<TSocket> for ReplicationConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, ReplicationCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, version: Self::Info) -> Self::Future {
        trace!("Upgraded inbound {}", version);
        future::ok(Framed::new(
            socket,
            ReplicationCodec {
                version,
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for ReplicationConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Framed<TSocket, ReplicationCodec>;
    type Error = io::Error;
    type Future = FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, version: Self::Info) -> Self::Future {
        trace!("Upgraded outbound {}", version);
        future::ok(Framed::new(
            socket,
            ReplicationCodec {
                version,
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct ReplicationCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    #[derivative(Debug = "ignore")]
    length_prefix: codec::UviBytes,
    pub version: ReplicationVersion,
}

impl Encoder for ReplicationCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        metrics::OUTGOING_TRAFFIC
            .with_label_values(&[&PROTOCOL_LABEL])
            .inc_by(item.len() as i64);

        let msg = self.length_prefix.encode(item.into(), dst);
        match msg {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Decoder for ReplicationCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.length_prefix.decode(src)? {
            Some(bytes) => {
                metrics::INCOMING_TRAFFIC
                    .with_label_values(&[&PROTOCOL_LABEL])
                    .inc_by(bytes.len() as i64);
                Ok(Some(bytes.to_vec()))
            }
            None => Ok(None),
        }
    }
}
