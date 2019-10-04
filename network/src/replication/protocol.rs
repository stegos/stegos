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

use bytes::BytesMut;
use futures::future;
use libp2p_core::{upgrade::Negotiated, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use std::io;
use std::iter;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use unsigned_varint::codec;

/// Implementation of `ConnectionUpgrade` for the replication protocol.
#[derive(Debug, Clone)]
pub struct ReplicationConfig {}

impl ReplicationConfig {
    /// Builds a new `ReplicationConfig`.
    #[inline]
    pub fn new() -> ReplicationConfig {
        ReplicationConfig {}
    }
}

impl UpgradeInfo for ReplicationConfig {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/replication/0.13.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for ReplicationConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<Negotiated<TSocket>, ReplicationCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_inbound(self, socket: Negotiated<TSocket>, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            ReplicationCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for ReplicationConfig
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = Framed<Negotiated<TSocket>, ReplicationCodec>;
    type Error = io::Error;
    type Future = future::FutureResult<Self::Output, Self::Error>;

    #[inline]
    fn upgrade_outbound(self, socket: Negotiated<TSocket>, _: Self::Info) -> Self::Future {
        future::ok(Framed::new(
            socket,
            ReplicationCodec {
                length_prefix: Default::default(),
            },
        ))
    }
}

/// Implementation of `tokio_codec::Codec`.
pub struct ReplicationCodec {
    /// The codec for encoding/decoding the length prefix of messages.
    length_prefix: codec::UviBytes,
}

impl Encoder for ReplicationCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.length_prefix.encode(item.into(), dst)
    }
}

impl Decoder for ReplicationCodec {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.length_prefix.decode(src)? {
            Some(bytes) => Ok(Some(bytes.to_vec())),
            None => Ok(None),
        }
    }
}
