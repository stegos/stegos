//
// MIT License
//
// Copyright (c) 2018 Stegos
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

use bytes::{Bytes, BytesMut};
use futures::future::Future;
use futures::{future, Poll, Sink, StartSend, Stream};
use libp2p::core::{ConnectionUpgrade, Endpoint};
use std::io::Error as IoError;
use std::iter;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_codec::{BytesCodec, Framed};

/// Implementation of the `ConnectionUpgrade` for the echo protocol.
#[derive(Debug, Clone)]
pub struct EchoUpgrade;

impl<S, Maf> ConnectionUpgrade<S, Maf> for EchoUpgrade
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    Maf: Send + 'static,
{
    type Output = (Endpoint, EchoMiddleware<S>);
    type MultiaddrFuture = Maf;
    type Future = Box<dyn Future<Item = (Self::Output, Maf), Error = IoError> + Send>;
    type NamesIter = iter::Once<(Bytes, ())>;
    type UpgradeIdentifier = ();

    // TODO: replace with stegos proto id.
    #[inline]
    fn protocol_names(&self) -> Self::NamesIter {
        iter::once(("/echo/1.0.0".into(), ()))
    }

    #[inline]
    fn upgrade(self, incoming: S, _: (), endpoint: Endpoint, remote_addr: Maf) -> Self::Future {
        // debug!("Starting secio upgrade");

        let fut = EchoMiddleware::new(incoming);
        Box::new(fut.map(move |out| ((endpoint, out), remote_addr)))
    }
}

/// Wraps around an object that implements `AsyncRead` and `AsyncWrite`.
///
/// Implements `Sink` and `Stream` whose items are frames of data. Each frame is encoded
/// individually, so you are encouraged to group data in few frames if possible.
pub struct EchoMiddleware<S>
where
    S: AsyncRead + AsyncWrite,
{
    // inner: MapErr<Framed<S, BytesCodec>, fn(Error) -> IoError>,
    inner: Framed<S, BytesCodec>,
}

impl<S> EchoMiddleware<S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    /// Wraps stream in Framing proto
    pub fn new<'a>(
        socket: S,
    ) -> Box<dyn Future<Item = EchoMiddleware<S>, Error = IoError> + Send + 'a>
    where
        S: 'a,
    {
        let fut = Framed::new(socket, BytesCodec::new());
        // .sink_map_err(|err| IoError::new(IoErrorKind::InvalidData, err))
        // .map_err(|err| IoError::new(IoErrorKind::InvalidData, err));

        Box::new(future::ok(EchoMiddleware { inner: fut }))
    }
}

impl<S> Sink for EchoMiddleware<S>
where
    S: AsyncRead + AsyncWrite,
{
    // type SinkItem = BytesMut;
    type SinkItem = Bytes;
    type SinkError = IoError;

    #[inline]
    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.inner.start_send(item)
    }

    #[inline]
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete()
    }

    #[inline]
    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.close()
    }
}

impl<S> Stream for EchoMiddleware<S>
where
    S: AsyncRead + AsyncWrite,
{
    // type Item = Vec<u8>;
    type Item = BytesMut;
    type Error = IoError;

    #[inline]
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.inner.poll()
    }
}
