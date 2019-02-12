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

// See https://github.com/stegos/stegos/wiki/Unicast-delivery-module for some details

use crate::unicast_send::protocol::{
    ChallengeMessage, ChallengeReplyMessage, DataMessage, UnicastSendConfig, UnicastWireCodec,
    UnicastWireMessage,
};
use crate::unicast_send::{UnicastDataMessage, UnicastSendError, UnicastSendMessage};
use futures::prelude::*;
use libp2p::core::{
    protocols_handler::ProtocolsHandlerUpgrErr,
    upgrade::{InboundUpgrade, OutboundUpgrade},
    ProtocolsHandler, ProtocolsHandlerEvent,
};
use log::*;
use smallvec::SmallVec;
use std::{fmt, io};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

/// Protocol handler that handles communication with the remote for the NCP protocol.
///
/// The handler will automatically open a substream with the remote for each request we make.
///
/// It also handles requests made by the remote.
pub struct UnicastHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Configuration for the Ncp protocol.
    config: UnicastSendConfig,

    /// If true, we are trying to shut down the existing NCP substream and should refuse any
    /// incoming connection.
    shutting_down: bool,

    /// The active substreams.
    // TODO: add a limit to the number of allowed substreams
    substreams: Vec<SubstreamState<TSubstream>>,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[UnicastDataMessage; 16]>,
    /// Local pbc public key
    local_pkey: secure::PublicKey,
    /// Local pbc secret key
    local_skey: secure::SecretKey,
}

/// State of an active substream, opened either by us or by the remote.
enum SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Waiting for a message from the remote.
    WaitingInput(Framed<TSubstream, UnicastWireCodec>, SendState),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<TSubstream, UnicastWireCodec>, SendState),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<TSubstream, UnicastWireCodec>, SendState),
    /// The substream is being closed.
    Closing(Framed<TSubstream, UnicastWireCodec>),
}

#[derive(Debug, Clone)]
enum SendState {
    WaitingChallenge,
    WaitingData(secure::Signature, u64),
    SendingChallenge(UnicastDataMessage),
    WaitingChallengeReply(u64, UnicastDataMessage),
    SendingData(UnicastDataMessage, secure::Signature),
}

impl<TSubstream> SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Consumes this state and produces the substream.
    fn into_substream(self) -> Framed<TSubstream, UnicastWireCodec> {
        match self {
            SubstreamState::WaitingInput(substream, _) => substream,
            SubstreamState::PendingSend(substream, _) => substream,
            SubstreamState::PendingFlush(substream, _) => substream,
            SubstreamState::Closing(substream) => substream,
        }
    }
}

impl<TSubstream> UnicastHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    /// Builds a new `UnicastHandler`.
    pub fn new(local_pkey: secure::PublicKey, local_skey: secure::SecretKey) -> Self {
        UnicastHandler {
            config: UnicastSendConfig::new(),
            shutting_down: false,
            substreams: Vec::new(),
            send_queue: SmallVec::new(),
            local_pkey,
            local_skey,
        }
    }
}

impl<TSubstream> ProtocolsHandler for UnicastHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    type InEvent = UnicastDataMessage;
    type OutEvent = UnicastSendMessage;
    type Error = io::Error;
    type Substream = TSubstream;
    type InboundProtocol = UnicastSendConfig;
    type OutboundProtocol = UnicastSendConfig;
    type OutboundOpenInfo = UnicastDataMessage;

    #[inline]
    fn listen_protocol(&self) -> Self::InboundProtocol {
        self.config.clone()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        if self.shutting_down {
            return ();
        }
        self.substreams.push(SubstreamState::WaitingInput(
            protocol,
            SendState::WaitingChallenge,
        ))
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<TSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        if self.shutting_down {
            return;
        }
        self.substreams.push(SubstreamState::PendingSend(
            protocol,
            SendState::SendingChallenge(message),
        ))
    }

    #[inline]
    fn inject_event(&mut self, message: Self::InEvent) {
        self.send_queue.push(message);
    }

    #[inline]
    fn inject_inbound_closed(&mut self) {}

    #[inline]
    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        _: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<Self::Substream>>::Error,
        >,
    ) {
    }

    // TODO: After upgrading to libp2p v0.3 set reasonable time
    #[inline]
    fn connection_keep_alive(&self) -> bool {
        !self.substreams.is_empty()
    }

    #[inline]
    fn shutdown(&mut self) {
        self.shutting_down = true;
        for n in (0..self.substreams.len()).rev() {
            let substream = self.substreams.swap_remove(n);
            self.substreams
                .push(SubstreamState::Closing(substream.into_substream()));
        }
    }

    fn poll(
        &mut self,
    ) -> Poll<
        ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent>,
        io::Error,
    > {
        if !self.send_queue.is_empty() {
            let message = self.send_queue.remove(0);
            return Ok(Async::Ready(
                ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    info: message,
                    upgrade: self.config.clone(),
                },
            ));
        }

        for n in (0..self.substreams.len()).rev() {
            let mut substream = self.substreams.swap_remove(n);
            loop {
                substream = match substream {
                    SubstreamState::WaitingInput(mut substream, send_state) => match substream
                        .poll()
                    {
                        Ok(Async::Ready(Some(message))) => {
                            debug!("handler got message from network: {:#?}", message);
                            match send_state {
                                SendState::WaitingChallenge => {
                                    if let UnicastWireMessage::Challenge(challenge_msg) = message {
                                        let signature = sign_challenge(
                                            challenge_msg.challenge,
                                            &self.local_skey,
                                        );
                                        let sender_challenge = rand::random::<u64>();
                                        SubstreamState::PendingSend(
                                            substream,
                                            SendState::WaitingData(signature, sender_challenge),
                                        )
                                    } else {
                                        let out_msg = UnicastSendMessage::Error(
                                            UnicastSendError::NoChallenge,
                                        );
                                        self.substreams.push(SubstreamState::Closing(substream));
                                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                            out_msg,
                                        )));
                                    }
                                }
                                SendState::WaitingData(signature, sender_challenge) => {
                                    if let UnicastWireMessage::Data(data_msg) = message {
                                        let out_msg = if verify_challenge_data_signature(
                                            sender_challenge,
                                            &data_msg,
                                        ) {
                                            UnicastSendMessage::Data(UnicastDataMessage {
                                                to: self.local_pkey,
                                                from: data_msg.sender_pkey,
                                                protocol_id: data_msg.protocol_id,
                                                data: data_msg.data,
                                            })
                                        } else {
                                            UnicastSendMessage::Error(
                                                UnicastSendError::BadSignature,
                                            )
                                        };
                                        self.substreams.push(SubstreamState::WaitingInput(
                                            substream,
                                            SendState::WaitingData(signature, sender_challenge),
                                        ));
                                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                            out_msg,
                                        )));
                                    } else {
                                        let out_msg =
                                            UnicastSendMessage::Error(UnicastSendError::NoData);
                                        self.substreams.push(SubstreamState::Closing(substream));
                                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                            out_msg,
                                        )));
                                    }
                                }
                                SendState::WaitingChallengeReply(challenge, msg) => {
                                    if let UnicastWireMessage::ChallengeReply(reply_msg) = message {
                                        if verify_challenge_signature(
                                            challenge,
                                            reply_msg.signature,
                                            msg.to,
                                        ) {
                                            // Remote replied with correct signature
                                            // Sign remote challenge and send signature along with data
                                            let challenge_signature = sign_challenge_data(
                                                reply_msg.sender_challenge,
                                                &msg,
                                                &self.local_skey,
                                            );
                                            SubstreamState::PendingSend(
                                                substream,
                                                SendState::SendingData(msg, challenge_signature),
                                            )
                                        } else {
                                            let out_msg = UnicastSendMessage::Error(
                                                UnicastSendError::BadSignature,
                                            );
                                            self.substreams
                                                .push(SubstreamState::Closing(substream));
                                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                                out_msg,
                                            )));
                                        }
                                    } else {
                                        let out_msg = UnicastSendMessage::Error(
                                            UnicastSendError::BadChallengeReply,
                                        );
                                        self.substreams.push(SubstreamState::Closing(substream));
                                        return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                            out_msg,
                                        )));
                                    }
                                }
                                // Other states impossible
                                _ => {
                                    error!("Invalid state waiting input: {:#?}", send_state);
                                    unreachable!();
                                }
                            }
                        }
                        Ok(Async::Ready(None)) => SubstreamState::Closing(substream),
                        Ok(Async::NotReady) => {
                            self.substreams
                                .push(SubstreamState::WaitingInput(substream, send_state));
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            let out_msg =
                                UnicastSendMessage::Error(UnicastSendError::SubstreamError(e));
                            self.substreams.push(SubstreamState::Closing(substream));
                            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(out_msg)));
                        }
                    },
                    SubstreamState::PendingSend(mut substream, send_state) => {
                        let (message, new_state) = match send_state {
                            SendState::WaitingData(signature, sender_challenge) => {
                                let wire_msg =
                                    UnicastWireMessage::ChallengeReply(ChallengeReplyMessage {
                                        signature: signature.clone(),
                                        sender_challenge,
                                    });
                                let new_state =
                                    SendState::WaitingData(signature.clone(), sender_challenge);
                                (wire_msg, new_state)
                            }
                            SendState::SendingChallenge(ref msg) => {
                                let challenge = rand::random::<u64>();
                                let wire_msg =
                                    UnicastWireMessage::Challenge(ChallengeMessage { challenge });
                                let new_state =
                                    SendState::WaitingChallengeReply(challenge, msg.clone());
                                (wire_msg, new_state)
                            }
                            SendState::SendingData(ref msg, ref signature) => {
                                let wire_msg = UnicastWireMessage::Data(DataMessage {
                                    sender_pkey: msg.from.clone(),
                                    protocol_id: msg.protocol_id.clone(),
                                    data: msg.data.clone(),
                                    sender_signature: signature.clone(),
                                });
                                let new_state =
                                    SendState::SendingData(msg.clone(), signature.clone());
                                (wire_msg, new_state)
                            }
                            _ => {
                                error!("Invalid state in sending to remote: {:#?}", send_state);
                                unreachable!();
                            }
                        };
                        debug!("trying to send message: {:#?}", message);
                        match substream.start_send(message)? {
                            AsyncSink::Ready => SubstreamState::PendingFlush(substream, new_state),
                            AsyncSink::NotReady(_message) => {
                                self.substreams.push(SubstreamState::PendingSend(
                                    substream,
                                    send_state.clone(),
                                ));
                                return Ok(Async::NotReady);
                            }
                        }
                    }
                    SubstreamState::PendingFlush(mut substream, send_state) => {
                        match substream.poll_complete()? {
                            Async::Ready(()) => match send_state {
                                SendState::WaitingData(ref _signature, ref _sender_challenge) => {
                                    SubstreamState::WaitingInput(substream, send_state)
                                }
                                SendState::WaitingChallengeReply(ref _challenge, ref _msg) => {
                                    SubstreamState::WaitingInput(substream, send_state)
                                }
                                SendState::SendingData(msg, _signature) => {
                                    self.substreams.push(SubstreamState::Closing(substream));
                                    return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                                        UnicastSendMessage::Success(msg.to),
                                    )));
                                }
                                _ => {
                                    error!("Invalid state flushing socket: {:#?}", send_state);
                                    unreachable!();
                                }
                            },
                            Async::NotReady => {
                                self.substreams
                                    .push(SubstreamState::PendingFlush(substream, send_state));
                                return Ok(Async::NotReady);
                            }
                        }
                    }
                    SubstreamState::Closing(mut substream) => match substream.close() {
                        Ok(Async::Ready(())) => break,
                        Ok(Async::NotReady) => {
                            self.substreams.push(SubstreamState::Closing(substream));
                            return Ok(Async::NotReady);
                        }
                        Err(_) => return Ok(Async::Ready(ProtocolsHandlerEvent::Shutdown)),
                    },
                }
            }
        }

        Ok(Async::NotReady)
    }
}

impl<TSubstream> fmt::Debug for UnicastHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("UnicastHandler")
            .field("shutting_down", &self.shutting_down)
            .field("substreams", &self.substreams.len())
            .field("send_queue", &self.send_queue.len())
            .finish()
    }
}

fn verify_challenge_signature(
    challenge: u64,
    signature: secure::Signature,
    remote_pkey: secure::PublicKey,
) -> bool {
    let challenge_hash = Hash::digest(&challenge);
    secure::check_hash(&challenge_hash, &signature, &remote_pkey)
}

fn sign_challenge(challenge: u64, local_skey: &secure::SecretKey) -> secure::Signature {
    let challenge_hash = Hash::digest(&challenge);
    secure::sign_hash(&challenge_hash, &local_skey)
}

fn sign_challenge_data(
    challenge: u64,
    msg: &UnicastDataMessage,
    local_skey: &secure::SecretKey,
) -> secure::Signature {
    let mut hasher = Hasher::new();
    challenge.hash(&mut hasher);
    msg.protocol_id.hash(&mut hasher);
    msg.data.hash(&mut hasher);
    let msg_hash = hasher.result();
    secure::sign_hash(&msg_hash, &local_skey)
}

fn verify_challenge_data_signature(challenge: u64, msg: &DataMessage) -> bool {
    let mut hasher = Hasher::new();
    challenge.hash(&mut hasher);
    msg.protocol_id.hash(&mut hasher);
    msg.data.hash(&mut hasher);
    let msg_hash = hasher.result();
    secure::check_hash(&msg_hash, &msg.sender_signature, &msg.sender_pkey)
}
