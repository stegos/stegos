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

use stegos_crypto::pbc::secure;

use failure::Error;
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::messages::Message;

#[derive(Debug, Eq, PartialEq)]
pub enum PoolEvent {
    Message(Vec<u8>),
    InternalMessage(Message),
    PoolInfo(Vec<u8>),
    ChangeFacilitator(secure::PublicKey),
}

//TODO: Pool should return some commulative transaction.
#[derive(Debug, Eq, PartialEq)]
pub enum PoolFeedback {
    Ping,
}

pub struct TransactionPool {
    pub feedback_receiver: UnboundedReceiver<PoolFeedback>,
    pub events_sender: UnboundedSender<PoolEvent>,
}

impl TransactionPool {
    /// Adds transaction into txpool.
    pub fn add_message(&mut self, pkey: secure::PublicKey) -> Result<(), Error> {
        let message = Message { pkey };
        self.events_sender
            .unbounded_send(PoolEvent::InternalMessage(message))?;
        Ok(())
    }

    /// Changes facilitator in txpool.
    pub fn change_facilitator(&mut self, pkey: secure::PublicKey) -> Result<(), Error> {
        self.events_sender
            .unbounded_send(PoolEvent::ChangeFacilitator(pkey))?;
        Ok(())
    }
}
