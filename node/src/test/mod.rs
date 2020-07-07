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

// most of the code is used in tests, so it can false positive detected as unused during build.
#![allow(dead_code)]

mod sandbox;

#[cfg(test)]
extern crate tokio;

mod microblocks;
mod consensus;
mod integration;

use crate::CHAIN_LOADER_TOPIC;
use crate::*;
use log::*;
pub use sandbox::*;
pub use stegos_blockchain::test::*;
pub use stegos_network::loopback::Loopback;

#[derive(Debug)]
pub enum VDFExecution {
    PendingVDF {
        data: Vec<u8>,
        tx: oneshot::Sender<Vec<u8>>,
    },
    Nothing,
    WaitForVDF,
}

impl VDFExecution {
    pub(crate) fn add_vdf(&mut self, rx: &mut oneshot::Receiver<Vec<u8>>) {
        // release old vdf.
        self.try_produce();

        let (tx, mut rx_new) = oneshot::channel::<Vec<u8>>();
        std::mem::swap(rx, &mut rx_new);
        let data = futures::executor::block_on(async { rx_new.await.unwrap() });
        match self {
            // if we wait for micro block, and we are leader for micro block,
            // then synchronously wait until vdf computes.
            VDFExecution::WaitForVDF => tx.send(data).unwrap(),
            // if we not waiting for microblock, save vdf for future computation.
            VDFExecution::Nothing => {
                *self = VDFExecution::PendingVDF { tx, data };
            }
            e => panic!("VDF execution in wrong state = {:?}", e),
        }
        self.try_unset();
    }

    fn try_produce(&mut self) {
        match std::mem::replace(self, VDFExecution::Nothing) {
            VDFExecution::PendingVDF { data, tx } => drop(tx.send(data)), // drop error because tx channel could be outdated.
            e => *self = e,
        }
    }

    fn try_unset(&mut self) {
        match self {
            VDFExecution::WaitForVDF => {
                *self = VDFExecution::Nothing;
            }
            _ => (),
        }
    }
}

pub async fn precondition_n_different_block_leaders(s: &mut Sandbox, different_leaders: u32) {
    skip_blocks_until(s, |s| {
        let leaders: Vec<_> = (0..different_leaders)
            .map(|id| s.partition().future_block_leader(id).unwrap())
            .collect();

        info!(
            "Checking that all leaders are different: leaders={:?}.",
            leaders
        );
        check_unique(leaders)
    })
    .await;
}

pub async fn precondition_n_different_viewchange_leaders(s: &mut Sandbox, different_leaders: u32) {
    skip_blocks_until(s, |s| {
        let leaders: Vec<_> = (0..different_leaders)
            .map(|id| s.partition().future_view_change_leader(id))
            .collect();

        info!(
            "Checking that all leaders are different: leaders={:?}.",
            leaders
        );
        check_unique(leaders)
    })
    .await;
}

/// Skip blocks until condition not true
pub async fn skip_blocks_until<F>(s: &mut Sandbox, mut condition: F)
where
    F: FnMut(&mut Sandbox) -> bool,
{
    let mut ready = false;
    for _id in 0..s.config.chain.micro_blocks_in_epoch {
        if condition(s) {
            ready = true;
            break;
        }
        info!("Skipping microblock");
        s.partition().skip_micro_block().await;
    }
    assert!(ready, "Not enough microblocks to skip");
}

pub fn check_unique<T: Ord + Clone + PartialEq>(original: Vec<T>) -> bool {
    let original_len = original.len();
    let mut array = original;
    array.sort_unstable();
    array.dedup();
    original_len == array.len()
}

async fn wait(d: Duration) {
    // Turn the timer wheel to let timers get polled.
    let now = Instant::now();
    tokio::time::advance(d).await;
    tokio::task::yield_now().await;
    trace!("Advanced time by {:?}. Wanted: {:?}", now.elapsed(), d);
}

// tests
#[cfg(test)]
mod test_framework {
    use super::*;
    use assert_matches::assert_matches;
    use futures::task::Poll;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_partition() {
        let config: SandboxConfig = Default::default();
        let mut sb = Sandbox::new(config);
        let mut part = sb.partition();
        part.poll().await;
        let first = part.first();
        let leader_pk = first.node_service.state().chain.leader();
        let r = part.split(&[leader_pk]);
        assert_eq!(r.parts.0.nodes.len(), 1);
        assert_eq!(r.parts.1.nodes.len(), 3);
        part.filter_unicast(&[CHAIN_LOADER_TOPIC]);
        part.filter_broadcast(&[SEALED_BLOCK_TOPIC]);
    }

    #[tokio::test]
    async fn test_fake_timer() {
        let timer = Duration::from_secs(30);
        tokio::time::pause();

        let mut future = tokio::time::delay_for(timer);

        let result = futures::poll!(&mut future);
        assert_matches!(result, Poll::Pending);
        wait(timer).await;

        tokio::task::yield_now().await;

        let result = futures::poll!(future);

        assert_matches!(result, Poll::Ready(_));
    }
}
