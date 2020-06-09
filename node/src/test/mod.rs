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

mod logger;
mod sandbox;

#[cfg(test)]
extern crate tokio;
/*
mod consensus;
mod integration;
mod microblocks;
*/

use crate::*;
use crate::CHAIN_LOADER_TOPIC;
use log::*;
pub use sandbox::*;
use std::time::Duration;
pub use stegos_blockchain::test::*;
pub use stegos_network::loopback::Loopback;
use stegos_crypto::pbc;
use stegos_crypto::pbc::PublicKey;

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

/// Inner logic specific for cheater slashing.
pub async fn slash_cheater_inner<'a>(
    s: &'a mut Sandbox,
    leader_pk: PublicKey,
    mut filter_nodes: Vec<PublicKey>,
) -> PartitionGuard<'a> {
    s.partition().filter_unicast(&[CHAIN_LOADER_TOPIC]);

    filter_nodes.push(leader_pk);
    let mut r = s.split(&filter_nodes);
    let leader = &mut r.parts.0.node_mut(&leader_pk).unwrap();
    leader.handle_vdf();
    leader.node_service.step().await;
    let b1: Block = leader
        .network_service
        .get_broadcast(crate::SEALED_BLOCK_TOPIC);
    let mut b2 = b1.clone();
    // modify timestamp for block
    match &mut b2 {
        Block::MicroBlock(ref mut b) => {
            b.header.timestamp += Duration::from_millis(1);
            let block_hash = Hash::digest(&*b);
            b.sig = pbc::sign_hash(&block_hash, &leader.node_service.state().network_skey);
        }
        Block::MacroBlock(_) => unreachable!("Expected a MacroBlock"),
    }

    info!("BROADCAST BLOCK, WITH COPY.");
    for node in r.parts.1.iter_mut() {
        node.network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b1.clone());
    }

    if let Some(auditor) = r.parts.1.auditor_mut() {
        auditor
            .network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b1.clone());
    }

    r.parts
        .1
        .iter_mut()
        .for_each(|node| assert_eq!(node.node_service.state().cheating_proofs.len(), 0));

    for node in r.parts.1.iter_mut() {
        node.network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b2.clone());
    }

    if let Some(auditor) = r.parts.1.auditor_mut() {
        auditor
            .network_service
            .receive_broadcast(crate::SEALED_BLOCK_TOPIC, b2.clone());
    }

    r.parts.1.poll();
    r
}

pub fn precondition_n_different_block_leaders(s: &mut Sandbox, different_leaders: u32) {
    skip_blocks_until(s, |s| {
        let leaders: Vec<_> = (0..different_leaders)
            .map(|id| s.partition().future_block_leader(id).unwrap())
            .collect();

        info!(
            "Checking that all leader are different: leaders={:?}.",
            leaders
        );
        check_unique(leaders)
    })
}

pub fn precondition_n_different_viewchange_leaders(s: &mut Sandbox, different_leaders: u32) {
    skip_blocks_until(s, |s| {
        let leaders: Vec<_> = (0..different_leaders)
            .map(|id| s.partition().future_view_change_leader(id))
            .collect();

        info!(
            "Checking that all leader are different: leaders={:?}.",
            leaders
        );
        check_unique(leaders)
    })
}

/// Skip blocks until condition not true
pub fn skip_blocks_until<F>(s: &mut Sandbox, mut condition: F)
where
    F: FnMut(&mut Sandbox) -> bool,
{
    let mut ready = false;
    for _id in 0..s.config.chain.micro_blocks_in_epoch {
        if condition(s) {
            ready = true;
            break;
        }
        info!("Skipping microlock.");
        s.partition().skip_micro_block()
    }
    assert!(ready, "Not enought micriblocks found");
}

pub fn check_unique<T: Ord + Clone + PartialEq>(original: Vec<T>) -> bool {
    let original_len = original.len();
    let mut array = original;
    array.sort_unstable();
    array.dedup();
    original_len == array.len()
}

// tests
#[cfg(test)]
mod test_framework {
    use super::*;
    #[tokio::test]
    async fn test_partition() {
        let config: SandboxConfig = Default::default();

        Sandbox::start(config, |mut s| {
            s.partition().poll();
            let leader_pk = s.nodes[0].node_service.state().chain.leader();
            let r = s.split(&[leader_pk]);
            assert_eq!(r.parts.0.nodes.len(), 1);
            assert_eq!(r.parts.1.nodes.len(), 3);
            s.partition().filter_unicast(&[CHAIN_LOADER_TOPIC]);
        });
    }
}
