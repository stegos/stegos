//
// Copyright (c) 2019 Stegos
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

use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;

use super::time::{start_test, wait};
use super::*;
use crate::*;

// just namespace that hides method belong to tickets processing.
pub struct VRFHelper;
impl VRFHelper {
    /// Returns a list of all nodes tickets based on current state, and nodes keys.
    pub fn nodes_tickets(
        height: u64,
        view_change: u32,
        last_random: Hash,
        keys: &[KeyChain],
    ) -> Vec<tickets::VRFTicket> {
        let seed = Self::calculate_seed(last_random, view_change);
        let mut result = Vec::new();
        debug!("last random hash = {:?}", last_random);
        debug!(
            "create ticket for state: seed = {:?}, retry = {}",
            seed, view_change
        );
        for keys in keys.iter() {
            result.push(Self::node_ticket(
                height,
                view_change,
                seed,
                keys.network_pkey,
                &keys.network_skey,
            ));
        }
        result
    }

    /// Returns single node key, based on seed.
    pub fn node_ticket(
        height: u64,
        view_change: u32,
        seed: Hash,
        pkey: secure::PublicKey,
        skey: &secure::SecretKey,
    ) -> VRFTicket {
        VRFTicket::new(seed, height, view_change, pkey, skey)
    }

    /// Calculate seed from block_hash and view_change.
    pub fn calculate_seed(block_hash: Hash, view_change: u32) -> Hash {
        let mut hasher = Hasher::new();
        block_hash.hash(&mut hasher);
        view_change.hash(&mut hasher);
        hasher.result()
    }
}

// checks that vrf successfuly restarts consensus.
#[test]
fn test_vrf_change_consensus() {
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let mut sandbox = Sandbox::new(4);
        let node_id = 1;
        let s = &mut sandbox.nodes[node_id];
        // Generate list of keys like in VRF.
        let block_hash = s.node_service.chain.last_random();
        let view_change = s.node_service.vrf_system.view_change() + 1;
        let height = s.node_service.chain.height();
        let tickets =
            VRFHelper::nodes_tickets(height, view_change, block_hash, &sandbox.nodes_keychains);

        // wait for restart consensus
        wait(timer, *crate::BLOCK_TIMEOUT);
        // node should broadcast ticket

        s.poll();
        s.network_service
            .assert_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets[node_id]);
        // receive messages from other nodes
        for i in 0..tickets.len() {
            if i == node_id {
                continue;
            }
            s.network_service.assert_empty_queue();
            s.network_service
                .receive_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets[i]);
        }
        // node should reelect leader after timeout

        s.poll();
        assert_eq!(s.node_service.vrf_system.view_change(), 1);

        wait(timer, crate::tickets::COLLECTING_TICKETS_TIMER);
        s.poll();
    });
}

// Checks that if no enought tickets vrf system restarts correctly.

#[test]
fn test_vrf_not_enought_tickets() {
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let mut sandbox = Sandbox::new(4);
        let node_id = 1;
        let s = &mut sandbox.nodes[node_id];

        // Generate list of keys like in VRF.
        let last_random = s.node_service.chain.last_random();
        for count in 1..2 {
            let view_change = s.node_service.vrf_system.view_change() + 1;
            let height = s.node_service.chain.height();
            let tickets = VRFHelper::nodes_tickets(
                height,
                view_change,
                last_random,
                &sandbox.nodes_keychains,
            );

            // wait for restart consensus
            wait(timer, *crate::BLOCK_TIMEOUT);
            // node should broadcast ticket

            s.poll();
            s.network_service
                .assert_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets[node_id].clone());
            // receive messages from other nodes
            for i in 0..tickets.len() {
                if i == node_id {
                    continue;
                }
                s.network_service.assert_empty_queue();
                s.network_service
                    .receive_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets[i]);
            }
            // node should not init consensus, but change view_change

            wait(timer, crate::tickets::COLLECTING_TICKETS_TIMER);
            s.poll();
            assert_eq!(s.node_service.vrf_system.view_change(), count as u32);
        }
    });
}

#[test]
fn test_vrf_invalid_encoding() {
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let mut sandbox = Sandbox::new(4);
        let node_id = 1;
        let s = &mut sandbox.nodes[node_id];

        // Generate list of keys like in VRF.
        let last_random = s.node_service.chain.last_random();
        let view_change = s.node_service.vrf_system.view_change() + 1;
        let height = s.node_service.chain.height();
        let tickets =
            VRFHelper::nodes_tickets(height, view_change, last_random, &sandbox.nodes_keychains);

        // wait for restart consensus
        wait(timer, *crate::BLOCK_TIMEOUT);
        // node should broadcast ticket

        s.poll();
        s.network_service
            .assert_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets[node_id]);
        // receive messages from other nodes
        for _ in 1..tickets.len() {
            s.network_service.assert_empty_queue();
            // send invalid data
            s.network_service
                .receive_broadcast_raw(crate::tickets::VRF_TICKETS_TOPIC, vec![88u8; 1222]);
        }

        s.poll();
        assert_eq!(s.node_service.vrf_system.view_change(), 1);

        wait(timer, crate::tickets::COLLECTING_TICKETS_TIMER);
        s.poll();
    });
}
