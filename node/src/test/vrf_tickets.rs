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
use stegos_serialization::traits::ProtoConvert;

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
        block_hash: Hash,
        keys: &[KeyChain],
    ) -> Vec<tickets::VRFTicket> {
        let seed = Self::calculate_seed(block_hash, view_change);
        let mut result = Vec::new();
        debug!("block hash = {:?}", block_hash);
        debug!(
            "create ticket for state: seed = {:?}, retry = {}",
            seed, view_change
        );
        for keys in keys.iter() {
            result.push(Self::node_ticket(
                height,
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
        seed: Hash,
        pkey: secure::PublicKey,
        skey: &secure::SecretKey,
    ) -> VRFTicket {
        VRFTicket::new(seed, height, pkey, skey)
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
        let mut s = NodeSandbox::new(4);
        // Generate list of keys like in VRF.
        let block_hash = Hash::digest(s.node_service.chain.last_block());
        let view_change = s.node_service.vrf_system.view_change() + 1;
        let height = s.node_service.chain.blocks().len() as u64;
        let tickets =
            VRFHelper::nodes_tickets(height, view_change, block_hash, &s.config.nodes_keychains);

        let mut tickets = tickets.into_iter();

        // wait for restart consensus
        wait(timer, *crate::tickets::RESTART_CONSENSUS_TIMER);
        // node should broadcast ticket

        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        s.manager
            .assert_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets.next().unwrap());
        // receive messages from other nodes
        for ticket in tickets {
            s.manager.assert_empty_queue();
            s.manager.receive_broadcast(
                crate::tickets::VRF_TICKETS_TOPIC,
                ticket.into_buffer().unwrap(),
            );
        }
        // node should reelect leader after timeout

        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        assert_eq!(s.node_service.vrf_system.view_change(), 1);

        assert_eq!(
            s.node_service.consensus.as_ref().unwrap().epoch(),
            s.node_service.chain.epoch
        );
        wait(timer, crate::tickets::COLLECTING_TICKETS_TIMER);
        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        // check that consensus at new epoch
        assert_eq!(
            s.node_service.consensus.as_ref().unwrap().epoch(),
            s.node_service.chain.epoch + 1
        );
    });
}

// Checks that if no enought tickets vrf system restarts correctly.

#[test]
fn test_vrf_not_enought_tickets() {
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let mut s = NodeSandbox::new(4);

        // Generate list of keys like in VRF.
        let block_hash = Hash::digest(s.node_service.chain.last_block());
        for count in 1..2 {
            let view_change = s.node_service.vrf_system.view_change() + 1;
            let height = s.node_service.chain.blocks().len() as u64;
            let tickets = VRFHelper::nodes_tickets(
                height,
                view_change,
                block_hash,
                &s.config.nodes_keychains,
            );

            // wait for restart consensus
            wait(timer, *crate::tickets::RESTART_CONSENSUS_TIMER);
            // node should broadcast ticket

            assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
            s.manager
                .assert_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets[0].clone());
            // receive messages from other nodes
            for i in 1..count + 1 {
                s.manager.assert_empty_queue();
                s.manager.receive_broadcast(
                    crate::tickets::VRF_TICKETS_TOPIC,
                    tickets[i].into_buffer().unwrap(),
                );
            }
            // node should not init consensus, but change view_change

            wait(timer, crate::tickets::COLLECTING_TICKETS_TIMER);
            assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
            assert_eq!(s.node_service.vrf_system.view_change(), count as u32);
            // check that consensus at old epoch
            assert_eq!(
                s.node_service.consensus.as_ref().unwrap().epoch(),
                s.node_service.chain.epoch
            );
        }
    });
}

#[test]
fn test_vrf_invalid_encoding() {
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let mut s = NodeSandbox::new(4);
        // Generate list of keys like in VRF.
        let block_hash = Hash::digest(s.node_service.chain.last_block());
        let view_change = s.node_service.vrf_system.view_change() + 1;
        let height = s.node_service.chain.blocks().len() as u64;
        let tickets =
            VRFHelper::nodes_tickets(height, view_change, block_hash, &s.config.nodes_keychains);

        let mut tickets = tickets.into_iter();

        // wait for restart consensus
        wait(timer, *crate::tickets::RESTART_CONSENSUS_TIMER);
        // node should broadcast ticket

        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        s.manager
            .assert_broadcast(crate::tickets::VRF_TICKETS_TOPIC, tickets.next().unwrap());
        // receive messages from other nodes
        for _ticket in tickets {
            s.manager.assert_empty_queue();
            // send invalid data
            s.manager
                .receive_broadcast(crate::tickets::VRF_TICKETS_TOPIC, vec![88u8; 1222]);
        }

        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        assert_eq!(s.node_service.vrf_system.view_change(), 1);

        assert_eq!(
            s.node_service.consensus.as_ref().unwrap().epoch(),
            s.node_service.chain.epoch
        );
        wait(timer, crate::tickets::COLLECTING_TICKETS_TIMER);
        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));

        assert_eq!(
            s.node_service.consensus.as_ref().unwrap().epoch(),
            s.node_service.chain.epoch
        );
    });
}
