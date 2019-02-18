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

use stegos_consensus::{ConsensusMessage, ConsensusMessageBody};
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc::secure;
use stegos_keychain::KeyChain;

use super::time::{start_test, wait};
use super::Loopback;
use crate::*;

struct NetworkConfig {
    nodes_keychains: Vec<KeyChain>,
    genesis: Vec<Block>,
}

impl NetworkConfig {
    fn genesis(num_nodes: usize) -> Self {
        let mut nodes_keychains: Vec<_> = (0..num_nodes).map(|_num| KeyChain::new_mem()).collect();
        nodes_keychains.sort_by(|first, other| first.cosi_pkey.cmp(&other.cosi_pkey));
        let genesis = stegos_blockchain::genesis(&nodes_keychains, 100, 1000000, 0);
        Self {
            genesis,
            nodes_keychains,
        }
    }
}

struct NodeSandbox {
    pub config: NetworkConfig,
    pub manager: Loopback,
    pub keychain: KeyChain,
    pub outbox: UnboundedSender<NodeMessage>,
    pub node_service: NodeService,
}

impl NodeSandbox {
    fn new(num_nodes: usize) -> Self {
        let config = NetworkConfig::genesis(num_nodes);
        // init network
        let (network_manager, network) = Loopback::new();

        // Create node, with first node keychain.
        let my_keychain = config.nodes_keychains.first().unwrap().clone();
        let (outbox, inbox) = unbounded();
        let mut node_service = NodeService::testing(my_keychain.clone(), network, inbox).unwrap();
        node_service.handle_init(config.genesis.clone()).unwrap();
        Self {
            config,
            manager: network_manager,
            keychain: my_keychain,
            outbox,
            node_service,
        }
    }
}

struct NodeState {
    height: u64,
    epoch: u64,
    last_block: Hash,
}

impl NodeState {
    fn create_monetary_block(
        &self,
        version: u64,
        reward: i64,
        keys: &KeyChain,
    ) -> (Block, BlockProof) {
        let mut tmp_pool = Mempool::new();
        let (monetary, fee_output, tx_hashes) = tmp_pool.create_block(
            self.last_block,
            version,
            self.epoch,
            reward,
            &keys.wallet_skey,
            &keys.wallet_pkey,
        );
        let proof = MonetaryBlockProof {
            fee_output,
            tx_hashes,
        };
        let proof = BlockProof::MonetaryBlockProof(proof);
        let block = Block::MonetaryBlock(monetary);
        (block, proof)
    }
}

struct ConsensusHelper {
    validators: Vec<KeyChain>,
    state: NodeState,
}
impl ConsensusHelper {
    fn from_sandbox(sandbox: &NodeSandbox) -> ConsensusHelper {
        let state = NodeState {
            height: sandbox.node_service.chain.height() as u64,
            epoch: sandbox.node_service.chain.epoch,
            last_block: Hash::digest(sandbox.node_service.chain.last_block()),
        };
        ConsensusHelper {
            validators: sandbox.config.nodes_keychains.clone(),
            state,
        }
    }

    fn propose(&self, node_id: usize) -> (BlockConsensusMessage, Hash) {
        let (request, proof) = self.state.create_monetary_block(
            crate::VERSION,
            crate::BLOCK_REWARD,
            &self.validators[node_id],
        );
        let request_hash = Hash::digest(&request);
        let body = ConsensusMessageBody::Proposal { request, proof };
        let msg = ConsensusMessage::new(
            self.state.height,
            self.state.epoch,
            request_hash,
            &self.validators[node_id].cosi_skey,
            &self.validators[node_id].cosi_pkey,
            body,
        );
        (msg, request_hash)
    }
    fn prevote(&self, node_id: usize, request_hash: Hash) -> BlockConsensusMessage {
        let body = ConsensusMessageBody::Prevote {};
        ConsensusMessage::new(
            self.state.height,
            self.state.epoch,
            request_hash,
            &self.validators[node_id].cosi_skey,
            &self.validators[node_id].cosi_pkey,
            body,
        )
    }

    fn precommit(&self, node_id: usize, request_hash: Hash) -> BlockConsensusMessage {
        let request_hash_sig =
            secure::sign_hash(&request_hash, &self.validators[node_id].cosi_skey);
        let body = ConsensusMessageBody::Precommit { request_hash_sig };
        ConsensusMessage::new(
            self.state.height,
            self.state.epoch,
            request_hash,
            &self.validators[node_id].cosi_skey,
            &self.validators[node_id].cosi_pkey,
            body,
        )
    }
    fn sealed_message(&self, node_id: usize, block: Block) -> SealedBlockMessage {
        SealedBlockMessage::new(
            &self.validators[node_id].cosi_skey,
            &self.validators[node_id].cosi_pkey,
            block,
        )
    }
}

#[test]
fn consensus_produce_block() {
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let mut s = NodeSandbox::new(4);
        let helper = ConsensusHelper::from_sandbox(&s);
        info!("sleep for 2x consensus propose timeout.");
        wait(timer, crate::TX_WAIT_TIMEOUT + crate::TX_WAIT_TIMEOUT);
        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));

        assert_eq!(s.node_service.chain.height(), 2);
        let propose = helper.propose(0).0;
        let mut request = None;
        let mut block = None;
        //TODO: Handwriten comparator to avoid different utc::timestamps.
        s.manager.assert_broadcast_with(
            crate::CONSENSUS_TOPIC,
            |msg: BlockConsensusMessage| -> bool {
                request = Some(msg.request_hash);

                let is_propose = if let ConsensusMessageBody::Proposal { request, .. } = msg.body {
                    block = Some(request);
                    true
                } else {
                    false
                };
                is_propose
                    && msg.epoch == propose.epoch
                    && msg.height == propose.height
                    && msg.pkey == propose.pkey
            },
        );

        let mut block = block.unwrap();
        let request = request.unwrap();
        s.manager.assert_broadcast_with(
            crate::CONSENSUS_TOPIC,
            |msg: BlockConsensusMessage| -> bool {
                let is_prevote = if let ConsensusMessageBody::Prevote {} = msg.body {
                    true
                } else {
                    false
                };
                is_prevote
                    && msg.epoch == propose.epoch
                    && msg.height == propose.height
                    && msg.pkey == propose.pkey
                    && request == msg.request_hash
            },
        );

        assert_eq!(s.node_service.chain.height(), 2);

        s.manager.assert_empty_queue();
        for i in 1..3 {
            let prevote = helper.prevote(i, request);
            s.manager
                .receive_broadcast(crate::CONSENSUS_TOPIC, prevote.into_buffer().unwrap())
        }
        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        assert_eq!(s.node_service.chain.height(), 2);

        let mut sig = BTreeMap::new();
        s.manager.assert_broadcast_with(
            crate::CONSENSUS_TOPIC,
            |msg: BlockConsensusMessage| -> bool {
                let is_prevote =
                    if let ConsensusMessageBody::Precommit { request_hash_sig } = msg.body {
                        assert!(sig.insert(msg.pkey, request_hash_sig).is_none());
                        true
                    } else {
                        false
                    };
                is_prevote
                    && msg.epoch == propose.epoch
                    && msg.height == propose.height
                    && msg.pkey == propose.pkey
                    && request == msg.request_hash
            },
        );
        s.manager.assert_empty_queue();
        for i in 1..3 {
            let precommit = helper.precommit(i, request);
            if let ConsensusMessageBody::Precommit { request_hash_sig } = precommit.body {
                assert!(sig.insert(precommit.pkey, request_hash_sig).is_none());
            } else {
                panic!("Not precommit produced.")
            }
            s.manager
                .receive_broadcast(crate::CONSENSUS_TOPIC, precommit.into_buffer().unwrap())
        }

        let (sig, map) =
            stegos_consensus::create_multi_signature(&s.node_service.chain.validators, &sig);
        block.base_header_mut().multisig = sig;
        block.base_header_mut().multisigmap = map;

        assert_eq!(s.node_service.poll(), Ok(Async::NotReady));
        assert_eq!(s.node_service.chain.height(), 3);
        let sealed_block = helper.sealed_message(0, block);
        s.manager
            .assert_broadcast(crate::SEALED_BLOCK_TOPIC, sealed_block);

        s.manager.assert_empty_queue();
    });
}
