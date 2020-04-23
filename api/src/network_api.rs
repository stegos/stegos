use crate::server::api::*;
use async_trait::async_trait;
use failure::{bail, Error};
use futures::channel::{mpsc, oneshot};
use serde::{Deserialize, Serialize};
use stegos_crypto::pbc;
use stegos_network::{
    Network, NetworkResponse as NetworkServiceResponse, NodeInfo, UnicastMessage,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NetworkRequest {
    // VersionInfo is not about Network, but let's keep it here to simplify all things.
    VersionInfo {},
    ChainName {},
    SubscribeUnicast {
        topic: String,
    },
    SubscribeBroadcast {
        topic: String,
    },
    // UnsubscribeUnicast {
    //     topic: String,
    // },
    // UnsubscribeBroadcast {
    //     topic: String,
    // },
    SendUnicast {
        topic: String,
        to: pbc::PublicKey,
        data: Vec<u8>,
    },
    PublishBroadcast {
        topic: String,
        data: Vec<u8>,
    },
    ConnectedNodesRequest {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NetworkResponse {
    VersionInfo {
        version: String,
    },
    ChainName {
        name: String,
    },
    SubscribedUnicast {
        topic: String,
        #[serde(skip)]
        rx: Option<mpsc::UnboundedReceiver<UnicastMessage>>,
    },
    SubscribedBroadcast {
        topic: String,
        #[serde(skip)]
        rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    },
    // UnsubscribedUnicast,
    // UnsubscribedBroadcast,
    SentUnicast,
    PublishedBroadcast,
    ConnectedNodesRequested,
    ConnectedNodes {
        total: usize,
        nodes: Vec<NodeInfo>,
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NetworkNotification {
    UnicastMessage {
        topic: String,
        from: pbc::PublicKey,
        data: Vec<u8>,
    },
    BroadcastMessage {
        topic: String,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct NetworkApi {
    network: Network,
    version: String,
    /// Chain name.
    chain_name: String,
}

impl NetworkApi {
    pub fn new(network: Network, version: String, chain_name: String) -> Self {
        NetworkApi {
            network,
            version,
            chain_name,
        }
    }

    fn handle_network_request(
        &self,
        network_request: NetworkRequest,
    ) -> Result<NetworkResult, Error> {
        match network_request {
            NetworkRequest::VersionInfo {} => {
                let version = self.version.clone();
                Ok(NetworkResult::Immediate(NetworkResponse::VersionInfo {
                    version,
                }))
            }
            NetworkRequest::ChainName {} => {
                let name = self.chain_name.clone();
                Ok(NetworkResult::Immediate(NetworkResponse::ChainName {
                    name,
                }))
            }
            // NetworkRequest::UnsubscribeUnicast { topic } => {
            //     self.network_unicast.remove(&topic);
            //     Ok(NetworkResult::Immediate(
            //         NetworkResponse::UnsubscribedUnicast,
            //     ))
            // }
            // NetworkRequest::UnsubscribeBroadcast { topic } => {
            //     self.network_broadcast.remove(&topic);
            //     Ok(NetworkResult::Immediate(
            //         NetworkResponse::UnsubscribedBroadcast,
            //     ))
            // }
            NetworkRequest::SubscribeUnicast { topic } => {
                let rx = self.network.subscribe_unicast(&topic)?;
                Ok(NetworkResult::Immediate(
                    NetworkResponse::SubscribedUnicast {
                        topic,
                        rx: rx.into(),
                    },
                ))
            }
            NetworkRequest::SubscribeBroadcast { topic } => {
                let rx = self.network.subscribe(&topic)?;
                Ok(NetworkResult::Immediate(
                    NetworkResponse::SubscribedBroadcast {
                        topic,
                        rx: rx.into(),
                    },
                ))
            }
            NetworkRequest::SendUnicast { topic, to, data } => {
                self.network.send(to, &topic, data)?;
                Ok(NetworkResult::Immediate(NetworkResponse::SentUnicast))
            }
            NetworkRequest::PublishBroadcast { topic, data } => {
                self.network.publish(&topic, data)?;
                Ok(NetworkResult::Immediate(
                    NetworkResponse::PublishedBroadcast,
                ))
            }
            NetworkRequest::ConnectedNodesRequest {} => {
                let rx = self.network.list_connected_nodes()?;
                Ok(NetworkResult::Async(rx))
            }
        }
    }
}

enum NetworkResult {
    Immediate(NetworkResponse),
    Async(oneshot::Receiver<NetworkServiceResponse>),
}
use super::{RequestKind, ResponseKind};
use std::convert::{TryFrom, TryInto};
impl TryFrom<RawRequest> for NetworkRequest {
    type Error = Error;
    fn try_from(request: RawRequest) -> Result<NetworkRequest, Self::Error> {
        match request.0.kind {
            RequestKind::NetworkRequest(req) => Ok(req),
            _ => bail!("Cannot parse request as wallet request."),
        }
    }
}
impl From<NetworkResponse> for RawResponse {
    fn from(response: NetworkResponse) -> RawResponse {
        RawResponse(ResponseKind::NetworkResponse(response))
    }
}
#[async_trait]
impl ApiHandler for NetworkApi {
    async fn process_request(&self, req: RawRequest) -> Result<RawResponse, Error> {
        let request: NetworkRequest = req.try_into()?;
        match self.handle_network_request(request)? {
            NetworkResult::Immediate(response) => Ok(response.into()),
            NetworkResult::Async(response) => {
                let resp = response.await?;
                let result = match resp {
                    NetworkServiceResponse::ConnectedNodes { nodes } => {
                        NetworkResponse::ConnectedNodes {
                            total: nodes.len(),
                            nodes,
                        }
                    }
                };
                Ok(result.into())
            }
        }
    }

    fn cloned(&self) -> Box<dyn ApiHandler> {
        Box::new(self.clone())
    }
}
