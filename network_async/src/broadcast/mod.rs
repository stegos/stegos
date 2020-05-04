
#[derive(NetworkBehaviour)]
pub struct PubsubAdapter {
    floodsub: Floodsub,
    gatekeeper: Gatekeeper, // handshake
}