pub use futures;
pub use libp2p_core as core;
pub use libp2p_swarm as swarm;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
