pub use futures;
pub use libp2p_core as core;
pub use tokio_io;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
