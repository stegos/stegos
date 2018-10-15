#![deny(warnings)]

#[macro_use]
extern crate slog;
extern crate stegos_config;

use slog::Logger;
use std::error::Error;
use stegos_config::ConfigNetwork;

pub struct Node {}

pub fn init(cfg: ConfigNetwork, log: Logger) -> Result<(), Box<Error>> {
    info!(log, "starting network"; "strval" => &cfg.strval, "u32val" => cfg.u32val);
    Ok(())
}

pub fn server() {
    println!("Main loop");
}
