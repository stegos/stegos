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

use clap::{App, Arg};
use hex;
use stegos_crypto::vdf::VDF;

// ------------------------------------------------------------------------

fn main() {
    let args = App::new("Stegos VDF tool")
        .author("Stegos AG <info@stegos.com>")
        .about("Stegos VDF tool")
        .arg(
            Arg::with_name("challenge")
                .index(1)
                .help("A challenge to start.")
                .takes_value(true)
                .required(true)
                .value_name("CHALLENGE_HEX"),
        )
        .arg(
            Arg::with_name("difficulty")
                .index(2)
                .help("A difficulty of vdf.")
                .takes_value(true)
                .required(true)
                .value_name("NUMBER"),
        )
        .arg(
            Arg::with_name("proof")
                .index(3)
                .help("A difficulty of vdf.")
                .required(false)
                .takes_value(true)
                .value_name("PROOF"),
        )
        .get_matches();

    let challenge = hex::decode(args.value_of("challenge").unwrap()).unwrap();
    let difficulty = args.value_of("difficulty").unwrap().parse::<u64>().unwrap();
    let proof = args.value_of("proof").map(hex::decode).map(|e| e.unwrap());

    let vdf = VDF::new();
    if let Some(proof) = proof {
        println!(
            "{}",
            if vdf.verify(&challenge, difficulty, &proof).is_ok() {
                "Proof is correct"
            } else {
                "Proof is incorrect"
            }
        );
    } else {
        let data = vdf.solve(&challenge, difficulty);
        println!("{}", hex::encode(data));
    }
}
