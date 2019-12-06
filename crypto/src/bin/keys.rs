//
// Copyright (c) 2018 Stegos AG
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

#[cfg(feature = "old_crypto")]
use base58check::{FromBase58Check, ToBase58Check};
use bech32::{FromBase32, ToBase32};
use clap::{App, Arg, ArgMatches};
use curve25519_dalek::ristretto::CompressedRistretto;
use failure::{bail, format_err, Error};
use stegos_crypto::scc::{Pt, PublicKey};

enum Format {
    Hex,
    #[cfg(feature = "old_crypto")]
    Base58(u8),
    Bech32(String),
}

impl Format {
    fn deserialize(&self, source: &str) -> Result<PublicKey, Error> {
        let bytes = match self {
            Format::Hex => {
                let mut bytes = [0u8; 32];
                stegos_crypto::utils::hexstr_to_lev_u8(source, &mut bytes)?;
                bytes.to_vec()
            }
            #[cfg(feature = "old_crypto")]
            Format::Base58(v) => {
                let (version, raw_bytes) = source
                    .from_base58check()
                    .map_err(|e| format_err!("{:?}", e))?;
                if version != *v {
                    eprintln!(
                        "Wrong version for base58, expected={}, actual={}",
                        v, version
                    )
                }
                raw_bytes
            }
            Format::Bech32(p) => {
                let (s, bytes) = bech32::decode(source)?;
                if s != *p {
                    eprintln!("Wrong prefix for bech32, expected={}, actual={}", p, s)
                }
                FromBase32::from_base32(&bytes)?
            }
        };

        let pt = match CompressedRistretto::from_slice(&bytes).decompress() {
            None => bail!("Failed to decompress point"),
            Some(pt) => Pt::from(pt),
        };
        Ok(PublicKey::from(pt))
    }

    fn serialize(&self, data: &PublicKey) -> Result<String, Error> {
        let res = match self {
            Format::Hex => data.to_hex(),
            #[cfg(feature = "old_crypto")]
            Format::Base58(v) => {
                let bytes = data.to_bytes();
                bytes.to_base58check(*v)
            }
            Format::Bech32(p) => {
                let bytes = data.to_bytes();
                let bytes_u5 = bytes.to_base32();
                bech32::encode(&p, bytes_u5)?
            }
        };
        return Ok(res);
    }
}

fn parse_format(input: &str, args: &ArgMatches<'_>) -> Result<Format, Error> {
    match input {
        "hex" | "h" => Ok(Format::Hex),
        "bech32" | "b32" => {
            let prefix = args.value_of("bech32-prefix").unwrap_or_else(|| {
                eprintln!("Setting default prefix to dev");
                "dev"
            });
            Ok(Format::Bech32(prefix.to_string()))
        }
        #[cfg(feature = "old_crypto")]
        "base58" | "b58" => {
            let version = args
                .value_of("base58-version")
                .unwrap_or_else(|| {
                    eprintln!("Setting default version to 198");
                    "198"
                })
                .parse()?;
            Ok(Format::Base58(version))
        }
        f => bail!("Unknown format {}", f),
    }
}

fn main() {
    let args = App::new("Stegos public keys tools tool")
        .author("Stegos AG <info@stegos.com>")
        .about("Stegos VDF tool")
        .arg(
            Arg::with_name("input-format")
                .short("i")
                .long("input-format")
                .help("Input format of stegos public keys")
                .takes_value(true)
                .required(true)
                .value_name("INPUT_FORMAT"),
        )
        .arg(
            Arg::with_name("output-format")
                .short("o")
                .long("output-format")
                .help("Output format of stegos public keys")
                .takes_value(true)
                .required(true)
                .value_name("OUTPUT_FORMAT"),
        )
        .arg(
            Arg::with_name("base58-version")
                .short("v")
                .long("base58-prefix")
                .help("Versoion id for base58.")
                .takes_value(true)
                .value_name("BASE58_VERSION"),
        )
        .arg(
            Arg::with_name("bech32-prefix")
                .short("p")
                .long("bech32-prefix")
                .help("Network prefix for Bech32")
                .takes_value(true)
                .value_name("BECH32_PREFIX"),
        )
        .arg(
            Arg::with_name("input-string")
                .index(1)
                .help("Input sting.")
                .required(true)
                .takes_value(true)
                .value_name("INPUT_STRING"),
        )
        .get_matches();

    let input_format = args.value_of("input-format").expect("INPUT_FORMAT");
    let input_format = parse_format(input_format, &args).expect("INPUT_FORMAT parsable");

    let output_format = args.value_of("output-format").expect("OUTPUT_FORMAT");
    let output_format = parse_format(output_format, &args).expect("OUTPUT_FORMAT parsable");

    let input_string = args.value_of("input-string").expect("INPUT_STRING");

    let pk = input_format
        .deserialize(input_string)
        .expect("No error during processing string");
    println!(
        "{}",
        output_format
            .serialize(&pk)
            .expect("No error during processing public key")
    )
}
